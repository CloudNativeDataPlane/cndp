/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <pthread.h>        // for pthread_barrier_wait, pthread_self, pthread_...
#include <sched.h>          // for cpu_set_t
#include <signal.h>         // for SIGUSR1, SIGINT
#include <stdio.h>          // for fflush, stdout
#include <stdlib.h>         // for calloc, free
#include <string.h>         // for memset
#include <unistd.h>         // for getpid, sleep, gettid

#include <cne_common.h>        // for __cne_unused, cne_countof
#include <cne_gettid.h>
#include <cne.h>               // for cne_init, cne_on_exit, CNE_CALLED_EXIT, CNE_...
#include <cne_log.h>           // for CNE_LOG_ERR, CNE_ERR, CNE_DEBUG, CNE_LOG_DEBUG
#include <metrics.h>           // for metrics_destroy
#include <txbuff.h>            // for txbuff_t, txbuff_add, txbuff_free, txbuff_pk...
#include <cne_system.h>        // for cne_lcore_id
#include <jcfg.h>              // for jcfg_thd_t, jcfg_lport_t, jcfg_lport_by_index

#include "main.h"

static struct fwd_info fwd_info;
static struct fwd_info *fwd = &fwd_info;

struct create_txbuff_thd_priv_t {
    txbuff_t **txbuffs; /**< txbuff_t double pointer */
    pkt_api_t pkt_api;  /**< The packet API mode */
};

#define foreach_thd_lport(_t, _lp) \
    for (int _i = 0; _i < _t->lport_cnt && (_lp = _t->lports[_i]); _i++, _lp = _t->lports[_i])

#define TIMEOUT_VALUE 1000 /* Number of times to wait for each usleep() time */

enum thread_quit_state {
    THD_RUN = 0, /**< Thread should continue running */
    THD_QUIT,    /**< Thread should stop itself */
    THD_DONE,    /**< Thread should set this state when done */
};

static __cne_always_inline int
__rx_burst(pkt_api_t api, struct fwd_port *pd, pktmbuf_t **mbufs, int n_pkts)
{
    switch (api) {
    case XSKDEV_PKT_API:
        return xskdev_rx_burst(pd->xsk, (void **)mbufs, n_pkts);
    case PKTDEV_PKT_API:
        return pktdev_rx_burst(pd->lport, mbufs, n_pkts);
    default:
        break;
    }
    return 0;
}

static __cne_always_inline int
__tx_burst(pkt_api_t api, struct fwd_port *pd, pktmbuf_t **mbufs, int n_pkts)
{
    switch (api) {
    case XSKDEV_PKT_API:
        return xskdev_tx_burst(pd->xsk, (void **)mbufs, n_pkts);
    case PKTDEV_PKT_API:
        return pktdev_tx_burst(pd->lport, mbufs, n_pkts);
    default:
        break;
    }
    return 0;
}

static __cne_always_inline uint16_t
__tx_flush(struct fwd_port *pd, pkt_api_t api, pktmbuf_t **mbufs, uint16_t n_pkts)
{
    while (n_pkts > 0) {
        uint16_t n = __tx_burst(api, pd, mbufs, n_pkts);
        if (n == PKTDEV_ADMIN_STATE_DOWN)
            return n;

        n_pkts -= n;
        mbufs += n;
    }

    return n_pkts;
}

static int
_drop_test(jcfg_lport_t *lport, struct fwd_info *fwd)
{
    struct fwd_port *pd = lport->priv_;
    int n_pkts;

    if (!pd)
        CNE_ERR_RET("fwd_port passed in lport private data is NULL\n");

    n_pkts = __rx_burst(fwd->pkt_api, pd, pd->rx_mbufs, fwd->burst);
    if (n_pkts == PKTDEV_ADMIN_STATE_DOWN)
        return -1;

    if (n_pkts)
        pktmbuf_free_bulk(pd->rx_mbufs, n_pkts);

    return 0;
}

static int
_fwd_test(jcfg_lport_t *lport, struct fwd_info *fwd)
{
    struct fwd_port *pd                          = lport->priv_;
    struct create_txbuff_thd_priv_t *thd_private = pd->thd->priv_;
    txbuff_t **txbuff;
    int i, n_pkts;

    if (!pd)
        CNE_ERR_RET("fwd_port passed in lport private data is NULL\n");

    txbuff = thd_private->txbuffs;

    n_pkts = __rx_burst(fwd->pkt_api, pd, pd->rx_mbufs, fwd->burst);
    if (n_pkts == PKTDEV_ADMIN_STATE_DOWN)
        return -1;

    for (i = 0; i < n_pkts; i++) {
        uint8_t dst_lport = get_dst_lport(pktmbuf_mtod(pd->rx_mbufs[i], void *));
        jcfg_lport_t *dst = jcfg_lport_by_index(fwd->jinfo, dst_lport);

        if (!dst)
            /* Cannot forward to non-existing port, so echo back on incoming interface */
            dst = lport;

        MAC_SWAP(pktmbuf_mtod(pd->rx_mbufs[i], void *));
        (void)txbuff_add(txbuff[dst->lpid], pd->rx_mbufs[i]);
    }

    int nb_lports = jcfg_num_lports(fwd->jinfo);
    for (int i = 0; i < nb_lports; i++) {
        jcfg_lport_t *dst = jcfg_lport_by_index(fwd->jinfo, i);

        if (!dst)
            continue;

        /* Could hang here if we can never flush the TX packets */
        while (txbuff_count(txbuff[dst->lpid]) > 0)
            txbuff_flush(txbuff[dst->lpid]);
    }

    return 0;
}

static int
_loopback_test(jcfg_lport_t *lport, struct fwd_info *fwd)
{
    struct fwd_port *pd = lport->priv_;
    int n_pkts, n;

    if (!pd)
        CNE_ERR_RET("fwd_port passed in lport private data is NULL\n");

    n_pkts = __rx_burst(fwd->pkt_api, pd, pd->rx_mbufs, fwd->burst);
    if (n_pkts == PKTDEV_ADMIN_STATE_DOWN)
        return -1;

    if (n_pkts) {
        for (int j = 0; j < n_pkts; j++)
            MAC_SWAP(pktmbuf_mtod(pd->rx_mbufs[j], void *));

        n = __tx_flush(pd, fwd->pkt_api, pd->rx_mbufs, n_pkts);
        if (n == PKTDEV_ADMIN_STATE_DOWN)
            return -1;
        pd->tx_overrun += n;
    }
    return 0;
}

static int
_txonly_test(jcfg_lport_t *lport, struct fwd_info *fwd)
{
    struct fwd_port *pd = lport->priv_;
    pktmbuf_t *tx_mbufs[fwd->burst];
    int n_pkts, n;

    if (!pd)
        CNE_ERR_RET("fwd_port passed in lport private data is NULL\n");

    if (fwd->pkt_api == PKTDEV_PKT_API)
        n_pkts = pktdev_buf_alloc(pd->lport, tx_mbufs, fwd->burst);
    else {
        region_info_t *ri = &lport->umem->rinfo[lport->region_idx];

        n_pkts = pktmbuf_alloc_bulk(ri->pool, tx_mbufs, fwd->burst);
    }

    if (n_pkts > 0) {
        for (int j = 0; j < n_pkts; j++) {
            pktmbuf_t *xb = tx_mbufs[j];
            uint64_t *p   = pktmbuf_mtod(xb, uint64_t *);

            /*
             * IPv4/UDP 64 byte packet
             * Port Src/Dest       :           1234/ 5678
             * Pkt Type            :           IPv4 / UDP
             * IP  Destination     :           198.18.1.1
             *     Source          :        198.18.0.1/24
             * MAC Destination     :    3c:fd:fe:e4:34:c0
             *     Source          :    3c:fd:fe:e4:38:40
             * 0000   3cfd fee4 34c0 3cfd fee4 3840 08004500
             * 0010   002e 60ac 0000 4011 8cec c612 0001c612
             * 0020   0101 04d2 162e 001a 93c6 6b6c 6d6e6f70
             * 0030   7172 7374 7576 7778 797a 3031
             */
            p[0]                 = 0x3cfdfee434c03cfd;
            p[1]                 = 0xfee4384008004500;
            p[2]                 = 0x002e60ac00004011;
            p[3]                 = 0x8cecc6120001c612;
            p[4]                 = 0x010104d2162e001a;
            p[5]                 = 0x93c66b6c6d6e6f70;
            p[6]                 = 0x7172737475767778;
            p[7]                 = 0x797a3031;
            pktmbuf_data_len(xb) = 60;
        }

        n = __tx_flush(pd, fwd->pkt_api, tx_mbufs, n_pkts);
        if (n == PKTDEV_ADMIN_STATE_DOWN)
            return -1;
        pd->tx_overrun += n;
    }

    return 0;
}

static int
_txonly_rx_test(jcfg_lport_t *lport, struct fwd_info *fwd)
{
    struct fwd_port *pd = lport->priv_;
    pktmbuf_t *tx_mbufs[fwd->burst];
    int n_pkts, n;

    if (!pd)
        CNE_ERR_RET("fwd_port passed in lport private data is NULL\n");

    /* Cleanup RX side */
    n_pkts = __rx_burst(fwd->pkt_api, pd, pd->rx_mbufs, fwd->burst);
    if (n_pkts == PKTDEV_ADMIN_STATE_DOWN)
        return -1;

    pktmbuf_free_bulk(pd->rx_mbufs, n_pkts);

    if (fwd->pkt_api == PKTDEV_PKT_API)
        n_pkts = pktdev_buf_alloc(pd->lport, tx_mbufs, fwd->burst);
    else {
        region_info_t *ri = &lport->umem->rinfo[lport->region_idx];

        n_pkts = pktmbuf_alloc_bulk(ri->pool, tx_mbufs, fwd->burst);
    }

    if (n_pkts > 0) {
        for (int j = 0; j < n_pkts; j++) {
            pktmbuf_t *xb = tx_mbufs[j];
            uint64_t *p   = pktmbuf_mtod(xb, uint64_t *);

            /*
             * IPv4/UDP 64 byte packet
             * Port Src/Dest       :           1234/ 5678
             * Pkt Type            :           IPv4 / UDP
             * IP  Destination     :           198.18.1.1
             *     Source          :        198.18.0.1/24
             * MAC Destination     :    3c:fd:fe:e4:34:c0
             *     Source          :    3c:fd:fe:e4:38:40
             * 0000   3cfd fee4 34c0 3cfd fee4 3840 08004500
             * 0010   002e 60ac 0000 4011 8cec c612 0001c612
             * 0020   0101 04d2 162e 001a 93c6 6b6c 6d6e6f70
             * 0030   7172 7374 7576 7778 797a 3031
             */
            p[0]                 = 0x3cfdfee434c03cfd;
            p[1]                 = 0xfee4384008004500;
            p[2]                 = 0x002e60ac00004011;
            p[3]                 = 0x8cecc6120001c612;
            p[4]                 = 0x010104d2162e001a;
            p[5]                 = 0x93c66b6c6d6e6f70;
            p[6]                 = 0x7172737475767778;
            p[7]                 = 0x797a3031;
            pktmbuf_data_len(xb) = 60;
        }

        n = __tx_flush(pd, fwd->pkt_api, tx_mbufs, n_pkts);
        if (n == PKTDEV_ADMIN_STATE_DOWN)
            return -1;
        pd->tx_overrun += n;
    }

    return 0;
}

static void
destroy_per_thread_txbuff(jcfg_thd_t *thd, struct fwd_info *fwd)
{
    if (thd->priv_) {
        struct create_txbuff_thd_priv_t *thd_private = thd->priv_;
        txbuff_t **txbuffs                           = thd_private->txbuffs;
        int i;

        for (i = 0; i < jcfg_num_lports(fwd->jinfo); i++) {
            if (txbuffs[i])
                txbuff_free(txbuffs[i]);
            txbuffs[i] = NULL;
        }
        free(thd_private->txbuffs);
        thd_private->txbuffs = NULL;
        free(thd->priv_);
        thd->priv_ = NULL;
    }
}

static int
_create_txbuff(jcfg_info_t *jinfo __cne_unused, void *obj, void *arg, int idx)
{
    jcfg_lport_t *lport                          = obj;
    struct create_txbuff_thd_priv_t *thd_private = arg;
    txbuff_t **txbuffs                           = thd_private->txbuffs;
    struct fwd_port *pd;

    pd = lport->priv_;
    if (!pd)
        CNE_ERR_RET("fwd_port passed in lport private data is NULL\n");

    pkt_api_t pkt_api = thd_private->pkt_api;
    switch (pkt_api) {
    case XSKDEV_PKT_API:
        txbuffs[idx] =
            txbuff_xskdev_create(fwd->burst, txbuff_count_callback, &pd->tx_overrun, pd->xsk);
        break;
    case PKTDEV_PKT_API:
        txbuffs[idx] =
            txbuff_pktdev_create(fwd->burst, txbuff_count_callback, &pd->tx_overrun, pd->lport);
        break;
    default:
        txbuffs[idx] = NULL;
        break;
    }
    if (!txbuffs[idx])
        CNE_ERR_RET("Failed to create txbuff for lport %d\n", idx);

    return 0;
}

static int
create_per_thread_txbuff(jcfg_thd_t *thd, struct fwd_info *fwd)
{
    jcfg_lport_t *lport;

    if (thd->priv_) {
        CNE_ERR("Expected thread's private data to be unused but it is %p\n", thd->priv_);
        return -1;
    }
    struct create_txbuff_thd_priv_t *thd_private;
    thd_private = calloc(1, sizeof(struct create_txbuff_thd_priv_t));
    if (!thd_private) {
        CNE_ERR_RET("Failed to allocate thd_private for %d lport(s)\n",
                    jcfg_num_lports(fwd->jinfo));
    }

    thd_private->txbuffs = calloc(jcfg_num_lports(fwd->jinfo), sizeof(txbuff_t *));
    if (!thd_private->txbuffs) {
        free(thd_private);
        CNE_ERR_RET("Failed to allocate txbuff(s) for %d lport(s)\n", jcfg_num_lports(fwd->jinfo));
    }

    thd_private->pkt_api = fwd->pkt_api;
    thd->priv_           = thd_private;

    /* Allocate a Tx buffer for all lports, not just the receiving ones */
    if (jcfg_lport_foreach(fwd->jinfo, _create_txbuff, thd->priv_)) {
        destroy_per_thread_txbuff(thd, fwd);
        return -1;
    }

    /* Set reference for this thread's receiving lports, not all lports */
    foreach_thd_lport (thd, lport)
        ((struct fwd_port *)lport->priv_)->thd = thd;

    return 0;
}

void
thread_func(void *arg)
{
    struct thread_func_arg_t *func_arg = arg;
    struct fwd_info *fwd               = func_arg->fwd;
    jcfg_thd_t *thd                    = func_arg->thd;
    jcfg_lport_t *lport;
    // clang-format off
    struct {
        int (*func)(jcfg_lport_t *lport, struct fwd_info *fwd);
    } tests[] = {
        {NULL},
        {_drop_test},
        {_loopback_test},
        {_txonly_test},
        {_fwd_test},
        {acl_fwd_test},
        {acl_fwd_test},
        {_txonly_rx_test},
        {NULL}
    };
    // clang-format on

    if (thd->group->lcore_cnt > 0)
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &thd->group->lcore_bitmap);
    thd->tid = gettid();

    /* Wait for main thread to initialize */
    if (pthread_barrier_wait(&fwd->barrier) > 0)
        CNE_ERR_GOTO(leave, "Failed to wait on barrier\n");

    if (!thd->lport_cnt)
        goto leave_no_lport;

    if (fwd->test == FWD_TEST || fwd->test == ACL_STRICT_TEST || fwd->test == ACL_PERMISSIVE_TEST) {
        if (create_per_thread_txbuff(thd, fwd))
            cne_exit("Failed to create txbuff(s) for \"%s\" thread\n", thd->name);
    }

    cne_printf("   [green]Forwarding Thread ID [orange]%d [green]on lcore [orange]%d[]\n", thd->tid,
               cne_lcore_id());

    for (;;) {
        foreach_thd_lport (thd, lport) {
            if (thd->quit == THD_QUIT) /* Make sure we check quit often to break out ASAP */
                goto leave;
            if (thd->pause) {
                usleep(1000);        // sleep for 1ms
                continue;
            }

            if (tests[fwd->test].func(lport, fwd))
                goto leave;
        }
    }

leave:
    if (fwd->test == FWD_TEST || fwd->test == ACL_STRICT_TEST || fwd->test == ACL_PERMISSIVE_TEST)
        destroy_per_thread_txbuff(thd, fwd);
leave_no_lport:
    while (thd->quit != THD_QUIT)
        usleep(1000);
    // Free thread_func_arg_t.
    free(func_arg);

    /* There is a race between threads exiting and the destruction of thread resources. Avoid
     * this by notifying the cleanup signal handler that this thread is done.
     */
    thd->quit = THD_DONE;
}

static int
_thread_quit(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_thd_t *thd = obj;

    thd->quit = THD_QUIT;
    return 0;
}

static int
_thread_port_close(jcfg_info_t *j __cne_unused, void *obj, void *arg, int idx __cne_unused)
{
    jcfg_thd_t *thd = obj;
    jcfg_lport_t *lport;
    int ret;
    struct fwd_info *fwd = arg;

    if (thd->lport_cnt == 0) {
        CNE_DEBUG("No lports attached to thread '%s'\n", thd->name);
        return 0;
    } else
        CNE_DEBUG("Close %d lport%s for thread '%s'\n", thd->lport_cnt,
                  (thd->lport_cnt == 1) ? "" : "s", thd->name);

    foreach_thd_lport (thd, lport) {
        struct fwd_port *pd = lport->priv_;

        cne_printf(">>>    [magenta]lport [red]%d[] - '[cyan]%s[]'\n", lport->lpid, lport->name);
        switch (fwd->pkt_api) {
        case XSKDEV_PKT_API:
            xskdev_socket_destroy(pd->xsk);
            ret = 0;
            break;
        case PKTDEV_PKT_API:
            ret = pktdev_close(pd->lport);
            break;
        default:
            ret = -1;
            break;
        }
        if (ret < 0)
            CNE_ERR("port_close() returned error\n");
    }
    return 0;
}

static int
_check_thread_quit(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx)
{
    jcfg_thd_t *thd = obj;
    uint32_t timo   = TIMEOUT_VALUE;

    /* Make sure worker threads are done. Ignore main thread (idx=0) */
    while (--timo && thd->quit != THD_DONE && idx > 0)
        usleep(10000); /* 10ms */

    if (timo == 0)
        return -1;

    return 0;
}

static int
_thread_cleanup(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused,
                int idx __cne_unused)
{
    jcfg_thd_t *thd = obj;
    jcfg_lport_t *lport;

    if (thd->lport_cnt == 0) {
        CNE_DEBUG("No lports attached to thread '%s'\n", thd->name);
        return 0;
    } else
        CNE_DEBUG("Close %d lport%s for thread '%s'\n", thd->lport_cnt,
                  (thd->lport_cnt == 1) ? "" : "s", thd->name);

    foreach_thd_lport (thd, lport) {
        if (lport->umem) {
            for (int i = 0; i < lport->umem->region_cnt; i++) {
                pktmbuf_destroy(lport->umem->rinfo[i].pool);
                lport->umem->rinfo[i].pool = NULL;
            }
            mmap_free(lport->umem->mm);
            lport->umem->mm = NULL; /* Make sure we do not free this again */
        }
    }

    return 0;
}

static void
__on_exit(int val, void *arg, int exit_type)
{
    struct fwd_info *fwd = arg;

    switch (exit_type) {
    case CNE_CAUGHT_SIGNAL:
        /* Terminate the application if not USR1 signal, allows for GDB breakpoint setting */
        if (val == SIGUSR1)
            return;

        cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with signal [green]%d[]\n", val);

        fwd->timer_quit = 1;
        break;

    case CNE_CALLED_EXIT:
        if (val)
            cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with status [green]%d[]\n", val);

        if (fwd) {
            cne_printf(">>> [magenta]Closing lport(s)[]\n");
            jcfg_thread_foreach(fwd->jinfo, _thread_quit, fwd);
            jcfg_thread_foreach(fwd->jinfo, _thread_port_close, fwd);
            jcfg_thread_foreach(fwd->jinfo, _check_thread_quit, fwd);
            jcfg_thread_foreach(fwd->jinfo, _thread_cleanup, fwd);
            cne_printf(">>> [magenta]Done[]\n");

            udsc_close(fwd->xdp_uds);
            metrics_destroy();
            uds_destroy(NULL);

            fwd->timer_quit = 1;
        }
        break;

    case CNE_USER_EXIT:
        break;

    default:
        break;
    }
    fflush(stdout);
}

int
main(int argc, char **argv)
{
    // clang-format off
    const char *tests[] = {
        "Unknown", "Drop",
        "Loopback",
        "Tx Only",
        "Forward",
        "ACL Strict",
        "ACL Permissive",
        "Tx Only+RX",
        NULL
    };
    // clang-format on
    const char *apis[] = {"Unknown", "XSKDEV", "PKTDEV", NULL};
    int signals[]      = {SIGINT, SIGUSR1, SIGTERM};

    memset(&fwd_info, 0, sizeof(struct fwd_info));

    if (cne_init() || parse_args(argc, argv, fwd))
        goto err;

    cne_on_exit(__on_exit, fwd, signals, cne_countof(signals));

    cne_printf("\n[yellow]*** [cyan:-:italic]CNDPFWD Forward Application[], "
               "[green]API[]: [magenta:-:italic]%s[], "
               "[green]Mode[]: [magenta:-:italic]%s[], "
               "[green]Burst Size[]: [magenta]%d[] \n",
               apis[fwd->pkt_api], tests[fwd->test], fwd->burst);

    cne_printf("   [green]Initial Thread ID    [orange]%d [green]on lcore [orange]%d[]\n", getpid(),
               cne_lcore_id());

    /* if we're in ACL mode, initialize ACL context */
    if ((fwd->test == ACL_STRICT_TEST || fwd->test == ACL_PERMISSIVE_TEST) && acl_init(fwd) < 0)
        goto err;

    /* don't start any threads before we initialize ACL */
    if (pthread_barrier_wait(&fwd->barrier) > 0)
        CNE_ERR_GOTO(err, "Failed to wait for barrier\n");

    fwd->timer_quit = 0;
    for (;;) {
        sleep(1);

        if (fwd->timer_quit) /* Test for quitting after sleep to avoid calling print_port_stats() */
            break;

        if (fwd->opts.cli)
            print_port_stats_all(fwd);
    }
    if (pthread_barrier_destroy(&fwd->barrier))
        CNE_ERR_GOTO(err, "Failed to destroy barrier\n");

    cne_printf(">>> [cyan]Application Exiting[]: [green]Bye![]\n");
    return 0;

err:
    if (fwd->barrier_inited && pthread_barrier_destroy(&fwd->barrier))
        CNE_ERR("Failed to destroy barrier\n");

    cne_printf("\n*** [cyan]CNDPFWD Forward Application[], [green]API[]: [magenta]%s [green]PID[]: "
               "[magenta]%d[] failed\n",
               apis[fwd->pkt_api], getpid());
    return -1;
}
