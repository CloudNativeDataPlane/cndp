/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#include <pthread.h>             // for pthread_self, pthread_setaffinity_np
#include <signal.h>              // for signal, SIGUSR1, SIGINT
#include <sched.h>               // for cpu_set_t
#include <stdio.h>               // for printf, fflush, stdout, NULL
#include <stdlib.h>              // for exit, on_exit
#include <string.h>              // for memset
#include <unistd.h>              // for usleep, getpid, sleep
#include <cne_common.h>          // for __cne_unused
#include <cne_log.h>             // for CNE_ERR_RET, CNE_LOG_ERR
#include <pktdev.h>              // for pktdev_rx_burst, pktdev_tx_burst
#include <pktmbuf.h>             // for pktmbuf_t, pktmbuf_free_bulk, pktmbuf_all...
#include <txbuff.h>              // for txbuff_t, txbuff_add, txbuff_free
#include <net/ethernet.h>        // for ether_header, ether_addr
#include <dlb.h>                 // for DLB

#include "dlb_test.h"
#include "cne.h"               // for cne_init, cne_register
#include "cne_thread.h"        // for thread_register, thread_id
#include "jcfg.h"              // for jcfg_lport_t, jcfg_thd_t, jcfg_lport_by_i...
#include "pktdev_api.h"        // for pktdev_arg_get, pktdev_close

dlb_thread_args_t prod_args, cons_args, *work_args;

dlb_hdl_t dlb; /* DLB Device handle */
dlb_dev_cap_t cap;
int dev_id;
uint64_t num_events;
int num_workers;
dlb_domain_hdl_t domain;
int domain_id;
unsigned sns_per_queue;

static struct fwd_info fwd_info;
struct fwd_info *fwd = &fwd_info;

#define foreach_thd_lport(_t, _lp) \
    for (int _i = 0; _i < _t->lport_cnt && (_lp = _t->lports[_i]); _i++, _lp = _t->lports[_i])

#define PKTDEV_USE_NON_AVX 1
#if PKTDEV_USE_NON_AVX
static inline void
swap_mac_addresses(void *data)
{
    struct ether_header *eth    = (struct ether_header *)data;
    struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
    struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
    struct ether_addr tmp;

    tmp       = *src_addr;
    *src_addr = *dst_addr;
    *dst_addr = tmp;
}
#define MAC_SWAP swap_mac_addresses
#else
#define MAC_SWAP pktdev_mac_swap
#endif

static void
destroy_per_thread_txbuff(jcfg_thd_t *thd)
{
    if (thd->priv_) {
        txbuff_t **txbuffs = (txbuff_t **)thd->priv_;
        int i;

        for (i = 0; i < jcfg_num_lports(fwd->jinfo); i++) {
            if (txbuffs[i])
                txbuff_free(txbuffs[i]);
            txbuffs[i] = NULL;
        }

        free(thd->priv_);
        thd->priv_ = NULL;
    }
}

static int
_create_txbuff(jcfg_info_t *jinfo __cne_unused, void *obj, void *arg, int idx)
{
    jcfg_lport_t *lport = obj;
    txbuff_t **txbuffs  = arg;
    struct fwd_port *pd;

    pd           = lport->priv_;
    txbuffs[idx] = txbuff_pktdev_create(MAX_BURST, NULL, NULL, pd->lport);
    if (!txbuffs[idx])
        CNE_ERR_RET("Failed to create txbuff for lport %d\n", cne_lcore_id());

    cne_printf("Created TX buff for lport %d\n", cne_lcore_id());
    return 0;
}

static int
create_per_thread_txbuff(jcfg_thd_t *thd)
{
    jcfg_lport_t *lport;

    if (thd->priv_)
        CNE_ERR_RET("Expected thread's private data to be unused but it is %p\n", thd->priv_);

    thd->priv_ = calloc(jcfg_num_lports(fwd->jinfo), sizeof(txbuff_t *));
    if (!thd->priv_)
        CNE_ERR_RET("Failed to allocate txbuff(s) for %d lport(s)\n", jcfg_num_lports(fwd->jinfo));

    /* Allocate a Tx buffer for all lports, not just the receiving ones */
    if (jcfg_lport_foreach(fwd->jinfo, _create_txbuff, thd->priv_)) {
        destroy_per_thread_txbuff(thd);
        CNE_ERR_RET("Failed to create txbuff(s)\n");
    }

    /* Set reference for this thread's receiving lports, not all lports */
    foreach_thd_lport (thd, lport)
        ((struct fwd_port *)lport->priv_)->thd = thd;

    return 0;
}

int
producer(void *arg)
{
    jcfg_thd_t *thd = arg;
    jcfg_lport_t *lport;
    int n_pkts, n_evts;
    dlb_event_t events[MAX_BURST];
    uint8_t sched_type;
    int i, ret;

    if (thd->group->lcore_cnt > 0)
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &thd->group->lcore_bitmap);

    thd->tid = gettid();

    /* If there are no workers DLB can use only DIRECT ports and queues */
    if (num_workers == 0)
        sched_type = SCHED_DIRECTED;
    else
        sched_type = SCHED_ORDERED;

    cne_printf("  [blue]Producer Thread ID [red]%d [blue]on lcore [green]%d[]\n", thd->tid,
               cne_lcore_id());
    cne_printf("  [blue]Event Port ID [red]%d [blue]Enq Queue Id lcore [green]%d[]\n",
               prod_args.port_id, prod_args.queue_id);

    for (;;) {
        foreach_thd_lport (thd, lport) {
            if (thd->quit) /* Make sure we check quit often to break out ASAP */
                goto leave;

            struct fwd_port *pd = lport->priv_;
            if (!pd)
                continue;

            n_pkts = pktdev_rx_burst(pd->lport, pd->rx_mbufs, MAX_BURST);
            if (n_pkts == PKTDEV_ADMIN_STATE_DOWN)
                goto leave;

            if (n_pkts == 0)
                continue;
            for (i = 0; i < n_pkts; i++) {
                events[i].send.queue_id    = prod_args.queue_id;
                events[i].send.sched_type  = sched_type;
                events[i].send.priority    = 0;
                events[i].adv_send.udata64 = (uint64_t)pd->rx_mbufs[i];
            }

            /* Send the events */
            ret    = 0;
            n_evts = 0;
            for (i = 0; n_evts != n_pkts && i < RETRY_LIMIT; i++) {
                ret = dlb_send(prod_args.port, n_pkts - n_evts, &events[n_evts]);

                if (ret == -1)
                    break;

                n_evts += ret;
            }
            if (n_evts != n_pkts)
                CNE_ERR_RET("[%s()] Enqueued %d/%d packets!\n", __func__, n_evts, i);
            prod_args.curr_evt_stats.enq += n_evts;
        }
    }

leave:
    return 0;
}

int
consumer(void *arg)
{
    jcfg_thd_t *thd = arg;
    jcfg_lport_t *lport;
    txbuff_t **txbuff;
    dlb_event_t events[MAX_BURST];
    int ret;

    if (thd->group->lcore_cnt > 0)
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &thd->group->lcore_bitmap);

    thd->tid = gettid();

    cne_printf("  [blue]Consumer Thread ID [red]%d [blue]on lcore [green]%d[]\n", thd->tid,
               cne_lcore_id());
    cne_printf("  [blue]Event Port ID [red]%d [blue]Enq Queue Id lcore [green]%d[]\n",
               cons_args.port_id, cons_args.queue_id);

    if (create_per_thread_txbuff(thd))
        cne_exit("Failed to create txbuff(s) for \"%s\" thread\n", thd->name);

    for (;;) {
        foreach_thd_lport (thd, lport) {
            int i, num_deq;

            if (thd->quit) /* Make sure we check quit often to break out ASAP */
                goto leave;

            struct fwd_port *pd = lport->priv_;
            if (!pd)
                continue;

            txbuff = pd->thd->priv_;

            /* Receive the events */
            for (i = 0, num_deq = 0; num_deq == 0 && i < RETRY_LIMIT; i++) {
                ret = dlb_recv(cons_args.port, MAX_BURST - num_deq, POLL, &events[num_deq]);

                if (ret == -1)
                    break;

                num_deq += ret;
            }

            if (num_deq == 0)
                continue;

            cons_args.curr_evt_stats.deq += num_deq;

            for (i = 0; i < num_deq; i++) {
                /* MAC SWAP optional */
                MAC_SWAP(pktmbuf_mtod((pktmbuf_t *)events[i].recv.udata64, void *));
                (void)txbuff_add(txbuff[pd->lport], (pktmbuf_t *)events[i].recv.udata64);
            }
        }
    }

leave:
    return 0;
}

int
worker(void *arg)
{
    dlb_thread_args_t *args = (dlb_thread_args_t *)arg;
    dlb_event_t events[MAX_BURST];
    int num_enq, num_deq;
    int i, ret;

    thread_set_affinity(args->lcore);

    cne_printf("  [blue]Worker Thread ID [red]%d [blue]on lcore [green]%d[]\n", gettid(),
               cne_lcore_id());
    cne_printf("  [blue]Event Port ID [red]%d [blue]Enq Queue Id lcore [green]%d[]\n",
               args->port_id, args->queue_id);

    for (;;) {
        /* Receive the events */
        for (i = 0, num_deq = 0; num_deq == 0 && i < RETRY_LIMIT; i++) {
            ret = dlb_recv(args->port, MAX_BURST, POLL, events);

            if (ret == -1)
                break;

            num_deq += ret;
        }

        /* The port was disabled, indicating the thread should return */
        if (num_deq == -1 && errno == EACCES)
            break;

        if (num_deq == 0)
            continue;

        args->curr_evt_stats.deq += num_deq;

        for (i = 0; i < num_deq; i++) {
            events[i].send.queue_id   = args->queue_id;
            events[i].send.sched_type = SCHED_DIRECTED;
        }

        ret = 0;
        for (i = 0, num_enq = 0; num_enq < num_deq && i < RETRY_LIMIT; i++) {
            ret = dlb_forward(args->port, num_deq - num_enq, &events[num_enq]);

            if (ret == -1)
                break;

            num_enq += ret;
        }

        args->curr_evt_stats.enq += num_enq;

        if (num_enq != num_deq)
            CNE_ERR_RET("[%s()] Forwarded %d/%d packets!\n", __func__, num_enq, num_deq);
    }

    return 0;
}

static int
_thread_quit(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_thd_t *thd = obj;
    jcfg_lport_t *lport;

    thd->quit = 1;

    if (thd->lport_cnt == 0) {
        CNE_DEBUG("No lports attached to thread '%s'\n", thd->name);
        return 0;
    } else
        CNE_DEBUG("Close %d lport%s for thread '%s'\n", thd->lport_cnt,
                  (thd->lport_cnt == 1) ? "" : "s", thd->name);

    foreach_thd_lport (thd, lport) {
        cne_printf(">>>    [blue]lport [red]%d[] - '[cyan]%s[]'\n", lport->lpid, lport->name);
        if (pktdev_close(lport->lpid) < 0)
            CNE_ERR_RET("pktdev_close() returned error\n");
    }
    return 0;
}

static void
__on_exit(int val, void *arg, int exit_type)
{
    CNE_SET_USED(arg);

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

        cne_printf(">>> [blue]Closing lport(s)[]\n");
        cne_printf(">>> [blue]Done[]\n");

        if (fwd) {
            cne_printf(">>> [blue]Closing lport(s)[]\n");
            jcfg_thread_foreach(fwd->jinfo, _thread_quit, fwd);
            cne_printf(">>> [blue]Done[]\n");

            fwd->timer_quit = 1;
        }
        break;

    case CNE_USER_EXIT:
        cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with signal [green]%d[]\n", val);
        fwd->timer_quit = 1;
        break;

    default:
        break;
    }
    fflush(stdout);
}

int
main(int argc __cne_unused, char **argv __cne_unused)
{
    int signals[] = {SIGINT, SIGUSR1};

    memset(&fwd_info, 0, sizeof(struct fwd_info));

    if (cne_init() < 0)
        goto err;

    cne_on_exit(__on_exit, fwd, signals, cne_countof(signals));

    if (parse_args(argc, argv))
        goto err;

    if (cne_max_lcores() < (unsigned)(2 + num_workers))
        goto err;

    cne_printf("\nMax threads: %d, Max lcores: %d, NUMA nodes: %d, Num Workers: %d\n",
               cne_max_threads() - 2, cne_max_lcores(), cne_max_numa_nodes(), num_workers);

    fwd->timer_quit = 0;
    for (;;) {
        sleep(1);

        if (fwd->timer_quit) /* Test for quitting after sleep to avoid calling print_port_stats() */
            break;

        print_port_stats_all();
        print_dlb_stats();
    }

    dlb_remove();
    cne_printf(">>> [cyan]Main Application Exiting[]: [green]Bye![]\n");
    return 0;

err:
    cne_printf("\n*** [cyan]DLB Test Application[], [blue]PID[]: [green]%d[] failed\n", getpid());
    return 0;
}
