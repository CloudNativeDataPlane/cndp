/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2025 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, EOF
#include <stdint.h>            // for uint64_t, uint16_t, uint32_t
#include <getopt.h>            // for getopt_long, option, required_argument
#include <bsd/string.h>        // for strlcpy
#include <xskdev.h>            // for xskdev_socket_create, xskdev_socket_de...
#include <tst_info.h>          // for tst_ok, TST_ASSERT_GOTO, tst_end
#include <cne_common.h>        // for CNE_SET_USED
#include <pmd_af_xdp.h>        // for PMD_NET_AF_XDP_NAME
#include <net/if.h>            // for IF_NAMESIZE
#include <string.h>            // for memset, strcmp
#include <unistd.h>            // for sleep

#include "xskdev_test.h"
#include "cne_log.h"          // for cne_panic
#include "cne_lport.h"        // for lport_cfg, lport_stats_t, LPORT_DFLT_S...
#include "cne_mmap.h"         // for mmap_addr, mmap_free, mmap_alloc, mmap...
#include "pktmbuf.h"          // for pktmbuf_destroy, pktmbuf_pool_create

static void
reset_test_params(struct lport_cfg *cfg, const char *ifname, mmap_t *mmap)
{

    char *addr;

    memset(cfg, 0, sizeof(struct lport_cfg));

    strlcpy(cfg->ifname, ifname, sizeof(cfg->ifname));
    strlcpy(cfg->pmd_name, PMD_NET_AF_XDP_NAME, sizeof(cfg->pmd_name));

    cfg->qid    = LPORT_DFLT_START_QUEUE_IDX;
    cfg->bufcnt = DEFAULT_MBUF_COUNT;
    cfg->bufsz  = DEFAULT_MBUF_SIZE;

    addr = cfg->umem_addr = mmap_addr(mmap);
    cfg->umem_size        = mmap_size(mmap, NULL, NULL);
    cfg->bufsz            = LPORT_FRAME_SIZE;
    cfg->rx_nb_desc       = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg->tx_nb_desc       = XSK_RING_CONS__DEFAULT_NUM_DESCS;

    /* Set the region of umem memory to Rx mempool address */
    cfg->addr = addr;
}

int
xskdev_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt, ifname[IF_NAMESIZE] = "UNKNOWN";
    int option_index;
    uint32_t flag = 0;
    struct lport_cfg pc;
    mmap_t *mmap                        = NULL;
    xskdev_info_t *xi                   = NULL;
    int retval                          = -1;
    static const struct option lgopts[] = {{"interface", required_argument, NULL, 'i'},
                                           {NULL, 0, 0, 0}};

    argvopt = argv;

    optind = 0;
    while ((opt = getopt_long(argc, argvopt, "Vi:", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        case 'i':
            if (optarg != NULL)
                strlcpy(ifname, optarg, sizeof(ifname));
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("xskdev API Tests");

    if (!(strcmp(ifname, "UNKNOWN"))) {
        cne_printf("[red]>>> No interface was specified for the af_xdp driver tests \n"
                   "[white] Need to specify at least 1 interface with the -i parameter\n");
        goto err;
    }

    /*************************************************************************/
    /*                       Valid Parameter Tests                           */
    /*************************************************************************/
    mmap = mmap_alloc(DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, MMAP_HUGEPAGE_4KB);
    if (mmap == NULL)
        cne_panic("Failed to mmap(%lu, %s) memory",
                  (uint64_t)DEFAULT_MBUF_COUNT * (uint64_t)DEFAULT_MBUF_SIZE,
                  mmap_name_by_type(MMAP_HUGEPAGE_4KB));
    reset_test_params(&pc, ifname, mmap);

    pc.pi = pktmbuf_pool_create(mmap_addr(mmap), DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE,
                                MEMPOOL_CACHE_MAX_SIZE, NULL);
    TST_ASSERT_GOTO(pc.pi, "FAILED --- TEST: pktmbuf_pool_init\n", err);
    tst_ok("PASS --- TEST: pktmbuf_pool_create\n");

    cne_printf("\n[blue]>>>[white]TEST: Socket Create[]\n");
    xi = xskdev_socket_create(&pc);
    TST_ASSERT_GOTO(xi, "FAILED --- TEST: Socket Create\n", err);
    tst_ok("PASS --- TEST: Socket Create\n");

    lport_stats_t stats = {0};
    retval              = -1;
    cne_printf("\n[blue]>>>[white]TEST: xskdev_stats_get[]\n");
    retval = xskdev_stats_get(xi, &stats);
    TST_ASSERT_GOTO(retval == 0, "FAILED --- TEST: xskdev_stats_get\n", err);
    xskdev_print_stats(ifname, &stats, 0);
    tst_ok("PASS --- TEST: xskdev_stats_get\n");

    cne_printf("\n[blue]>>>[white]TEST: xskdev_tx_burst[]\n");

    pktmbuf_t *tx_mbufs[256];
    int n_pkts = pktmbuf_alloc_bulk(pc.pi, tx_mbufs, 256);
    if (n_pkts > 0) {
        for (int j = 0; j < n_pkts; j++) {
            pktmbuf_t *xb = tx_mbufs[j];
            uint64_t *p   = pktmbuf_mtod(xb, uint64_t *);

            p[0]                 = 0xfd3c78299efefd3c;
            p[1]                 = 0x00450008b82c9efe;
            p[2]                 = 0;
            pktmbuf_data_len(xb) = 60;
        }
        uint16_t n = xskdev_tx_burst(xi, (void **)tx_mbufs, n_pkts);

        if (n != n_pkts)
            pktmbuf_free_bulk(tx_mbufs, n_pkts - n);

        TST_ASSERT_GOTO(n == n_pkts, "FAILED --- TEST: xskdev_tx_burst\n", err);
        cne_printf("\n[yellow]>>> Sent %d Packets\n", n);
    } else {
        cne_printf("\n[red]>>>xskdev_buf_alloc FAILED[]\n");
        goto err;
    }

    retval = xskdev_stats_get(xi, &stats);
    TST_ASSERT_GOTO(retval == 0 && stats.opackets == 256, "FAILED --- TEST: xskdev_tx_burst\n",
                    err);
    xskdev_print_stats(ifname, &stats, 0);
    tst_ok("PASS --- TEST: xskdev_tx_burst\n");

    cne_printf("\n[blue]>>>[white]TEST: xskdev_stats_reset[]\n");
    retval = xskdev_stats_reset(xi);
    TST_ASSERT_GOTO(retval == 0, "FAILED --- TEST: xskdev_stats_reset\n", err);
    retval = xskdev_stats_get(xi, &stats);
    TST_ASSERT_GOTO(retval == 0 && stats.opackets == 0, "FAILED --- TEST: xskdev_tx_burst\n", err);
    xskdev_print_stats(ifname, &stats, 0);
    tst_ok("PASS --- TEST: xskdev_stats_reset\n");

    cne_printf("\n[blue]>>>[white]TEST: xskdev_dump[]\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    xskdev_dump(xi, flag | XSKDEV_STATS_FLAG);
    xskdev_dump(xi, flag | XSKDEV_RX_FQ_TX_CQ_FLAG);
    tst_ok("PASS --- TEST: API xskdev_dump\n");
    sleep(1);

    xskdev_socket_destroy(xi);
    pktmbuf_destroy(pc.pi);

    /*************************************************************************/
    /*                       Invalid Parameter Tests                         */
    /*************************************************************************/
    cne_printf("\n[blue]>>>[white]TEST: Invalid ifname\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    reset_test_params(&pc, "UNKNOWN", mmap);
    xi = xskdev_socket_create(&pc);
    TST_ASSERT_GOTO(xi == NULL, "FAILED --- TEST: Invalid ifname\n", err);
    tst_ok("PASS --- TEST: Invalid ifname\n");
    xskdev_socket_destroy(xi);

    tst_end(tst, TST_PASSED);

    return 0;

err:
    if (mmap)
        mmap_free(mmap);
    tst_end(tst, TST_FAILED);
    return -1;
}
