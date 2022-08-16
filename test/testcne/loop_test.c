/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, printf, fflush, EOF, stdout
#include <stdlib.h>            // for atoi
#include <string.h>            // for memset, memcpy
#include <stdint.h>            // for uint64_t, uint32_t, uintptr_t
#include <stdbool.h>           // for false, true, bool
#include <unistd.h>            // for sleep
#include <getopt.h>            // for getopt_long, option
#include <time.h>              // for clock_gettime, timespec
#include <signal.h>            // for signal, kill, SIGHUP, SIGUSR1, SIGINT
#include <cne_thread.h>        // for thread_create
#include <pktmbuf.h>           // for pktmbuf_t, DEFAULT_MBUF_COUNT, DEFAULT...
#include <pktdev.h>            // for pktdev_tx_burst, pktdev_mac_swap, pktd...
#include <tst_info.h>          // for tst_error, tst_end, tst_ok, tst_start
#include <sys/time.h>          // for CLOCK_MONOTONIC
#include <hexdump.h>           // for cne_hexdump
#include <bsd/string.h>        // for strlcpy
#include <pmd_af_xdp.h>        // for PMD_NET_AF_XDP_NAME

#include "loop_test.h"
#include "cne_common.h"          // for CNE_SET_USED, __cne_unused, cne_countof
#include "pktdev_api.h"          // for pktdev_port_setup
#include "cne_lport.h"           // for lport_cfg_t, lport_stats_t, LPORT_DFLT...
#include "netdev_funcs.h"        // for netdev_link, netdev_get_link, netdev_s...
#include "xskdev.h"              // for XSKDEV_DFLT_RX_NUM_DESCS, XSKDEV_DFLT_...
#include "cne_log.h"             // for cne_panic
#include "cne_mmap.h"            // for mmap_addr, mmap_alloc, mmap_name_by_type

static unsigned long long opt_duration;
static unsigned long start_time;
static bool benchmark_done = false;
static bool print_mempool  = false;
static bool dump_packet    = false;
static unsigned long prev_time;
lport_stats_t prev_stats;
#define DROP_TEST     0
#define LOOPBACK_TEST 1
#define L2FWD_TEST    2
#define TX_ONLY_TEST  3

static int test_type = DROP_TEST;

static unsigned long
get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static void
dump_stats(void)
{
    unsigned long now = get_nsecs();
    long dt           = now - prev_time;
    lport_stats_t stats;
    double rx_pps, tx_pps;

    prev_time = now;

    memset(&stats, 0, sizeof(stats));

    pktdev_stats_get(0, &stats);

    rx_pps = (stats.ipackets - prev_stats.ipackets) * 1000000000. / dt;
    tx_pps = (stats.opackets - prev_stats.opackets) * 1000000000. / dt;

    cne_printf("[blue]%10ld %10ld[] [red]%10ld %10ld [yellow]%'10.0f %'10.0f[]\n", stats.ipackets,
               stats.opackets, stats.imissed, stats.oerrors, rx_pps, tx_pps);

    memcpy(&prev_stats, &stats, sizeof(lport_stats_t));
}

static bool
is_benchmark_done(void)
{
    if (opt_duration > 0) {
        unsigned long dt = (get_nsecs() - start_time);

        if (dt >= opt_duration)
            benchmark_done = true;
    }
    return benchmark_done;
}

static void
poller(void *arg __cne_unused)
{
    uint64_t secs = 0;

    while (!is_benchmark_done()) {
        sleep(1);
        if ((secs % 10) == 0)
            cne_printf("[green]%10s %10s %10s %10s %10s %10s[]\n", "ipackets", "opackets",
                       "imissed", "oerrors", "RX pps", "TX pps");
        secs++;
        dump_stats();
    }
}

static void
sig_handler(int v)
{
    if (v == SIGUSR1) {
        print_mempool = true;
        dump_packet   = true;
    } else if (v == SIGHUP) {
        benchmark_done = true;
    } else {
        cne_printf(" Received signal %d\n", v);
        kill(0, SIGTERM);
    }
}

static int
rx_cb(pktmbuf_info_t *pi, pktmbuf_t *mb, uint32_t sz, uint32_t idx, void *opaque)
{
    CNE_SET_USED(pi);
    CNE_SET_USED(sz);
    CNE_SET_USED(opaque);
    CNE_SET_USED(idx);

    if (!mb || mb->pooldata == NULL) {
        cne_printf("Object %p, mempool is NULL\n", mb);
        return -1;
    } else
        pktmbuf_dump("MBUF", mb, 0);

    return 0;
}

int
loop_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt;
    int option_index;
    char *ifname;
    int lport;
    struct netdev_link link;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};
    pktmbuf_t *mbufs[128];
    lport_cfg_t cfg;
    mmap_t *mmap = NULL;
    int nb, num, n;

    signal(SIGHUP, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    argvopt = argv;

    lport = 0;

    optind = 0;
    ifname = (char *)(uintptr_t) "Unknown";
    while ((opt = getopt_long(argc, argvopt, "Vi:d:DLT2", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        case 'i':
            ifname = optarg;
            break;
        case 'D':
            test_type = DROP_TEST;
            break;
        case 'L':
            test_type = LOOPBACK_TEST;
            break;
        case 'T':
            test_type = TX_ONLY_TEST;
            break;
        case '2':
            test_type = L2FWD_TEST;
            break;
        case 'd':
            opt_duration = atoi(optarg);
            if (opt_duration <= 0 || opt_duration > INT_MAX) {
                /* opt_duraton won't be >INT_MAX, but the check silences klocwork */
                cne_printf("Invalid duration\n");
                return -1;
            }
            opt_duration *= 1000000000;
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("Port Loop Test");

    prev_time  = get_nsecs();
    start_time = prev_time;

    tst_ok("Use 'sudo killall -HUP test-cne' to stop\n");

    if (thread_create("Poller", poller, NULL) < 0) {
        tst_error("Failed to start Poller routine\n");
        goto leave;
    }

    mmap = mmap_alloc(DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, MMAP_HUGEPAGE_4KB);
    if (mmap == NULL)
        cne_panic("Unable to mmap(%lu, %s) memory",
                  (uint64_t)DEFAULT_MBUF_COUNT * (uint64_t)DEFAULT_MBUF_SIZE,
                  mmap_name_by_type(MMAP_HUGEPAGE_4KB));

    memset(&cfg, 0, sizeof(cfg));

    strlcpy(cfg.name, ifname, sizeof(cfg.name));
    strlcpy(cfg.pmd_name, PMD_NET_AF_XDP_NAME, sizeof(cfg.pmd_name));
    strlcpy(cfg.ifname, ifname, sizeof(cfg.ifname));

    cfg.addr = cfg.umem_addr = mmap_addr(mmap);
    cfg.umem_size            = mmap_size(mmap, NULL, NULL);
    cfg.qid                  = LPORT_DFLT_START_QUEUE_IDX;
    cfg.bufsz                = LPORT_FRAME_SIZE;
    cfg.bufcnt               = DEFAULT_MBUF_COUNT;
    cfg.rx_nb_desc           = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg.tx_nb_desc           = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    cfg.pi = pktmbuf_pool_create(mmap_addr(mmap), DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, 0, NULL);

    lport = pktdev_port_setup(&cfg);
    if (lport < 0) {
        tst_error("pktdev_port_setup() failed\n");
        goto leave;
    }

    if (netdev_set_link_up(ifname) < 0) {
        tst_error("netdev_set_link_up(%d) failed\n", lport);
        goto leave;
    }

    if (netdev_get_link(ifname, &link) < 0) {
        tst_error("netdev_get_link(%s) failed\n", ifname);
        goto leave;
    }

    cne_printf("[blue]Link State[]: [yellow]%s-%d-%s[]\n",
               link.link_duplex == ETH_LINK_FULL_DUPLEX ? "Full" : "Half", link.link_speed,
               link.link_status == ETH_LINK_DOWN ? "Down" : "Up");

    while (!is_benchmark_done()) {
        if (print_mempool) {
            print_mempool = false;
            /* Add the dump of pktmbuf pool */
            pktmbuf_iterate(cfg.pi, rx_cb, NULL);
        }

        num = pktdev_rx_burst(lport, mbufs, cne_countof(mbufs));
        if (num == PKTDEV_ADMIN_STATE_DOWN)
            goto leave;
        if (num == 0 || num > cne_countof(mbufs))
            continue;

        if (test_type == DROP_TEST)
            pktmbuf_free_bulk(mbufs, num);
        else if (test_type == LOOPBACK_TEST) {
            while (num) {
                nb = pktdev_tx_burst(lport, mbufs, num);
                if (nb == PKTDEV_ADMIN_STATE_DOWN)
                    goto leave;

                num -= nb;
            }
        } else if (test_type == TX_ONLY_TEST) {
            if (num > 0) {
                for (int j = 0; j < num; j++) {
                    pktmbuf_t *xb = mbufs[j];
                    uint64_t *p   = pktmbuf_mtod(xb, uint64_t *);

                    p[0]                 = 0xfd3c78299efefd3c;
                    p[1]                 = 0x00450008b82c9efe;
                    p[2]                 = 0x110400004f122e00;
                    p[3]                 = 0xa8c00100a8c01e22;
                    p[4]                 = 0x1a002e16d2040101;
                    p[5]                 = 0x706f6e6d6c6b9a9e;
                    p[6]                 = 0x7877767574737271;
                    p[7]                 = 0x31307a79;
                    pktmbuf_data_len(xb) = 60;
                }
                n = pktdev_tx_burst(lport, mbufs, num);
                if (n == PKTDEV_ADMIN_STATE_DOWN)
                    goto leave;
            }
        } else if (test_type == L2FWD_TEST) {
            for (int i = 0; i < num; i++) {
                pktmbuf_t *m = mbufs[i];
                void *body   = pktmbuf_mtod(m, void *);

                if (dump_packet)
                    cne_hexdump(NULL, "Before", body, 64);

                pktdev_mac_swap(body);

                if (dump_packet) {
                    cne_hexdump(NULL, "after", body, 64);
                    dump_packet = false;
                }
            }
            while (num) {
                nb = pktdev_tx_burst(lport, mbufs, num);
                if (nb == PKTDEV_ADMIN_STATE_DOWN)
                    goto leave;

                num -= nb;
            }
        }
    }

leave:
    if (pktdev_close(lport) < 0)
        tst_error("pktdev_close(%d) failed\n", lport);

    benchmark_done = true;

    tst_end(tst, TST_PASSED);
    mmap_free(mmap);

    return 0;
}
