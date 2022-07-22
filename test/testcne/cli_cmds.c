/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <stdio.h>             // for NULL, snprintf
#include <stdint.h>            // for uint64_t
#include <cne_common.h>        // for CNE_SET_USED, __cne_unused, cne_countof
#include <cne_mmap.h>          // for mmap_sizes_t, mmap_stats_t
#include <pktmbuf.h>           // for pktmbuf_t
#include <pktdev.h>            // for pktdev_info
#include <cne_log.h>
#include <cli.h>             // for c_cmd, cli_path_string, cli_add_bin_path
#include <tst_info.h>        // for tst_error

#include "testcne.h"                  // for init_tree, my_prompt, setup_cli
#include "acl_test.h"                 // for acl_main
#include "cne_register_test.h"        // for cne_register_main
#include "cthread_test.h"             // for cthread_main
#include "dsa_test.h"                 // for dsa_main
#include "jcfg_test.h"                // for jcfg_main
#include "loop_test.h"                // for loop_main
#include "mbuf_test.h"                // for mbuf_main
#include "mempool_test.h"             // for mempool_main
#include "metrics_test.h"             // for metrics_main
#include "mmap_test.h"                // for mmap_main
#include "pktcpy_test.h"              // for pktcpy_main
#include "cne_lport.h"                // for lport_stats_t
#include "pkt_test.h"                 // for pkt_main
#include "ring_test.h"                // for ring_main
#include "ring_api.h"                 // for ring_api_main
#include "ring_profile.h"             // for ring_profile
#include "thread_test.h"              // for thread_main
#include "uid_test.h"                 // for uid_main
#include "pktdev_test.h"              // for pktdev_main
#include "kvargs_test.h"              // for kvargs_main
#include "graph_test.h"               // for graph_main, graph_perf_main
#include "hmap_test.h"                // for hmap_main
#include "timer_test.h"               // for timer_main
#include "xskdev_test.h"              // for xskdev_main
#include "netdev_funcs.h"             // for netdev_link
#include "log_test.h"                 // for log_main
#include "hash_test.h"                // for hash_main, hash_perf_main
#include "rib_test.h"                 // for rib_main, rib6_main
#include "fib_test.h"                 // for fib_main, fib_perf_main, fib6_main, fib6_perf_main
#ifdef HAS_UINTR_SUPPORT
#include "ibroker_test.h"        // for ibroker_main
#endif
#include "meter_test.h"        // for meter_main
#include "vec_test.h"          // for vec_main
#include "msgchan_test.h"
#include "tailqs_test.h"

struct struct_sizes {
    const char *name;
    uint64_t size;
    uint64_t expected;
};

static int
sizeof_cmd(int argc, char **argv)
{
    // clang-format off
    struct struct_sizes ssizes[] = {
        {"mmap_sizes_t", sizeof(mmap_sizes_t)},
        {"mmap_stats_t", sizeof(mmap_stats_t)},
        {"pktmbuf_t", sizeof(pktmbuf_t), 64},
        {"lport_stats", sizeof(lport_stats_t)},
        {"netdev_link", sizeof(struct netdev_link)},
        {"pktdev_info", sizeof(struct pktdev_info)},
    };
    // clang-format on
    bool failed = false;
    tst_info_t *tst;
    int i;

    CNE_SET_USED(argc);
    CNE_SET_USED(argv);

    tst = tst_start("Sizeof");

    for (i = 0; i < cne_countof(ssizes); i++) {
        if (ssizes[i].name == NULL)
            break;
        cne_printf("  [blue]%-24s[]= [green]%ld[]", ssizes[i].name, ssizes[i].size);
        if (ssizes[i].expected && (ssizes[i].size != ssizes[i].expected)) {
            cne_printf("  [red]*** Size Error expected %ld ***[]", ssizes[i].expected);
            failed = true;
        }
        cne_printf("\n");
    }

    if (failed)
        tst_end(tst, TST_FAILED);
    else
        tst_end(tst, TST_PASSED);

    return 0;
}

static int
all_tests(int argc, char **argv)
{
    acl_main(argc, argv);
    cne_register_main(argc, argv);
    cthread_main(argc, argv);
    dsa_main(argc, argv);
    fib_main(argc, argv);
    fib_perf_main(argc, argv);
    fib6_main(argc, argv);
    fib6_perf_main(argc, argv);
    graph_main(argc, argv);
    graph_perf_main(argc, argv);
    hash_main(argc, argv);
    hash_perf_main(argc, argv);
    hmap_main(argc, argv);
#ifdef HAS_UINTR_SUPPORT
    ibroker_main(argc, argv);
#endif
    jcfg_main(argc, argv);
    kvargs_main(argc, argv);
    log_main(argc, argv);
    mbuf_main(argc, argv);
    mempool_main(argc, argv);
    metrics_main(argc, argv);
    mmap_main(argc, argv);
    meter_main(argc, argv);
    msgchan_main(argc, argv);
    pkt_main(argc, argv);
    pktcpy_main(argc, argv);
    pktdev_main(argc, argv);
    rib_main(argc, argv);
    rib6_main(argc, argv);
    ring_api_main(argc, argv);
    ring_main(argc, argv);
    ring_profile(argc, argv);
    tailqs_main(argc, argv);
    thread_main(argc, argv);
    timer_main(argc, argv);
    uid_main(argc, argv);
    vec_main(argc, argv);
    xskdev_main(argc, argv);

    return 0;
}

// clang-format off
static struct cli_tree default_tree[] = {
    c_dir("/bin"),

    c_cmd("acl", acl_main, "Run the ACL tests"),
    c_cmd("all", all_tests, "Run all tests"),
    c_cmd("cne", cne_register_main, "Run the CNE registration tests"),
    c_cmd("cthread", cthread_main, "Run the cthread API test"),
    c_cmd("dsa", dsa_main, "Run the dsa API test"),
    c_cmd("fib", fib_main, "Run the FIB test"),
    c_cmd("fib_perf", fib_perf_main, "Run the FIB Perf test"),
    c_cmd("fib6", fib6_main, "Run the FIB6 test"),
    c_cmd("fib6_perf", fib6_perf_main, "Run the FIB6 Perf test"),
    c_cmd("graph_perf", graph_perf_main, "Run the graph perf test"),
    c_cmd("graph", graph_main, "Run the graph test"),
    c_cmd("hash_perf", hash_perf_main, "Run the hash perf test"),
    c_cmd("hash", hash_main, "Run the hash test"),
    c_cmd("hmap", hmap_main, "Run the HashMap CFG file tests"),
#ifdef HAS_UINTR_SUPPORT
    c_cmd("ibroker", ibroker_main, "Run the ibroker tests"),
#endif
    c_cmd("jcfg", jcfg_main, "Run the JSON CFG file tests"),
    c_cmd("kvargs", kvargs_main, "Run the KVARGS tests"),
    c_cmd("log", log_main, "Run log test"),
    c_cmd("loop", loop_main, "Port loop test"),
    c_cmd("mbuf", mbuf_main, "Run MBUF test"),
    c_cmd("mempool", mempool_main, "Run MEMPOOL test"),
    c_cmd("metrics", metrics_main, "Run Metrics test"),
    c_cmd("mmap", mmap_main, "Run MMAP test"),
    c_cmd("meter", meter_main, "Run Meter test"),
    c_cmd("msgchan", msgchan_main, "Run Message Channel test"),
    c_cmd("pkt", pkt_main, "Run PKT test"),
    c_cmd("pktcpy", pktcpy_main, "Run pktcpy test"),
    c_cmd("pktdev", pktdev_main, "Run the pktdev tests"),
    c_cmd("rib", rib_main, "Run RIB tests"),
    c_cmd("rib6", rib6_main, "Run RIB6 tests"),
    c_cmd("ring_api", ring_api_main, "Run RING api tests"),
    c_cmd("ring_profile", ring_profile, "Run RING profile test"),
    c_cmd("ring", ring_main, "Run RING test"),
    c_cmd("tailqs", tailqs_main, "Run TailQ test"),
    c_cmd("sizeof", sizeof_cmd, "Size of structures"),
    c_cmd("thread", thread_main, "Run the Thread test"),
    c_cmd("timer", timer_main, "Run the Timer test"),
    c_cmd("uid", uid_main, "Run the User ID Allocator test"),
    c_cmd("vec", vec_main, "Run the vec routine test"),
    c_cmd("xdpdev", xskdev_main, "Run the xdpdev API test (deprecated)"),
    c_cmd("xskdev", xskdev_main, "Run the xskdev API test"),

    c_end()
};
// clang-format on

int
init_tree(void)
{
    /* Add the system default commands in /sbin directory */
    if (cli_default_tree_init())
        return -1;

    /* Add the directory tree */
    if (cli_add_tree(cli_root_node(), default_tree))
        return -1;

    /* Make sure the txgen commands are executable in search path */
    if (cli_add_bin_path("/bin"))
        return -1;

    return 0;
}

int
my_prompt(int cont __cne_unused)
{
    char buff[256];
    int n;

    n = snprintf(buff, sizeof(buff), "test-cne:%s> ", cli_path_string(NULL, NULL));

    cne_printf("[green]test-cne:%s[]> ", cli_path_string(NULL, NULL));

    return n;
}

int
setup_cli(void)
{
    if (cli_create(NULL)) {
        tst_error("cli_create() failed\n");
        return -1;
    }

    if (cli_setup_with_tree(init_tree)) {
        tst_error("cli_setup_with_tree() failed\n");
        return -1;
    }

    return 0;
}
