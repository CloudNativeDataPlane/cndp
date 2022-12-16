/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>               // for NULL, EOF
#include <stdint.h>              // for uint8_t, uint64_t, uint16_t
#include <stdbool.h>             // for false, true, bool
#include <getopt.h>              // for getopt_long, no_argument, option, requ...
#include <tst_info.h>            // for tst_ok, tst_error, tst_end, tst_in...
#include <net/if.h>              // for IF_NAMESIZE
#include <cne_common.h>          // for CNE_MAX_ETHPORTS, CNE_SET_USED
#include <cne_mmap.h>            // for mmap_free, mmap_t, mmap_addr, mmap_alloc
#include <cne_log.h>             // for cne_panic
#include <cne_lport.h>           // for lport_cfg, LPORT_DFLT_START_QUEUE_IDX
#include <pmd_af_xdp.h>          // for PMD_NET_AF_XDP_NAME
#include <bsd/string.h>          // for strlcpy
#include <inttypes.h>            // for PRIx8
#include <net/ethernet.h>        // for ether_addr
#include <string.h>              // for strcmp, memset
#include <errno.h>               // for ENODEV, ENOTSUP
#include <stdlib.h>              // for free, malloc
#include <unistd.h>              // for sleep

#include "netdev_funcs.h"        // for netdev_promiscuous_enable
#include "pktdev_test.h"
#include "pktdev_api.h"        // for pktdev_port_setup, pktdev_close, pktde...
#include "pktdev.h"            // for pktdev_port_setup, pktdev_close, pktde...
#include "pktmbuf.h"           // for DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE
#include "xskdev.h"            // for XSKDEV_DFLT_RX_NUM_DESCS, XSKDEV_DFLT_...
#include "pmd_null.h"

struct pktdev_info;

typedef struct clean_up_s {
    mmap_t *mmap;
} clean_up_t;

static pktmbuf_info_t *pi = NULL;

static void
cleanup(void *arg)
{
    mmap_t *mmap = NULL;

    mmap = (mmap_t *)((clean_up_t *)arg)->mmap;
    mmap_free(mmap);
}

static void
set_cleanup_params(mmap_t *mmap, clean_up_t *clnup)
{
    if (mmap)
        clnup->mmap = mmap;
}

static int
reset_test_params(struct lport_cfg *cfg, const char *ifname, mmap_t *mmap, const char *pmd)
{
    memset(cfg, 0, sizeof(struct lport_cfg));

    strlcpy(cfg->ifname, ifname, sizeof(cfg->ifname));
    strlcpy(cfg->pmd_name, pmd, sizeof(cfg->pmd_name));
    strlcpy(cfg->name, ifname, sizeof(cfg->name));

    cfg->qid       = LPORT_DFLT_START_QUEUE_IDX;
    cfg->bufcnt    = DEFAULT_MBUF_COUNT;
    cfg->bufsz     = DEFAULT_MBUF_SIZE;
    cfg->addr      = mmap_addr(mmap);
    cfg->umem_addr = mmap_addr(mmap);
    cfg->umem_size = mmap_size(mmap, NULL, NULL);

    if (mmap) {
        pi = pktmbuf_pool_create(mmap_addr(mmap), DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE,
                                 MEMPOOL_CACHE_MAX_SIZE, NULL);
        if (!pi) {
            mmap_free(mmap);
            CNE_ERR_RET("pktmbuf_pool_create() failed\n");
        }

        cfg->pi = pi;
    }
    cfg->rx_nb_desc = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg->tx_nb_desc = XSK_RING_CONS__DEFAULT_NUM_DESCS;

    return 0;
}

static int
general_tests(const char *ifname, const char *pmd)
{
    int retval;
    int portid, socketid, dev_num;
    uint16_t lport;
    struct lport_cfg pc;
    bool admin_state = false;
    struct ether_addr eaddr;
    mmap_t *mmap = NULL;
    void (*clean_up)(void *);
    clean_up_t clnup = {NULL};

    clean_up = &cleanup;

    if (pi) {
        pktmbuf_destroy(pi);
        pi = NULL;
    }

    if (!strcmp(pmd, PMD_NET_AF_XDP_NAME)) {
        mmap = mmap_alloc(DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, MMAP_HUGEPAGE_4KB);
        if (mmap == NULL)
            cne_panic("Unable to mmap(%lu, %s) memory",
                      (uint64_t)DEFAULT_MBUF_COUNT * (uint64_t)DEFAULT_MBUF_SIZE,
                      mmap_name_by_type(MMAP_HUGEPAGE_4KB));

        tst_info("TEST: Invalid PMD Name");
        reset_test_params(&pc, ifname, mmap, pmd);
        set_cleanup_params(mmap, &clnup);
        strlcpy(pc.pmd_name, PMD_NET_AF_XDP_NAME "_", sizeof(pc.pmd_name));
        retval = pktdev_port_setup(&pc);
        TST_ASSERT_FAIL_AND_CLEANUP(retval, "FAILED --- TEST: Invalid PMD Name\n", clean_up,
                                    &clnup);
        tst_ok("PASS --- TEST: Invalid PMD Name");

        tst_info("TEST: Invalid ifname");
        reset_test_params(&pc, "UNKNOWN", mmap, pmd);
        retval = pktdev_port_setup(&pc);
        TST_ASSERT_FAIL_AND_CLEANUP(retval, "FAILED --- TEST: Invalid ifname\n", clean_up, &clnup);
        tst_ok("PASS --- TEST: Invalid ifname");
    }

    tst_info("TEST: Valid ifname Test PMD %s", pmd);
    reset_test_params(&pc, ifname, mmap, pmd);
    set_cleanup_params(mmap, &clnup);
    retval = pktdev_port_setup(&pc);
    TST_ASSERT_SUCCESS_AND_CLEANUP(retval, "FAILED --- TEST: Valid ifname Test\n", clean_up,
                                   &clnup);
    tst_ok("PASS --- TEST: Valid ifname Test");
    lport = retval;
    tst_info("TEST: Set admin state Down");
    admin_state = false;
    retval      = pktdev_admin_state_set(lport, admin_state);
    TST_ASSERT_SUCCESS_AND_CLEANUP(retval, "FAIL --- pktdev_admin_state_set(%d) failed\n", clean_up,
                                   &clnup, lport);
    admin_state = pktdev_admin_state(lport);
    TST_ASSERT_EQUAL(admin_state, false, "TEST: Set admin state Down");
    tst_ok("PASS --- TEST: Set admin state Down");

    tst_info("TEST: Set admin state up");
    admin_state = true;
    retval      = pktdev_admin_state_set(lport, admin_state);
    TST_ASSERT_SUCCESS_AND_CLEANUP(retval, "FAIL --- pktdev_admin_state_set(%d) failed\n", clean_up,
                                   &clnup, lport);
    admin_state = pktdev_admin_state(lport);
    TST_ASSERT_EQUAL(admin_state, true, "TEST: Set admin state Up");
    tst_ok("PASS --- TEST: Set admin state Up");

    if (!(strcmp(pmd, PMD_NET_AF_XDP_NAME))) {
        tst_info("TEST: Check lport MAC addr");
        /* Display the lport MAC address. */
        retval = pktdev_macaddr_get(lport, &eaddr);
        TST_ASSERT_SUCCESS_AND_CLEANUP(retval, "FAIL --- TEST:  Check lport MAC addr\n", clean_up,
                                       &clnup);
        tst_info("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
                 ":%02" PRIx8,
                 lport, eaddr.ether_addr_octet[0], eaddr.ether_addr_octet[1],
                 eaddr.ether_addr_octet[2], eaddr.ether_addr_octet[3], eaddr.ether_addr_octet[4],
                 eaddr.ether_addr_octet[5]);
        tst_ok("PASS --- TEST:  Check lport MAC addr");

        tst_info("TEST: Check lport enabled offloads");
        struct offloads off;
        /* Display the lport MAC address. */
        retval = pktdev_offloads_get(lport, &off);
        TST_ASSERT_SUCCESS_AND_CLEANUP(retval, "FAIL --- TEST:  Check lport offloads\n", clean_up,
                                       &clnup);
        tst_info("\n\nPort %u TX OFFLOAD %" PRIu32, lport, off.tx_checksum_offload);
        tst_info("Port %u RX OFFLOAD %" PRIu32, lport, off.rx_checksum_offload);
        tst_ok("PASS --- TEST:  Check lport enabled offloads");
    }

    tst_info("TEST: pktdev_promiscuous_enable");
    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = netdev_promiscuous_enable(ifname);
    if (!(strcmp(pmd, PMD_NET_AF_XDP_NAME)))
        TST_ASSERT_SUCCESS_AND_CLEANUP(retval, "FAIL --- pktdev_promiscuous_enable(%d)\n", clean_up,
                                       &clnup, lport);
    else
        TST_ASSERT_FAIL_AND_CLEANUP(retval, "FAIL --- pktdev_promiscuous_enable(%d)\n", clean_up,
                                    &clnup, lport);
    tst_ok("PASS --- TEST:  pktdev_promiscuous_enable");

    tst_info("TEST: Check lport's port_id");
    /* Display the lport port_id */
    struct cne_pktdev *dev;
    dev    = pktdev_get(lport);
    portid = pktdev_portid(dev);
    TST_ASSERT(portid >= 0, "TEST: Get the port id");
    tst_ok("PASS --- TEST: Get the portid of pktdev");

    tst_info("TEST: Check lport's socket_id");
    /* Display the socket id of the lport */
    socketid = pktdev_socket_id(lport);
    TST_ASSERT(socketid >= 0, "TEST: Get the socket id");
    tst_ok("PASS --- TEST: Get the socket id of pktdev");

    tst_info("TEST: Check pktdev port number");
    /* Get the total number for the pktdev ports */
    dev_num = pktdev_port_count();
    TST_ASSERT(dev_num > 0, "TEST: Get the pktdev port number");
    tst_ok("PASS --- TEST: Get the pktdev number");

    tst_info("TEST: API test for pktdev_info_get");
    struct pktdev_info *dev_info = (struct pktdev_info *)malloc(sizeof(struct pktdev_info));
    if (!dev_info)
        goto leave;
    TST_ASSERT_GOTO(pktdev_info_get(lport, dev_info) == 0,
                    "ERROR - Could not get the pktdev info\n", leave);
    tst_ok("PASS --- TEST: Get the pktdev info successful");
    TST_ASSERT_GOTO(pktdev_info_get(lport + 1, dev_info) == -ENOTSUP,
                    "ERROR - The error code isn't correct\n", leave);
    tst_ok("PASS --- TEST: Port info out of valid range checking passed");
    TST_ASSERT_GOTO(pktdev_info_get(CNE_MAX_ETHPORTS + 1, dev_info) == -ENODEV,
                    "ERROR - The error code isn't correct\n", leave);
    tst_ok("PASS --- TEST: Port number above max checking passed");
    free(dev_info);

    tst_info("TEST: API test for pktdev_socket_id");
    if (pktdev_socket_id(lport) >= 0)
        tst_ok("PASS --- TEST: socket is correct");
    else {
        tst_error("ERROR - Returned socket id failed");
        goto leave;
    }

    tst_info("TEST: API test for pktdev_portid");
    if (pktdev_portid(pktdev_get(lport)) == lport)
        tst_ok("PASS --- TEST: port id is correct");
    else {
        tst_error("ERROR - Return port id error");
        goto leave;
    }

    tst_info("TEST: API test for pktdev_arg_get");
    if (pktdev_arg_get(lport) != NULL)
        tst_ok("PASS --- TEST: pktdev_arg_get action pass");
    else {
        tst_error("ERROR - Return pktdev_arg_get() failed");
        goto leave;
    }

    tst_info("TEST: API test for is_valid_port");
    if (pktdev_is_valid_port(lport) == 1)
        tst_ok("PASS --- TEST: is_valid_port api test pass");
    else {
        tst_error("ERROR - Is_valid_port api test failed");
        goto leave;
    }
    if (pktdev_is_valid_port(lport + 1) == 0)
        tst_ok("PASS --- TEST: is_valid_port api test for invalid id pass");
    else {
        tst_error("ERROR - is_valid_port api test for invalid id fail");
        goto leave;
    }

    tst_info("TEST: API test for pktdev_get_name_by_port");
    char name[100];
    int len = 100;
    if (pktdev_get_name_by_port(lport, name, len) == 0) {
        tst_info("The pktdev name is: %s", name);
        tst_ok("PASS --- TEST: Get port name pass");
    } else {
        tst_error("ERROR - Get port name failed");
        goto leave;
    }

    tst_info("TEST: API test for pktdev_port_name");
    const char *name_link = NULL;
    name_link             = pktdev_port_name(lport);
    if (name_link != NULL) {
        tst_info("The pktdev name is: %d", name_link);
        tst_ok("PASS --- TEST: Get port name pass");
    } else {
        tst_error("ERROR - Get port name failed");
        goto leave;
    }

    tst_info("TEST: API test for lport_cfg_dump");
    lport_cfg_dump(NULL, &pc);
    tst_ok("PASS --- TEST: lport config dump pass");

    tst_info("TEST: API test for pktdev_start");
    if (pktdev_start(lport) < 0) {
        tst_error("ERROR - Could not start the lport");
        goto leave;
    }
    sleep(1);

    tst_info("TEST: API test for pktdev_stop");
    if (pktdev_stop(lport) < 0) {
        tst_error("ERROR - Could not stop the lport");
        goto leave;
    } else
        tst_ok("PASS --- TEST: pktdev stop success");
    sleep(1);

    /* Cleanup lport and complete test*/
    if (pktdev_close(lport)) {
        tst_error("ERROR - Could not close the lport");
        goto leave;
    } else
        tst_ok("PASS --- TEST: pktdev close success");

    lport = -1;
    sleep(1);

    if (!(strcmp(pmd, PMD_NET_AF_XDP_NAME)))
        mmap_free(mmap);
    return 0;
leave:
    mmap_free(mmap);
    return -1;
}

int
pktdev_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt, option_index = 0;
    char **argvopt, ifname[IF_NAMESIZE] = "UNKNOWN", afxdp_ifname[IF_NAMESIZE] = "UNKNOWN";
    const char *tests[] = {PMD_NET_AF_XDP_NAME, "net_ring", PMD_NET_NULL_NAME};
    // clang-format off
    static const struct option lgopts[] = {
        {"verbose", no_argument, NULL, 'v'},
        {"interface", required_argument, NULL, 'i'},
        {NULL, 0, 0, 0}
    };
    // clang-format on
    argvopt = argv;

    optind = 0;
    while ((opt = getopt_long(argc, argvopt, "Vi:r", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        case 'i':
            if (optarg != NULL)
                strlcpy(afxdp_ifname, optarg, sizeof(afxdp_ifname));
            break;
        case 'r':
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("Pktdev Tests");

    for (int i = 0; i < cne_countof(tests); i++) {
        memset(ifname, 0, IF_NAMESIZE);
        if (!(strcmp(afxdp_ifname, "UNKNOWN"))) {
            tst_error("No interface was specified for the pktdev tests \n"
                      "Need to specify at least 1 interface with the -i parameter");
            goto leave;
        }

        if (!(strcmp(tests[i], "net_ring")))
            strlcpy(ifname, "ring0", sizeof(ifname));
        else if (!strcmp(tests[i], PMD_NET_NULL_NAME))
            strlcpy(ifname, "null0", sizeof(ifname));
        else
            strlcpy(ifname, afxdp_ifname, sizeof(ifname));

        tst_info("%s Tests", tests[i]);

        if (general_tests(ifname, tests[i]) < 0)
            goto leave;
    }
    tst_end(tst, TST_PASSED);

    return 0;

leave:
    tst_error("pktdev tests failed");
    tst_end(tst, TST_FAILED);
    return -1;
}
