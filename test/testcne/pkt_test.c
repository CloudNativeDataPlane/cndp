/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, stdout, EOF
#include <stdint.h>            // for uint64_t, uint16_t, UINT32_MAX, UINT16...
#include <getopt.h>            // for getopt_long, option
#include <sys/wait.h>          // for wait
#include <cne_common.h>        // for CNE_PKTMBUF_HEADROOM, CNE_SET_USED
#include <cne_mmap.h>          // for mmap_free, mmap_addr, mmap_alloc, MMAP...
#include <tst_info.h>          // for tst_ok, TST_ASSERT_GOTO, tst_error
#include <cne_log.h>
#include <pktmbuf.h>        // for pktmbuf_t, pktmbuf_free, pktmbuf_alloc
#include <stdlib.h>         // for exit
#include <string.h>         // for memset, memcmp
#include <unistd.h>         // for fork

#include "pkt_test.h"

#define NB_MBUF                128
#define MBUF_TEST_DATA_LEN     60
#define MBUF_TEST_DATA_LEN2    50
#define MBUF_TEST_HDR1_LEN     20
#define MBUF_TEST_HDR2_LEN     30
#define MBUF_TEST_ALL_HDRS_LEN (MBUF_TEST_HDR1_LEN + MBUF_TEST_HDR2_LEN)

static pktmbuf_info_t *pi = NULL;
static mmap_t *mm         = NULL;

static int
create_pktmbuf(void)
{
    mm = mmap_alloc(DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, MMAP_HUGEPAGE_DEFAULT);
    TST_ASSERT_GOTO(mm, "unable to allocate memory", err);

    pi = pktmbuf_pool_create(mmap_addr(mm), DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE,
                             MEMPOOL_CACHE_MAX_SIZE, NULL);
    TST_ASSERT_GOTO(pi != NULL, "unable to allocate pktmbufs", err);

    return 0;
err:
    mmap_free(mm);
    return -1;
}

static void
destroy_pktmbuf(void)
{
    pktmbuf_destroy(pi);
    mmap_free(mm);
    pi = NULL;
    mm = NULL;
}

static int
simple_pkt_test(void)
{
    int ret              = -1;
    pktmbuf_t *mbufs[32] = {NULL};

    cne_printf("[blue]>>>[white]SUBTEST: pktmbuf_pool_create\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);

    if (create_pktmbuf())
        goto leave;
    tst_ok("PASS --- SUBTEST: pktmbuf_pool_create\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_alloc_bulk\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    ret = pktmbuf_alloc_bulk(pi, mbufs, 32);
    TST_ASSERT_GOTO(ret > 0, "SUBTEST: pktmbuf_alloc_bulk failed\n", leave);
    tst_ok("PASS --- SUBTEST: pktmbuf_alloc_bulk\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_copy\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    uint64_t *p                = pktmbuf_mtod(mbufs[0], uint64_t *);
    p[0]                       = 0xfd3c78299efefd3c;
    p[1]                       = 0x00450008b82c9efe;
    p[2]                       = 0x0;
    pktmbuf_data_len(mbufs[0]) = 60;
    cne_printf("[magenta]");
    pktmbuf_dump("pktmbuf[0]", mbufs[0], pktmbuf_data_len(mbufs[0]));
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);

    pktmbuf_t *copy = pktmbuf_copy(mbufs[0], pi, 0, UINT32_MAX);
    TST_ASSERT_GOTO(copy, "SUBTEST: pktmbuf_copy failed\n", leave);
    cne_printf("[magenta]");
    pktmbuf_dump("copy", copy, pktmbuf_data_len(copy));
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    tst_ok("PASS --- SUBTEST: pktmbuf_copy\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: memcmp copied buffer\n");
    uint64_t *p1 = pktmbuf_mtod(copy, uint64_t *);
    ret          = memcmp(p, p1, 60);
    TST_ASSERT_GOTO(ret == 0, "SUBTEST: memcmp copied buffer failed\n", leave);
    tst_ok("PASS --- SUBTEST:  memcmp copied buffer\n");
    pktmbuf_free(copy);

leave:
    pktmbuf_free_bulk((pktmbuf_t **)mbufs, 32);
    destroy_pktmbuf();
    return 0;
}

/*
 * test data manipulation in pktmbuf
 */
static int
test_one_pktmbuf(void)
{
    pktmbuf_t *m = NULL;
    char *data, *data2, *hdr;
    unsigned i;

    cne_printf("[blue]>>>[white]SUBTEST: pktmbuf API\n");

    /* alloc a pktmbuf */
    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_alloc\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    m = pktmbuf_alloc(pi);
    TST_ASSERT_GOTO(m, "SUBTEST: pktmbuf_alloc failed\n", fail);
    tst_ok("PASS --- SUBTEST: pktmbuf_alloc\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_data_len\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_data_len(m) == 0, "SUBTEST: pktmbuf_data_len failed\n", fail);
    tst_ok("PASS --- SUBTEST: pktmbuf_data_len\n");

    cne_printf("[magenta]");
    pktmbuf_dump("m", m, 0);
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);

    /* append data */
    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_append\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    data = pktmbuf_append(m, MBUF_TEST_DATA_LEN);
    TST_ASSERT_GOTO(data != NULL, "SUBTEST: pktmbuf_append failed\n", fail);
    tst_ok("PASS --- SUBTEST: pktmbuf_append\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_data_len\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_data_len(m) == MBUF_TEST_DATA_LEN, "SUBTEST: pktmbuf_data_len failed\n",
                    fail);
    tst_ok("PASS --- SUBTEST: pktmbuf_data_len\n");

    memset(data, 0x66, pktmbuf_data_len(m));
    cne_printf("[magenta]");
    pktmbuf_dump("m", m, MBUF_TEST_DATA_LEN);
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);

    cne_printf("\n[blue]>>>[white]pktmbuf_data_len(m) %d\n", pktmbuf_data_len(m));

    /* this append should fail */
    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_append invalid\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    data2 = pktmbuf_append(m, (uint16_t)(pktmbuf_tailroom(m) + 1));
    TST_ASSERT_GOTO(data2 == NULL, "SUBTEST: pktmbuf_append invalid failed\n", fail);
    tst_ok("PASS --- SUBTEST: pktmbuf_append invalid\n");

    /* append some more data */
    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_append valid\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    data2 = pktmbuf_append(m, MBUF_TEST_DATA_LEN2);
    TST_ASSERT_GOTO(data2 != NULL, "SUBTEST: pktmbuf_append valid failed\n", fail);
    tst_ok("PASS --- SUBTEST: pktmbuf_append valid\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: Check packet length valid\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_data_len(m) == (MBUF_TEST_DATA_LEN + MBUF_TEST_DATA_LEN2),
                    "SUBTEST: Check packet length valid\n", fail);
    tst_ok("PASS --- SUBTEST: Check packet length valid\n");

    /* trim data at the end of pktmbuf */
    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_trim\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_trim(m, MBUF_TEST_DATA_LEN2) == 0, "SUBTEST: pktmbuf_trim\n", fail);
    tst_ok("PASS --- SUBTEST: pktmbuf_trim\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: check length after pktmbuf_trim\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_data_len(m) == MBUF_TEST_DATA_LEN,
                    "SUBTEST: check length after pktmbuf_trim\n", fail);
    tst_ok("PASS --- SUBTEST: check length after pktmbuf_trim\n");

    /* this trim should fail */
    cne_printf("\n[blue]>>>[white]SUBTEST: invalid pktmbuf_trim\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_trim(m, (uint16_t)(pktmbuf_data_len(m) + 1)) != 0,
                    "SUBTEST: invalid pktmbuf_trim\n", fail);
    tst_ok("PASS --- SUBTEST: invalid pktmbuf_trim\n");

    /* prepend one header */
    cne_printf("\n[blue]>>>[white]SUBTEST: prepend one header\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    hdr = pktmbuf_prepend(m, MBUF_TEST_HDR1_LEN);
    TST_ASSERT_GOTO(hdr != NULL, "SUBTEST: prepend one header\n", fail);
    tst_ok("PASS --- SUBTEST: prepend one header\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: Verify prepend one header 1\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(data - hdr == MBUF_TEST_HDR1_LEN, "SUBTEST: Verify prepend one header 1\n",
                    fail);
    tst_ok("PASS --- SUBTEST: Verify prepend one header 1\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: Verify prepend one header 2\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_data_len(m) == MBUF_TEST_DATA_LEN + MBUF_TEST_HDR1_LEN,
                    "SUBTEST: Verify prepend one header 2\n", fail);
    tst_ok("PASS --- SUBTEST: Verify prepend one header 2\n");

    memset(hdr, 0x55, MBUF_TEST_HDR1_LEN);

    /* prepend another header */
    cne_printf("\n[blue]>>>[white]SUBTEST: prepend another valid header\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    hdr = pktmbuf_prepend(m, MBUF_TEST_HDR2_LEN);
    TST_ASSERT_GOTO(hdr != NULL, "SUBTEST: prepend another valid header\n", fail);
    tst_ok("PASS --- SUBTEST: prepend another valid header\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: Verify prepend one header 1\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(data - hdr == MBUF_TEST_ALL_HDRS_LEN, "SUBTEST: Verify prepend one header 1\n",
                    fail);
    tst_ok("PASS --- SUBTEST: Verify prepend one header 1\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: Verify prepend one header 2\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_data_len(m) == MBUF_TEST_DATA_LEN + MBUF_TEST_ALL_HDRS_LEN,
                    "SUBTEST: Verify prepend one header 2\n", fail);
    tst_ok("PASS --- SUBTEST: Verify prepend one header 2\n");

    memset(hdr, 0x55, MBUF_TEST_HDR2_LEN);

    pktmbuf_sanity_check(m, 1);
    pktmbuf_sanity_check(m, 0);
    cne_printf("[magenta]");
    pktmbuf_dump("m", m, 0);
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);

    /* this prepend should fail */
    cne_printf("\n[blue]>>>[white]SUBTEST: prepend an invalid header\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    hdr = pktmbuf_prepend(m, (uint16_t)(CNE_PKTMBUF_HEADROOM + 1));
    TST_ASSERT_GOTO(hdr == NULL, "SUBTEST: prepend an invalid header\n", fail);
    tst_ok("PASS --- SUBTEST: prepend an invalid header\n");

    /* remove data at beginning of pktmbuf (adj) */
    cne_printf("\n[blue]>>>[white]SUBTEST: remove data at beginning of pktmbuf (adj)\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(data == pktmbuf_adj_offset(m, MBUF_TEST_ALL_HDRS_LEN),
                    "SUBTEST: remove data at beginning of pktmbuf (adj)\n", fail);
    tst_ok("PASS --- SUBTEST: remove data at beginning of pktmbuf (adj)\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: Verify pktmbuf_prepend\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_data_len(m) == MBUF_TEST_DATA_LEN, "SUBTEST: Verify pktmbuf_prepend\n",
                    fail);
    tst_ok("PASS --- SUBTEST: Verify pktmbuf_prepend\n");

    /* this adj should fail */
    cne_printf("\n[blue]>>>[white]SUBTEST: invalid remove data at beginning of pktmbuf (adj)\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(pktmbuf_adj_offset(m, (uint16_t)(pktmbuf_data_len(m) + 1)) == NULL,
                    "SUBTEST: invalid  remove data at beginning of pktmbuf (adj)\n", fail);
    tst_ok("PASS --- SUBTEST:  invalid remove data at beginning of pktmbuf (adj)\n");

    for (i = 0; i < MBUF_TEST_DATA_LEN; i++) {
        if (data[i] != 0x66) {
            tst_error("Data corrupted at offset %u", i);
            goto fail;
        }
    }
    tst_ok("PASS --- SUBTEST: pktmbuf API\n");
    /* free pktmbuf */
    pktmbuf_free(m);
    m = NULL;
    return 0;

fail:
    tst_error("FAILED --- SUBTEST: pktmbuf API\n");
    pktmbuf_free(m);
    return -1;
}

/*
 * test allocation and free of mbufs
 */
static int
test_pktmbuf_pool(void)
{
    unsigned i;
    pktmbuf_t *m[DEFAULT_MBUF_COUNT];

    cne_printf("[blue]>>>[white]SUBTEST:  test_pktmbuf_pool\n");

    for (i = 0; i < DEFAULT_MBUF_COUNT - 1; i++)
        m[i] = NULL;

    /* alloc NB_MBUF mbufs */
    cne_printf("\n[blue]>>>[white]SUBTEST: alloc NB_MBUF mbufs\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    for (i = 0; i < DEFAULT_MBUF_COUNT - 1; i++) {
        m[i] = pktmbuf_alloc(pi);
        TST_ASSERT_GOTO(m[i] != NULL, "SUBTEST: alloc NB_MBUF mbufs\n", leave);
    }
    tst_ok("PASS ---  SUBTEST: alloc NB_MBUF mbufs\n");

    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_copy\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    pktmbuf_t *extra = NULL;
    extra            = pktmbuf_copy(m[0], pi, 0, UINT32_MAX);
    TST_ASSERT_GOTO(extra != NULL, "SUBTEST: pktmbuf_copy\n", leave);
    tst_ok("PASS ---  SUBTEST: pktmbuf_copy\n");

    /* free them */
    for (i = 0; i < DEFAULT_MBUF_COUNT - 1; i++) {
        pktmbuf_free(m[i]);
    }

    pktmbuf_free(extra);
    tst_ok("PASS --- SUBTEST:  test_pktmbuf_pool\n");

    return 0;

leave:
    tst_error("FAILED --- SUBTEST:  test_pktmbuf_pool\n");
    return -1;
}

/*
 * test that the pointer to the data on a packet pktmbuf is set properly
 */
static int
test_pktmbuf_pool_ptr(void)
{
    unsigned i;
    pktmbuf_t *m[NB_MBUF];
    int ret = 0;

    for (i = 0; i < NB_MBUF; i++)
        m[i] = NULL;

    /* alloc NB_MBUF mbufs */
    cne_printf("\n[blue]>>>[white]SUBTEST: alloc NB_MBUF mbufs\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    for (i = 0; i < NB_MBUF; i++) {
        m[i] = pktmbuf_alloc(pi);
        TST_ASSERT_GOTO(m[i] != NULL, "SUBTEST: alloc NB_MBUF mbufs\n", leave);
        m[i]->data_off += 64;
    }
    tst_ok("PASS ---  SUBTEST: alloc NB_MBUF mbufs\n");
    /* free them */
    for (i = 0; i < NB_MBUF; i++) {
        pktmbuf_free(m[i]);
    }

    for (i = 0; i < NB_MBUF; i++)
        m[i] = NULL;

    /* alloc NB_MBUF mbufs */
    cne_printf("\n[blue]>>>[white]SUBTEST: alloc NB_MBUF mbufs\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    for (i = 0; i < NB_MBUF; i++) {
        m[i] = pktmbuf_alloc(pi);
        TST_ASSERT_GOTO(m[i] != NULL, "SUBTEST: alloc NB_MBUF mbufs\n", leave);
        TST_ASSERT_GOTO(m[i]->data_off == CNE_PKTMBUF_HEADROOM, "SUBTEST: alloc NB_MBUF mbufs\n",
                        leave);
    }
    tst_ok("PASS ---  SUBTEST: alloc NB_MBUF mbufs\n");

leave:
    /* free them */
    for (i = 0; i < NB_MBUF; i++) {
        pktmbuf_free(m[i]);
    }

    return ret;
}

/* use fork() to test pktmbuf errors panic */
static int
verify_mbuf_check_panics(pktmbuf_t *buf)
{
    int pid;
    int status;

    cne_printf("[green]");
    pid = fork();

    if (pid == 0) {
        pktmbuf_sanity_check(buf, 1); /* should panic */
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
        exit(0); /* return normally if it doesn't panic */
    } else if (pid < 0) {
        tst_error("Fork Failed\n");
        goto leave;
    }
    wait(&status);
    if (status == 0)
        goto leave;

    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    return 0;

leave:
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    return -1;
}

static int
test_failing_pktmbuf_sanity_check(void)
{
    pktmbuf_t *buf;
    pktmbuf_t badbuf;

    cne_printf("[blue]>>>[white]SUBTEST: Checking pktmbuf_sanity_check for failure conditions\n");

    /* get a good pktmbuf to use to make copies */
    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_alloc\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    buf = pktmbuf_alloc(pi);
    TST_ASSERT_GOTO(buf, "SUBTEST: pktmbuf_alloc failed\n", leave);
    tst_ok("PASS --- SUBTEST: pktmbuf_alloc\n");

    cne_printf("[magenta]Checking good pktmbuf initially\n");
    cne_printf("\n[blue]>>>[white]SUBTEST: verify_mbuf_check_panics\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(verify_mbuf_check_panics(buf) == -1,
                    "SUBTEST: verify_mbuf_check_panics failed\n", leave);
    tst_ok("PASS --- SUBTEST: verify_mbuf_check_panics\n");

    cne_printf("[magenta]Now checking for error conditions - [green]Note PANICS are GOOD HERE\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    cne_printf("\n[blue]>>>[white]SUBTEST: verify_mbuf_check_panics on NULL\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!verify_mbuf_check_panics(NULL),
                    "SUBTEST: verify_mbuf_check_panics on NULL failed\n", leave);
    tst_ok("PASS --- SUBTEST: verify_mbuf_check_panics on NULL\n");

    badbuf          = *buf;
    badbuf.pooldata = NULL;
    cne_printf("\n[blue]>>>[white]SUBTEST: verify_mbuf_check_panics on badbuf.pool = NULL\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!verify_mbuf_check_panics(&badbuf),
                    "SUBTEST: verify_mbuf_check_panics on badbuf.pool  = NULL failed\n", leave);
    tst_ok("PASS --- SUBTEST: verify_mbuf_check_panics on badbuf.pool  = NULL\n");

    badbuf          = *buf;
    badbuf.buf_addr = 0;
    cne_printf("\n[blue]>>>[white]SUBTEST: verify_mbuf_check_panics on badbuf.buf_addr = 0\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!verify_mbuf_check_panics(&badbuf),
                    "SUBTEST: verify_mbuf_check_panics on badbuf.buf_addr = 0 failed\n", leave);
    tst_ok("PASS --- SUBTEST: verify_mbuf_check_panics on badbuf.buf_addr = 0\n");

    badbuf          = *buf;
    badbuf.buf_addr = NULL;
    cne_printf("\n[blue]>>>[white]SUBTEST: verify_mbuf_check_panics on badbuf.buf_addr = NULL\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!verify_mbuf_check_panics(&badbuf),
                    "SUBTEST: verify_mbuf_check_panics on badbuf.buf_addr = NULL failed\n", leave);
    tst_ok("PASS --- SUBTEST: verify_mbuf_check_panics on badbuf.buf_addr = NULL\n");

    badbuf        = *buf;
    badbuf.refcnt = 0;
    cne_printf("\n[blue]>>>[white]SUBTEST: verify_mbuf_check_panics on badbuf.refcnt = 0\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!verify_mbuf_check_panics(&badbuf),
                    "SUBTEST: verify_mbuf_check_panics on badbuf.refcnt = 0 failed\n", leave);
    tst_ok("PASS --- SUBTEST: verify_mbuf_check_panics on badbuf.refcnt = 0\n");

    badbuf        = *buf;
    badbuf.refcnt = UINT16_MAX;
    cne_printf(
        "\n[blue]>>>[white]SUBTEST: verify_mbuf_check_panics on badbuf.refcnt = UINT16_MAX\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!verify_mbuf_check_panics(&badbuf),
                    "SUBTEST: verify_mbuf_check_panics on badbuf.refcnt = UINT16_MAX failed\n",
                    leave);
    tst_ok("PASS --- SUBTEST: verify_mbuf_check_panics on badbuf.refcnt = UINT16_MAX\n");

    tst_ok("PASS --- SUBTEST:  Checking pktmbuf_sanity_check for failure conditions\n");
    return 0;

leave:
    tst_error("FAILED --- SUBTEST: Checking pktmbuf_sanity_check for failure conditions\n");
    return -1;
}

/*
 * test data manipulation in pktmbuf with non-ascii data
 */
static int
test_pktmbuf_with_non_ascii_data(void)
{
    pktmbuf_t *m = NULL;
    char *data;

    cne_printf("[blue]>>>[white]SUBTEST: test_pktmbuf_with_non_ascii_data\n");

    /* alloc a pktmbuf */
    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_alloc\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    m = pktmbuf_alloc(pi);
    TST_ASSERT_GOTO(m, "SUBTEST: pktmbuf_alloc failed\n", fail);
    tst_ok("PASS --- SUBTEST: pktmbuf_alloc\n");
    TST_ASSERT_GOTO(pktmbuf_data_len(m) == 0, "SUBTEST: pktmbuf_alloc failed\n", fail);

    cne_printf("\n[blue]>>>[white]SUBTEST: pktmbuf_append\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    data = pktmbuf_append(m, MBUF_TEST_DATA_LEN);
    TST_ASSERT_GOTO(data != NULL, "SUBTEST: pktmbuf_append failed\n", fail);
    tst_ok("PASS --- SUBTEST: pktmbuf_append\n");
    TST_ASSERT_GOTO(pktmbuf_data_len(m) == MBUF_TEST_DATA_LEN, "SUBTEST: pktmbuf_alloc failed\n",
                    fail);

    memset(data, 0xff, pktmbuf_data_len(m));
    tst_ok("PASS --- SUBTEST:  test_pktmbuf_with_non_ascii_data\n");

    cne_printf("[magenta]");
    pktmbuf_dump("m", m, MBUF_TEST_DATA_LEN);
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);

    pktmbuf_free(m);

    return 0;

fail:
    tst_error("FAILED --- SUBTEST: test_pktmbuf_with_non_ascii_data\n");
    pktmbuf_free(m);
    return -1;
}

static int
test_mbuf(void)
{
    /* create pktmbuf pool if it does not exist */
    if (pi == NULL) {
        cne_printf("\n[blue]>>>[white]TEST: pktmbuf_pool_create\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
        if (create_pktmbuf())
            goto leave;
        tst_ok("PASS --- TEST: pktmbuf_pool_create\n");
    }

    cne_printf("\n[blue]>>>[white]TEST: test multiple pktmbuf alloc\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!test_pktmbuf_pool(), "TEST: test multiple pktmbuf alloc failed\n", leave);
    tst_ok("PASS --- TEST: test multiple pktmbuf alloc\n");

    /* test that the pointer to the data on a packet pktmbuf is set properly */
    cne_printf("\n[blue]>>>[white]TEST: test_pktmbuf_pool_ptr\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!test_pktmbuf_pool_ptr(), "TEST: test_pktmbuf_pool_ptr failed\n", leave);
    tst_ok("PASS --- TEST: test_pktmbuf_pool_ptr\n");

    /* test data manipulation in pktmbuf */
    cne_printf("\n[blue]>>>[white]TEST: test_one_pktmbuf\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!test_one_pktmbuf(), "TEST: test_one_pktmbuf failed\n", leave);
    tst_ok("PASS --- TEST: test_one_pktmbuf\n");

    cne_printf("\n[blue]>>>[white]TEST: test_pktmbuf_with_non_ascii_data\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!test_pktmbuf_with_non_ascii_data(),
                    "TEST: test_pktmbuf_with_non_ascii_data failed\n", leave);
    tst_ok("PASS --- TEST: test_pktmbuf_with_non_ascii_data\n");

    cne_printf("\n[blue]>>>[white]TEST: test_failing_pktmbuf_sanity_check\n");
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    TST_ASSERT_GOTO(!test_failing_pktmbuf_sanity_check(),
                    "TEST: test_failing_pktmbuf_sanity_check failed\n", leave);
    tst_ok("PASS --- TEST: test_failing_pktmbuf_sanity_check\n");

    return 0;

leave:

    destroy_pktmbuf();
    return -1;
}

int
pkt_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt;
    int option_index;

    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    optind = 0;
    while ((opt = getopt_long(argc, argvopt, "V", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("PKT");

    if (simple_pkt_test())
        goto err;
    if (test_mbuf())
        goto err;

    tst_end(tst, TST_PASSED);
    return 0;
err:
    tst_end(tst, TST_FAILED);
    return -1;
}
