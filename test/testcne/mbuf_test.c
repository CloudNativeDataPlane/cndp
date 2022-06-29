/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, snprintf, EOF
#include <stdlib.h>            // for random
#include <getopt.h>            // for getopt_long, option
#include <pktmbuf.h>           // for pktmbuf_t, pktmbuf_alloc_bulk, pktmbuf...
#include <tst_info.h>          // for tst_end, tst_ok, TST_ASSERT_GOTO, tst_...
#include <cne_common.h>        // for CNE_USED, cne_countof
#include <stdint.h>            // for uint32_t

#include "mbuf_test.h"
#include "mempool.h"         // for mempool_cfg
#include "cne_mmap.h"        // for mmap_free, mmap_addr, mmap_alloc, MMAP...

typedef struct {
    int id;
    int expected;
    struct mempool_cfg cinfo;
    unsigned cache_size;
    unsigned alloc_size;
    pktmbuf_info_t *pi;
} mbuf_info_t;

static char err_msg[512];

static int
iterate_cb(pktmbuf_info_t *pi, pktmbuf_t *m, uint32_t sz, uint32_t idx, void *ud)
{
    CNE_SET_USED(sz);
    CNE_SET_USED(ud);
    CNE_SET_USED(idx);

    if (!m || !pi) {
        snprintf(err_msg, sizeof(err_msg), "mbuf pointer or pktmbuf_info_t is NULL\n");
        return -1;
    }
    if (m->pooldata == NULL) {
        snprintf(err_msg, sizeof(err_msg), "mbuf pointer pooldata invalid\n");
        return -1;
    }

    return 0;
}

int
mbuf_main(int argc, char **argv)
{
    // clang-format off
    mbuf_info_t *t, tsts[] = {
        {100, 0, {.objcnt = 1024, .objsz = 8, .cache_sz = 0}, 128, 64},
        {101, 0, {.objcnt = 1024, .objsz = 32, .cache_sz = 0}, 128, 64},
        {110, 1, {.objcnt = 1024, .objsz = 64, .cache_sz = 0}, 128, 64},
        {111, 1, {.objcnt = 1024, .objsz = 128, .cache_sz = 0}, 128, 64},
        {120, 0, {.objcnt = 1024, .objsz = 9, .cache_sz = 0}, 128, 64},
        {130, 1, {.objcnt = 4096, .objsz = 2176, .cache_sz = 64}, 256, 128},
        {131, 1, {.objcnt = 4096, .objsz = 2048, .cache_sz = 64}, 256, 128},
        {132, 1, {.objcnt = 2048, .objsz = 8192, .cache_sz = 92}, 256, 32},
        {133, 1, {.objcnt = 2048, .objsz = 8192, .cache_sz = 92}, 256, 32},
        {134, 1, {.objcnt = 2048, .objsz = 8192, .cache_sz = 92}, 256, 32},
        {135, 1, {.objcnt = 2048, .objsz = 8192, .cache_sz = 92}, 256, 32},
        {140, 0, {.objcnt = 4096, .objsz = 2000, .cache_sz = 64}, 256, 128},
        {141, 0, {.objcnt = 4096, .objsz = 2144, .cache_sz = 128}, 32, 128},
        {142, 0, {.objcnt = 4096, .objsz = 2144, .cache_sz = 128}, 64, 128},
        {143, 0, {.objcnt = 4096, .objsz = 2144, .cache_sz = 128}, 128, 128},
        {144, 0, {.objcnt = 4096, .objsz = 2144, .cache_sz = 128}, 256, 128},
        {145, 0, {.objcnt = 4096, .objsz = 2144, .cache_sz = 128}, 512, 128},
        {146, 0, {.objcnt = 4096, .objsz = 1500, .cache_sz = 128}, 512, 128},
        {147, 0, {.objcnt = 2048, .objsz = 1500, .cache_sz = 0}, 256, 32},
        {148, 0, {.objcnt = 2048, .objsz = 1000, .cache_sz = 64}, 256, 32},
        {149, 0, {.objcnt = 2048, .objsz = 1000, .cache_sz = 64}, 256, 128},
        {150, 0, {.objcnt = 2048, .objsz = 1000, .cache_sz = 92}, 256, 128},
        {151, 0, {.objcnt = 2048, .objsz = 1000, .cache_sz = 128}, 256, 128},
        {152, 0, {.objcnt = 2048, .objsz = 2000, .cache_sz = 128}, 256, 128},
        {153, 0, {.objcnt = 2048, .objsz = 6000, .cache_sz = 128}, 256, 128},
        {160, 1, {.objcnt = 2048, .objsz = 6016, .cache_sz = 128}, 256, 128},
    };
    // clang-format on
    tst_info_t *tst;
    pktmbuf_t *mbs[256];
    int i, j, ret;
    long int nb;
    int verbose = 0, opt;
    char **argvopt;
    int option_index;
    struct mempool_cfg *ci;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};
    mmap_t *mm;

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

    tst = tst_start("PKTMBUF pool create");

    if (verbose)
        tst_ok("MBUF Size %ld\n", sizeof(pktmbuf_t));

    for (i = 0; i < cne_countof(tsts); i++) {
        t  = &tsts[i];
        ci = &t->cinfo;

        tst_ok("%2d: count %6d, size %6d, cache_size %4d", t->id, ci->objcnt, ci->objsz,
               ci->cache_sz);

        mm = mmap_alloc(ci->objcnt, ci->objsz, MMAP_HUGEPAGE_DEFAULT);
        TST_ASSERT_GOTO(mm != NULL, "unable to allocate memory", err);

        t->pi = pktmbuf_pool_create(mmap_addr(mm), ci->objcnt, ci->objsz, ci->cache_sz, NULL);
        if (t->expected) {
            if (t->pi) {
                TST_ASSERT_GOTO(t->pi != NULL, "unable to create pktmbufs", err);

                err_msg[0] = '\0';
                pktmbuf_iterate(t->pi, iterate_cb, t);

                for (j = 0; j < 16; j++) {
                    nb = random() % t->alloc_size;
                    if (nb == 0)
                        nb = 1;
                    ret = pktmbuf_alloc_bulk(t->pi, mbs, nb);
                    TST_ASSERT_GOTO(ret > 0, "bulk allocate of %ld entries: Pool Empty", err, nb);

                    pktmbuf_free_bulk(mbs, nb);
                }

                pktmbuf_destroy(t->pi);
            } else
                TST_ASSERT_GOTO(t->pi != NULL, "pktmbuf pool expected, but NULL", err);
        } else
            TST_ASSERT_GOTO(t->pi == NULL, "pktmbuf pool not expected, but not NULL", err);
        mmap_free(mm);
    }
    cne_printf("\n");
    tst_end(tst, TST_PASSED);

    tst = tst_start("PKTMBUF pool cfg create");

    for (i = 0; i < cne_countof(tsts); i++) {
        pktmbuf_pool_cfg_t cfg = {0};

        t  = &tsts[i];
        ci = &t->cinfo;

        tst_ok("%2d: count %6d, size %6d, cache_size %4d", t->id, ci->objcnt, ci->objsz,
               ci->cache_sz);

        mm = mmap_alloc(ci->objcnt, ci->objsz, MMAP_HUGEPAGE_DEFAULT);
        TST_ASSERT_GOTO(mm != NULL, "unable to allocate memory", err);

        pktmbuf_pool_cfg(&cfg, mmap_addr(mm), ci->objcnt, ci->objsz, ci->cache_sz, NULL, 0, NULL);

        t->pi = pktmbuf_pool_cfg_create(&cfg);
        if (t->expected) {
            if (t->pi) {
                TST_ASSERT_GOTO(t->pi != NULL, "unable to create pktmbufs", err);

                err_msg[0] = '\0';
                pktmbuf_iterate(t->pi, iterate_cb, t);

                for (j = 0; j < 16; j++) {
                    nb = random() % t->alloc_size;
                    if (nb == 0)
                        nb = 1;
                    ret = pktmbuf_alloc_bulk(t->pi, mbs, nb);
                    TST_ASSERT_GOTO(ret > 0, "bulk allocate of %ld entries: Pool Empty", err, nb);

                    pktmbuf_free_bulk(mbs, nb);
                }

                pktmbuf_destroy(t->pi);
            } else
                TST_ASSERT_GOTO(t->pi != NULL, "pktmbuf pool expected, but NULL", err);
        } else
            TST_ASSERT_GOTO(t->pi == NULL, "pktmbuf pool not expected, but not NULL", err);
        mmap_free(mm);
    }
    cne_printf("\n");
    tst_end(tst, TST_PASSED);
    return 0;

err:
    mmap_free(mm);
    tst_end(tst, TST_FAILED);
    return -1;
}
