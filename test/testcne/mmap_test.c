/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, size_t, EOF
#include <getopt.h>            // for getopt_long, option
#include <cne_mmap.h>          // for MMAP_HUGEPAGE_4KB, MMAP_HUGEPAGE_2MB
#include <tst_info.h>          // for tst_error, tst_end, tst_start, TST_FAILED
#include <unistd.h>            // for getpagesize
#include <cne_common.h>        // for CNE_SET_USED, cne_countof
#include <cne_log.h>           // for CNE_ERR, CNE_LOG_ERR

#include "mmap_test.h"
#include "cne_stdio.h"        // for cne_printf

typedef struct {
    mmap_type_t type;
    size_t requested;
    size_t expected;
    int err_type;
    mmap_t *mmap;
} mmaps_t;

enum { OK = 0, ERR };

#define _2MB (2L * 1024L * 1024L)
#define _1GB (1024L * 1024L * 1024L)

int
mmap_main(int argc, char **argv)
{
    int i, pg_sz = getpagesize();
    tst_info_t *tst;
    // clang-format off
    mmaps_t mmaps[] = {
        { MMAP_HUGEPAGE_4KB,            1, pg_sz,  OK },
        { MMAP_HUGEPAGE_4KB,           16, pg_sz,  OK },
        { MMAP_HUGEPAGE_4KB,         1024, pg_sz,  OK },
        { MMAP_HUGEPAGE_4KB,         2048, pg_sz,  OK },
        { MMAP_HUGEPAGE_4KB,   (4 * 1024), pg_sz,  OK },
        { MMAP_HUGEPAGE_4KB,   (7 * 1024), pg_sz * 2,  OK },
        { MMAP_HUGEPAGE_4KB,   (7 * 1024), pg_sz * 2,  OK },
        { MMAP_HUGEPAGE_2MB,            1, _2MB, OK },
        { MMAP_HUGEPAGE_2MB,        pg_sz, _2MB, OK },
        { MMAP_HUGEPAGE_2MB,         _2MB, _2MB, OK },
        { MMAP_HUGEPAGE_2MB,       _2MB+1, _2MB * 2, OK },
        { MMAP_HUGEPAGE_1GB,            1, _1GB, OK },
        { MMAP_HUGEPAGE_1GB,        pg_sz, _1GB, OK },
        { MMAP_HUGEPAGE_1GB,       _1GB+1, _1GB * 2, OK },
        { MMAP_HUGEPAGE_4KB,           1, pg_sz, ERR },
        { 0 }
    };
    // clang-format on
    int verbose  = 0, opt;
    mmap_t *mmap = NULL;
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

    tst = tst_start("MMAP");

    for (i = 0; i < cne_countof(mmaps); i++) {
        if (mmaps[i].requested == 0)
            break;
        mmaps_t *ms = &mmaps[i];
        ms->mmap    = mmap_alloc(1, ms->requested, ms->type);
        if (!ms->mmap) {
            if (ms->err_type == OK) {
                tst_error("mmap_alloc() failed for size %ld, type %d\n", ms->requested, ms->type);
                goto err;
            }
            continue;
        }
        if (mmap_free(ms->mmap)) {
            tst_error("%2d: mmap_free() failed\n", i);
            goto err;
        }
        ms->mmap = NULL;
    }

    cne_printf("\n[blue]>>>[white]TEST: API Test for mmap_type_by_name\n[]");
    const char *type_name[] = {"default", "4KB", "2MB", "1GB"};
    // clang-format off
    mmap_type_t exp_type[] = {
        MMAP_HUGEPAGE_4KB,
        MMAP_HUGEPAGE_4KB,
        MMAP_HUGEPAGE_2MB,
        MMAP_HUGEPAGE_1GB
    };
    // clang-format on
    for (i = 0; i < cne_countof(type_name); i++) {
        if (mmap_type_by_name(type_name[i]) != exp_type[i]) {
            tst_error("mmap type set failed for size %s\n", type_name[i]);
            goto err;
        }
    }

    cne_printf("\n[blue]>>>[white]TEST: API Test for mmap_size\n[]");
    mmap_type_t type[]   = {MMAP_HUGEPAGE_4KB, MMAP_HUGEPAGE_2MB, MMAP_HUGEPAGE_1GB};
    size_t expect_size[] = {4096, 2 * 1024 * 1024, 1024 * 1024 * 1024};
    for (i = 0; i < cne_countof(type); i++) {
        mmap = mmap_alloc(1, expect_size[i], type[i]);
        if (!mmap) {
            tst_error("mmap_alloc() failed\n");
            goto err;
        }
        if (mmap_size(mmap, NULL, NULL) != expect_size[i]) {
            tst_error("the mmap size isn't correct\n");
            goto err;
        }
        if (mmap_free(mmap)) {
            tst_error("mmap_free() failed\n");
            goto err;
        }
        mmap = NULL;
    }

    cne_printf("\n[blue]>>>[white]TEST: API Test for mmap_addr_at_offset\n[]");
    mmap = mmap_alloc(1, 1, MMAP_HUGEPAGE_4KB);
    char *addr, *addr_offset;
    addr        = mmap_addr(mmap);
    addr_offset = mmap_addr_at_offset(mmap, 0);
    if (addr != addr_offset) {
        tst_error("the address got by offset 0 is error\n");
        goto err;
    }
    addr_offset = mmap_addr_at_offset(mmap, 4096);
    if (addr != (addr_offset - 4096)) {
        tst_error("the address got by offset 4K is error\n");
        goto err;
    }
    addr_offset = mmap_addr_at_offset(mmap, 4097);
    if (addr_offset != NULL) {
        tst_error("the address is out of mmap range\n");
        goto err;
    }

    if (mmap_free(mmap)) {
        tst_error("%2d: mmap_free() failed\n", i);
        goto err;
    }
    mmap = NULL;

    cne_printf("\n[blue]>>>[white]TEST: API Test for mmap_default_type\n[]");
    for (i = 0; i < cne_countof(type); i++) {
        mmap_set_default_by_name(type_name[i]);
        if (mmap_type_by_name("default") != mmap_type_by_name(type_name[i])) {
            tst_error("mmap default type setting failed\n");
            goto err;
        }
    }

    tst_end(tst, TST_PASSED);

    return 0;
err:
    if (mmap)
        if (mmap_free(mmap))
            CNE_ERR("mmap_free() failed\n");
    for (i = 0; i < cne_countof(mmaps); i++) {
        mmap = mmaps[i].mmap;
        if (mmap)
            if (mmap_free(mmap))
                CNE_ERR("mmap_free() failed\n");
    }

    tst_end(tst, TST_FAILED);
    return -1;
}
