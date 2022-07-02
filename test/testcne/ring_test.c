/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdbool.h>           // for bool
#include <stdio.h>             // for size_t, NULL, snprintf, EOF
#include <stdint.h>            // for uintptr_t, uint64_t
#include <getopt.h>            // for no_argument, getopt_long_only, option
#include <cne_ring.h>          // for CNE_RING_NAMESIZE
#include <tst_info.h>          // for TST_ASSERT_AND_CLEANUP, tst_start, tst_ok
#include <cne_common.h>        // for cne_align32pow2, cne_countof, CNE_SET_USED
#include <stdlib.h>            // for rand
#include <string.h>            // for strlen, strncmp, strnlen, memset
#include <cne_mmap.h>

#include "ring_test.h"
#include "cne_ring_api.h"        // for cne_ring_count, cne_ring_dump, cne_rin...
#include "cne_stdio.h"           // for cne_printf
#include "vt100_out.h"           // for vt_color, VT_NO_CHANGE, VT_OFF, VT_BLUE

#define RING_SIZE 1024

static int verbose        = 0;
static int help           = 0;
static int opt_list_tests = 0;
static int opt_run_all    = 0;

struct ring_test_info {
    tst_info_t *tst;
    struct cne_ring *r;
    mmap_t *mm;
    bool passed;
};

static void
test_ring_cleanup(struct ring_test_info *ring_tst)
{
    if (ring_tst) {
        if (ring_tst->r)
            cne_ring_free(ring_tst->r);
        if (ring_tst->mm) {
            if (mmap_free(ring_tst->mm) < 0)
                CNE_WARN("unable to free mmap\n");
        }

        if (ring_tst->tst)
            tst_end(ring_tst->tst, ring_tst->passed);
    }
}

struct name_test_cfg {
    int expected;  /* expected test result */
    size_t length; /* name length */
};

static int
test_create_ring_name(struct name_test_cfg *cfg)
{
    struct ring_test_info tst = {0};
    char ring_name[256]       = {0};
    size_t i;
    char tst_name[128];
    char ring_name_chars[] = "1234567890";

    TST_ASSERT_NOT_NULL(cfg, "Test arguments null\n");

    snprintf(tst_name, sizeof(tst_name), "Name: len=%zu", cfg->length);
    tst.tst = tst_start(tst_name);
    for (i = 0; i < cfg->length; i++)
        ring_name[i] = ring_name_chars[i % 10];

    tst.r = cne_ring_create(ring_name, 0, 1024, 0);
    if (cfg->expected)
        TST_ASSERT_NOT_NULL_AND_CLEANUP(tst.r, "CNE_RING_NAMESIZE=%d ring_name=(%s)(len=%zu)\n",
                                        test_ring_cleanup, &tst, CNE_RING_NAMESIZE, ring_name,
                                        strnlen(ring_name, CNE_RING_NAMESIZE));
    else
        TST_ASSERT_NULL_AND_CLEANUP(tst.r, "CNE_RING_NAMESIZE=%d ring_name=(%s)(len=%zu)\n",
                                    test_ring_cleanup, &tst, CNE_RING_NAMESIZE, ring_name,
                                    strnlen(ring_name, CNE_RING_NAMESIZE));
    if (tst.r)
        tst_ok("CNE_RING_NAMESIZE=%d ring_name=(%s)(len=%zu) r=%p->(name=%s)(len=%zu)\n",
               CNE_RING_NAMESIZE, ring_name, strlen(ring_name), tst.r, cne_ring_get_name(tst.r),
               strlen(cne_ring_get_name(tst.r)));
    else
        tst_ok("CNE_RING_NAMESIZE=%d ring_name=(%s)(len=%zu)\n", CNE_RING_NAMESIZE, ring_name,
               strlen(ring_name));

    tst.passed = TST_PASSED;
    test_ring_cleanup(&tst);

    return 0;
}

static int
ring_name_tests(void *args)
{
    size_t i                     = 0;
    struct name_test_cfg tests[] = {{1, 0},
                                    {1, 1},
                                    {1, CNE_RING_NAMESIZE - 1},
                                    {0, CNE_RING_NAMESIZE},
                                    {0, CNE_RING_NAMESIZE + 1}};

    CNE_SET_USED(args);

    for (i = 0; i < cne_countof(tests); i++) {
        struct name_test_cfg *tst = &tests[i];

        TST_ASSERT_SUCCESS(test_create_ring_name(tst), "Ring name size=%zu\n", tst->length);
    }
    return 0;
}

static int
test_ring_init(void *args)
{
    unsigned int ring_size, i;
    struct ring_test_info tst = {0};
    ssize_t tsize;
    uint32_t bufcnt, bufsz;
    size_t sz;

    CNE_SET_USED(args);

    tst.tst   = tst_start("Ring init API");
    ring_size = cne_align32pow2(rand() % 16384);
    tst_ok("Using ring_size=%u\n", ring_size);

    tsize = cne_ring_get_memsize_elem(0, ring_size);
    TST_ASSERT_AND_CLEANUP(tsize > 0, "Ring memsize < 0\n", test_ring_cleanup, &tst);

    tst.mm = mmap_alloc((tsize / CNE_CACHE_LINE_SIZE), CNE_CACHE_LINE_SIZE, MMAP_HUGEPAGE_4KB);
    TST_ASSERT_AND_CLEANUP(tst.mm != NULL, "Out of memory\n", test_ring_cleanup, &tst);

    sz = mmap_size(tst.mm, &bufcnt, &bufsz);
    CNE_INFO("tsize: %zd, mmap size %zd, bufcnt %u, bufsz %u\n", tsize, sz, bufcnt, bufsz);

    TST_ASSERT_AND_CLEANUP(sz >= ring_size, "mmap size too small\n", test_ring_cleanup, &tst);

    tst.r = cne_ring_init(mmap_addr(tst.mm), 0, "ring init", 8, ring_size, 0);
    TST_ASSERT_AND_CLEANUP(tst.r == NULL, "Ring invalid size should have failed\n",
                           test_ring_cleanup, &tst);

    tst.r = cne_ring_init(mmap_addr(tst.mm), sz - (4 * RING_SIZE), "ring init", 8, ring_size, 0);
    TST_ASSERT_AND_CLEANUP(tst.r == NULL, "Ring invalid size should have failed\n",
                           test_ring_cleanup, &tst);

    /* Make address non-cacheline aligned */
    tst.r = cne_ring_init(CNE_PTR_ADD(mmap_addr(tst.mm), 1), 0, "ring init", 8, ring_size, 0);
    TST_ASSERT_AND_CLEANUP(tst.r == NULL, "Ring invalid address should have failed\n",
                           test_ring_cleanup, &tst);

    tst.r = cne_ring_init(mmap_addr(tst.mm), sz, "ring init", 8, ring_size, 0);
    TST_ASSERT_AND_CLEANUP(tst.r != NULL, "Ring create failed\n", test_ring_cleanup, &tst);

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, tst.r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }

    TST_ASSERT_AND_CLEANUP(1 == cne_ring_empty(tst.r), "Ring empty expected\n", test_ring_cleanup,
                           &tst);
    TST_ASSERT_AND_CLEANUP(0 == cne_ring_full(tst.r), "Ring full unexpected\n", test_ring_cleanup,
                           &tst);
    TST_ASSERT_AND_CLEANUP(ring_size == cne_ring_get_size(tst.r),
                           "ring size=%u expected instead of %u\n", test_ring_cleanup, &tst,
                           ring_size - 1, cne_ring_get_size(tst.r));

    for (i = 0; i < ring_size / 2; i++)
        TST_ASSERT_AND_CLEANUP(0 == cne_ring_enqueue(tst.r, (void *)((uintptr_t)i + 1)),
                               "Enqueue i=%u", test_ring_cleanup, &tst, i + 1);

    TST_ASSERT_AND_CLEANUP(i == cne_ring_count(tst.r),
                           "Ring count=%u mismatch with enqueued=%u elements\n", test_ring_cleanup,
                           &tst, cne_ring_count(tst.r), i);
    TST_ASSERT_AND_CLEANUP(ring_size - i - 1 == cne_ring_free_count(tst.r),
                           "Ring free count=%u mismatch with expected=%u elements\n",
                           test_ring_cleanup, &tst, cne_ring_free_count(tst.r), ring_size - i - 1);
    cne_ring_reset(tst.r);
    TST_ASSERT_AND_CLEANUP(0 == cne_ring_count(tst.r),
                           "Ring count=%u mismatch with expected=%u elements\n", test_ring_cleanup,
                           &tst, cne_ring_count(tst.r), 0);
    TST_ASSERT_AND_CLEANUP(ring_size - 1 == cne_ring_free_count(tst.r),
                           "Ring free count=%u mismatch with expected=%u elements\n",
                           test_ring_cleanup, &tst, cne_ring_free_count(tst.r), ring_size - 1);

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, tst.r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }

    tst.passed = TST_PASSED;
    test_ring_cleanup(&tst);

    return 0;
}

/*--------- Ring reset tests -----------------*/
static int
test_ring_reset_tests(void *args)
{
    unsigned int ring_size, i;
    struct ring_test_info tst = {0};

    CNE_SET_USED(args);

    tst.tst   = tst_start("Ring reset");
    ring_size = cne_align32pow2(rand() % 16384);
    tst_ok("Using ring_size=%zu\n", ring_size);
    tst.r = cne_ring_create("ring reset", 8, ring_size, 0);

    TST_ASSERT_AND_CLEANUP(tst.r != NULL, "Ring create failed\n", test_ring_cleanup, &tst);

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, tst.r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }

    TST_ASSERT_AND_CLEANUP(1 == cne_ring_empty(tst.r), "Ring empty expected\n", test_ring_cleanup,
                           &tst);
    TST_ASSERT_AND_CLEANUP(0 == cne_ring_full(tst.r), "Ring full unexpected\n", test_ring_cleanup,
                           &tst);
    TST_ASSERT_AND_CLEANUP(ring_size == cne_ring_get_size(tst.r),
                           "ring size=%u expected instead of %u\n", test_ring_cleanup, &tst,
                           ring_size - 1, cne_ring_get_size(tst.r));

    for (i = 0; i < ring_size / 2; i++)
        TST_ASSERT_AND_CLEANUP(0 == cne_ring_enqueue(tst.r, (void *)((uintptr_t)i + 1)),
                               "Enqueue i=%u", test_ring_cleanup, &tst, i + 1);

    TST_ASSERT_AND_CLEANUP(i == cne_ring_count(tst.r),
                           "Ring count=%u mismatch with enqueued=%u elements\n", test_ring_cleanup,
                           &tst, cne_ring_count(tst.r), i);
    TST_ASSERT_AND_CLEANUP(ring_size - i - 1 == cne_ring_free_count(tst.r),
                           "Ring free count=%d mismatch with expected=%d elements\n",
                           test_ring_cleanup, &tst, cne_ring_free_count(tst.r), ring_size - i - 1);
    cne_ring_reset(tst.r);
    TST_ASSERT_AND_CLEANUP(0 == cne_ring_count(tst.r),
                           "Ring count=%u mismatch with expected=%u elements\n", test_ring_cleanup,
                           &tst, cne_ring_count(tst.r), 0);
    TST_ASSERT_AND_CLEANUP(ring_size - 1 == cne_ring_free_count(tst.r),
                           "Ring free count=%u mismatch with expected=%u elements\n",
                           test_ring_cleanup, &tst, cne_ring_free_count(tst.r), ring_size - 1);

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, tst.r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }

    if (tst.r)
        cne_ring_free(tst.r);
    tst_end(tst.tst, TST_PASSED);

    return 0;
}

static int
test_ring_fill_tests(void *args)
{
    unsigned int ring_size    = RING_SIZE;
    struct ring_test_info tst = {0};
    ring_size                 = cne_align32pow2(rand() % 16384);
    unsigned i;

    CNE_SET_USED(args);

    tst.tst   = tst_start("Ring fill");
    ring_size = cne_align32pow2(rand() % 16384);
    tst_ok("Using ring_size=%zu\n", ring_size);
    tst.r = cne_ring_create("ring reset", 8, ring_size, 0);
    TST_ASSERT_NOT_NULL_AND_CLEANUP(tst.r, "Ring create failed\n", test_ring_cleanup, &tst);

    for (i = 0; i < ring_size - 1; i++)
        TST_ASSERT_AND_CLEANUP(0 == cne_ring_enqueue(tst.r, (void *)((uintptr_t)i + 1)),
                               "enqueue failed i=%u\n", test_ring_cleanup, &tst, i);

    TST_ASSERT_AND_CLEANUP(i == cne_ring_count(tst.r),
                           "Ring count=%u mismatch with enqueued=%u elements\n", test_ring_cleanup,
                           &tst, cne_ring_count(tst.r), i);
    TST_ASSERT_AND_CLEANUP(1 == cne_ring_full(tst.r), "Ring full expected \n", test_ring_cleanup,
                           &tst);

    tst.passed = TST_PASSED;
    test_ring_cleanup(&tst);
    return 0;
}

static int
test_ring_enqueue_dequeue(void *arg)
{
    struct ring_test_info tst = {0};
    unsigned int i            = 0;
    uint64_t val;

    CNE_SET_USED(arg);

    tst.tst = tst_start("Ring");
    tst.r   = cne_ring_create("ring", 0, RING_SIZE, 0);
    TST_ASSERT_AND_CLEANUP(tst.r != NULL, "Ring create failed\n", test_ring_cleanup, &tst);

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, tst.r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }
    for (i = 0; i < RING_SIZE / 2; i++)
        TST_ASSERT_AND_CLEANUP(0 == cne_ring_enqueue(tst.r, (void *)((uintptr_t)i + 1)),
                               "Enqueue failed i=%u\n", test_ring_cleanup, &tst, i + 1);

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, tst.r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }

    val = 0;
    for (i = 0; i < RING_SIZE / 2; i++) {
        TST_ASSERT_AND_CLEANUP(0 == cne_ring_dequeue(tst.r, (void *)&val), "Dequeue failed i=%d\n",
                               test_ring_cleanup, &tst, i);
        TST_ASSERT_AND_CLEANUP(val == (uint64_t)i + 1, "Ring Dequeue failed val=%lu expected=%u\n",
                               test_ring_cleanup, &tst, val, i + 1);
    }

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, tst.r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }

    tst.passed = TST_PASSED;
    test_ring_cleanup(&tst);
    return 0;
}

static int
test_ring_fill_object_range(uintptr_t *obj, size_t obj_sz, int start)
{
    size_t i = 0;
    for (i = 0; i < obj_sz; i++) {
        obj[i] = (uintptr_t)(start + i);
    }
    return i;
}

static int
test_ring_check_object_range(uintptr_t *obj, size_t obj_sz, int start)
{
    size_t i = 0;
    for (i = 0; i < obj_sz; i++) {
        if (obj[i] != (uintptr_t)(start + i))
            break;
    }
    return i;
}

static int
test_ring_burst(void *arg)
{
    int result                = -1;
    struct ring_test_info tst = {0};
    size_t burst_size         = 50;
    size_t iterations         = cne_align32pow2(1000000);
    uint64_t deq_i            = 0;
    uintptr_t enq_obj[1024], deq_obj[1024];
    size_t enq_cnt, deq_cnt;
    unsigned int free_space;

    CNE_SET_USED(arg);

    tst.tst = tst_start("Ring burst");

    tst.r = cne_ring_create("ring burst", 0, RING_SIZE, 0);
    TST_ASSERT_AND_CLEANUP(tst.r != NULL, "Ring create failed\n", test_ring_cleanup, &tst);

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, tst.r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }
    for (uintptr_t enq_i = 0; enq_i < iterations; enq_i += enq_cnt) {
        enq_cnt = test_ring_fill_object_range(enq_obj, burst_size, enq_i);
        TST_ASSERT_AND_CLEANUP(
            enq_cnt == cne_ring_enqueue_burst(tst.r, (void **)enq_obj, enq_cnt, &free_space),
            "Enqueue failed i=%lu\n", test_ring_cleanup, &tst, enq_i);
        if (free_space <= burst_size) {
            memset(deq_obj, 0, sizeof(deq_obj));
            for (; deq_i < enq_i; deq_i += deq_cnt) {
                size_t valid_cnt;

                deq_cnt = cne_ring_dequeue_burst(tst.r, (void **)deq_obj, burst_size, &free_space);
                TST_ASSERT_AND_CLEANUP(deq_cnt == burst_size,
                                       "Dequeue failed i=%lu deq_cnt=%zu burst_size=%zu\n",
                                       test_ring_cleanup, &tst, deq_i, deq_cnt, burst_size);
                valid_cnt = test_ring_check_object_range(deq_obj, burst_size, deq_i);
                TST_ASSERT_AND_CLEANUP(burst_size == valid_cnt,
                                       "Ring Dequeue failed burst_size=%zu valid_cnt=%zu enq_i=%lu "
                                       "deq_i=%lu enq_cnt=%lu deq_cnt=%lu\n",
                                       test_ring_cleanup, &tst, burst_size, valid_cnt, enq_i, deq_i,
                                       enq_cnt, deq_cnt);
            }
        }
    }

    tst.passed = TST_PASSED;
    test_ring_cleanup(&tst);

    return result;
}

typedef int (*ring_test_fn)(void *arg);

struct test_info {
    char name[128]; /*< test name */
    ring_test_fn fn;
    void *args;
    int result;
    int run;
};

static struct test_info *
find_test_by_name(struct test_info *tests, size_t tests_n, char *name)
{
    size_t tst_idx        = 0;
    struct test_info *tst = NULL;

    if (!tests)
        return NULL;
    if (!name)
        return NULL;

    for (tst_idx = 0; tst_idx < tests_n; tst_idx++) {
        if (tests[tst_idx].name[0] == '\0')
            continue;
        if (!strncmp(tests[tst_idx].name, name, sizeof(tst[tst_idx].name))) {
            if (tests[tst_idx].fn) {
                tst = &tests[tst_idx];
                break;
            }
        }
    }
    return tst;
}

int
ring_main(int argc, char **argv)
{
    int opt;
    char **argvopt;
    int option_index;
    int idx;
    int result     = 0;
    size_t tst_idx = 0;
    // clang-format off
    struct test_info tests[] = {
        {"init", test_ring_init},
        {"name", ring_name_tests},
        {"fill", test_ring_fill_tests},
        {"reset", test_ring_reset_tests},
        {"burst", test_ring_burst},
        {"basic", test_ring_enqueue_dequeue},
    };
    static const struct option lgopts[] = {
        {"verbose", no_argument, &verbose, 1},
        {"list", no_argument, &opt_list_tests, 1},
        {"help", no_argument, &help, 1},
        {"all", no_argument, &opt_run_all, 1},
        {NULL, 0, 0, 0}
    };
    // clang-format on

    verbose        = 0;
    help           = 0;
    opt_list_tests = 0;
    opt_run_all    = 0;

    argvopt = argv;

    optind = 0;
    opterr = 0;
    while ((opt = getopt_long_only(argc, argvopt, "Vlha", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'h':
            help = 1;
            break;
        case 'l':
            opt_list_tests = 1;
            break;
        case 'a':
            opt_run_all = 1;
            break;
        case 'V':
            verbose = 1;
            break;
        case ':':
            cne_printf("Option %c requires an argument\n", optopt);
            break;
        case '?':
            cne_printf("Unknown option -%c\n", optopt);
            break;
        default:
            break;
        }
    }

    cne_printf("option_index=%d argc=%d opt_run_all=%d verbose=%d\n", option_index, argc,
               opt_run_all, verbose);
    if (opt_list_tests) {
        cne_printf("listing available tests:");
        for (size_t tst_idx = 0; tst_idx < cne_countof(tests); tst_idx++)
            cne_printf("%s\n", tests[tst_idx].name);
    }

    /* search for all option */
    if (optind == argc)
        opt_run_all = 1;
    else
        for (idx = optind; idx < argc; idx++) {
            if (!strncmp(argv[idx], "all", strlen(argv[idx]))) {
                cne_printf("Option %d -> %s\n", idx, argv[idx]);
                opt_run_all = 1;
            }
        }

    cne_printf("option_index=%d argc=%d opt_run_all=%d verbose=%d\n", option_index, argc,
               opt_run_all, verbose);
    if (option_index == argc || opt_run_all) {
        cne_printf("Running all test\n");
        for (tst_idx = 0; tst_idx < cne_countof(tests); tst_idx++) {
            if (tests[tst_idx].fn) {
                tests[tst_idx].run    = 1;
                tests[tst_idx].result = tests[tst_idx].fn(tests[tst_idx].args);
            }
        }
    } else {
        for (option_index = optind; option_index < argc; option_index++) {
            cne_printf("Running test %s\n", argv[option_index]);
            struct test_info *tst =
                find_test_by_name(tests, cne_countof(tests), argv[option_index]);
            if (tst) {
                tst->run    = 1;
                tst->result = tst->fn(tst->args);
            } else {
                cne_printf("No test named '%s' found\n", argv[option_index]);
            }
        }
    }

    for (tst_idx = 0; tst_idx < cne_countof(tests); tst_idx++) {
        if (tests[tst_idx].run && tests[tst_idx].result) {
            result = tests[tst_idx].result;
            break;
        }
    }

    return result;
}
