/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2023 Intel Corporation
 */

#include <stdio.h>               // for NULL, EOF
#include <stdint.h>              // for int32_t, uint64_t, uint8_t, uint32_t
#include <getopt.h>              // for getopt_long, option
#include <cne_log.h>             // for CNE_LOG_ERR
#include <cne_rib6.h>            // for get_msk_part
#include <private_fib6.h>        // for CNE_FIB6_MAXDEPTH, IPV6_ADDR_LEN
#include <cne_fib6.h>            // for cne_fib6_create, cne_fib6_conf, cne_fib6_free
#include <tst_info.h>            // for tst_end, tst_start, TST_FAILED, TST_PASSED

#include "test.h"            // for TEST_SUCCESS, TEST_CASE, unit_test_suite_r...
#include "fib_test.h"        // for fib6_main
#include "cne_test.h"        // for CNE_TEST_ASSERT

struct cne_fib6;

typedef int32_t (*cne_fib6_test)(void);

static int32_t test_create_invalid(void);
static int32_t test_multiple_create(void);
static int32_t test_free_null(void);
static int32_t test_add_del_invalid(void);
static int32_t test_get_invalid(void);
static int32_t test_lookup(void);

#define MAX_ROUTES (1 << 16)
/** Maximum number of tbl8 for 2-byte entries */
#define MAX_TBL8 (1 << 15)

/*
 * Check that cne_fib6_create fails gracefully for incorrect user input
 * arguments
 */
int32_t
test_create_invalid(void)
{
    struct cne_fib6 *fib = NULL;
    struct cne_fib_conf config;

    config.max_routes = MAX_ROUTES;
    config.default_nh = 0;
    config.type       = CNE_FIB_DUMMY;

    /* cne_fib6_create: fib name == NULL */
    fib = cne_fib6_create(NULL, &config);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");

    /* cne_fib6_create: config == NULL */
    fib = cne_fib6_create(__func__, NULL);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");

    /* cne_fib6_create: max_routes = 0 */
    config.max_routes = 0;
    fib               = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");
    config.max_routes = MAX_ROUTES;

    config.type = CNE_FIB_TRIE + 1;
    fib         = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");

    config.type          = CNE_FIB_TRIE;
    config.trie.num_tbl8 = MAX_TBL8;

    config.trie.nh_sz = CNE_FIB_TRIE_8B + 1;
    fib               = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");
    config.trie.nh_sz = CNE_FIB_TRIE_8B;

    config.trie.num_tbl8 = 0;
    fib                  = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");

    return TEST_SUCCESS;
}

/*
 * Create fib table then delete fib table 10 times
 * Use a slightly different rules size each time
 */
int32_t
test_multiple_create(void)
{
    struct cne_fib6 *fib = NULL;
    struct cne_fib_conf config;
    int32_t i;

    config.default_nh = 0;
    config.type       = CNE_FIB_DUMMY;

    for (i = 0; i < 100; i++) {
        config.max_routes = MAX_ROUTES - i;
        fib               = cne_fib6_create(__func__, &config);
        CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
        cne_fib6_free(fib);
    }
    /* Can not test free so return success */
    return TEST_SUCCESS;
}

/*
 * Call cne_fib6_free for NULL pointer user input. Note: free has no return and
 * therefore it is impossible to check for failure but this test is added to
 * increase function coverage metrics and to validate that freeing null does
 * not crash.
 */
int32_t
test_free_null(void)
{
    struct cne_fib6 *fib = NULL;
    struct cne_fib_conf config;

    config.max_routes = MAX_ROUTES;
    config.default_nh = 0;
    config.type       = CNE_FIB_DUMMY;

    fib = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

    cne_fib6_free(fib);
    cne_fib6_free(NULL);

    return TEST_SUCCESS;
}

/*
 * Check that cne_fib6_add and cne_fib6_delete fails gracefully
 * for incorrect user input arguments
 */
int32_t
test_add_del_invalid(void)
{
    struct cne_fib6 *fib = NULL;
    struct cne_fib_conf config;
    uint64_t nh               = 100;
    uint8_t ip[IPV6_ADDR_LEN] = {0};
    int ret;
    uint8_t depth = 24;

    config.max_routes = MAX_ROUTES;
    config.default_nh = 0;
    config.type       = CNE_FIB_DUMMY;

    /* cne_fib6_add: fib == NULL */
    ret = cne_fib6_add(NULL, ip, depth, nh);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /* cne_fib6_delete: fib == NULL */
    ret = cne_fib6_delete(NULL, ip, depth);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /*Create valid fib to use in rest of test. */
    fib = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

    /* cne_fib6_add: depth > CNE_FIB6_MAXDEPTH */
    ret = cne_fib6_add(fib, ip, CNE_FIB6_MAXDEPTH + 1, nh);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /* cne_fib6_delete: depth > CNE_FIB6_MAXDEPTH */
    ret = cne_fib6_delete(fib, ip, CNE_FIB6_MAXDEPTH + 1);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    cne_fib6_free(fib);

    return TEST_SUCCESS;
}

/*
 * Check that cne_fib6_get_dp and cne_fib6_get_rib fails gracefully
 * for incorrect user input arguments
 */
int32_t
test_get_invalid(void)
{
    void *p;

    p = cne_fib6_get_dp(NULL);
    CNE_TEST_ASSERT(p == NULL, "Call succeeded with invalid parameters\n");

    p = cne_fib6_get_rib(NULL);
    CNE_TEST_ASSERT(p == NULL, "Call succeeded with invalid parameters\n");

    return TEST_SUCCESS;
}

/*
 * Add routes for one supernet with all possible depths and do lookup
 * on each step
 * After delete routes with doing lookup on each step
 */
static int
lookup_and_check_asc(struct cne_fib6 *fib, uint8_t ip_arr[CNE_FIB6_MAXDEPTH][IPV6_ADDR_LEN],
                     uint8_t ip_missing[][IPV6_ADDR_LEN], uint64_t def_nh, uint32_t n)
{
    uint64_t nh_arr[CNE_FIB6_MAXDEPTH];
    int ret;
    uint32_t i = 0;

    ret = cne_fib6_lookup_bulk(fib, ip_arr, nh_arr, CNE_FIB6_MAXDEPTH);
    CNE_TEST_ASSERT(ret == 0, "Failed to lookup\n");

    for (; i <= CNE_FIB6_MAXDEPTH - n; i++)
        CNE_TEST_ASSERT(nh_arr[i] == n, "Failed to get proper nexthop\n");

    for (; i < CNE_FIB6_MAXDEPTH; i++)
        CNE_TEST_ASSERT(nh_arr[i] == --n, "Failed to get proper nexthop\n");

    ret = cne_fib6_lookup_bulk(fib, ip_missing, nh_arr, 1);
    CNE_TEST_ASSERT((ret == 0) && (nh_arr[0] == def_nh), "Failed to get proper nexthop\n");

    return TEST_SUCCESS;
}

static int
lookup_and_check_desc(struct cne_fib6 *fib, uint8_t ip_arr[CNE_FIB6_MAXDEPTH][IPV6_ADDR_LEN],
                      uint8_t ip_missing[][IPV6_ADDR_LEN], uint64_t def_nh, uint32_t n)
{
    uint64_t nh_arr[CNE_FIB6_MAXDEPTH];
    int ret;
    uint32_t i = 0;

    ret = cne_fib6_lookup_bulk(fib, ip_arr, nh_arr, CNE_FIB6_MAXDEPTH);
    CNE_TEST_ASSERT(ret == 0, "Failed to lookup\n");

    for (; i < n; i++)
        CNE_TEST_ASSERT(nh_arr[i] == CNE_FIB6_MAXDEPTH - i, "Failed to get proper nexthop\n");

    for (; i < CNE_FIB6_MAXDEPTH; i++)
        CNE_TEST_ASSERT(nh_arr[i] == def_nh, "Failed to get proper nexthop\n");

    ret = cne_fib6_lookup_bulk(fib, ip_missing, nh_arr, 1);
    CNE_TEST_ASSERT((ret == 0) && (nh_arr[0] == def_nh), "Failed to get proper nexthop\n");

    return TEST_SUCCESS;
}

static int
check_fib(struct cne_fib6 *fib)
{
    uint64_t def_nh = 100;
    uint8_t ip_arr[CNE_FIB6_MAXDEPTH][IPV6_ADDR_LEN];
    uint8_t ip_add[IPV6_ADDR_LEN]        = {0};
    uint8_t ip_missing[1][IPV6_ADDR_LEN] = {{255}};
    uint32_t i, j;
    int ret;

    ip_add[0]        = 128;
    ip_missing[0][0] = 127;
    for (i = 0; i < CNE_FIB6_MAXDEPTH; i++) {
        for (j = 0; j < IPV6_ADDR_LEN; j++) {
            ip_arr[i][j] = ip_add[j] | ~get_msk_part(CNE_FIB6_MAXDEPTH - i, j);
        }
    }

    ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, 0);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");

    for (i = 1; i <= CNE_FIB6_MAXDEPTH; i++) {
        ret = cne_fib6_add(fib, ip_add, i, i);
        CNE_TEST_ASSERT(ret == 0, "Failed to add a route\n");
        ret = lookup_and_check_asc(fib, ip_arr, ip_missing, def_nh, i);
        CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
    }

    for (i = CNE_FIB6_MAXDEPTH; i > 1; i--) {
        ret = cne_fib6_delete(fib, ip_add, i);
        CNE_TEST_ASSERT(ret == 0, "Failed to delete a route\n");
        ret = lookup_and_check_asc(fib, ip_arr, ip_missing, def_nh, i - 1);

        CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
    }
    ret = cne_fib6_delete(fib, ip_add, i);
    CNE_TEST_ASSERT(ret == 0, "Failed to delete a route\n");
    ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, 0);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");

    for (i = 0; i < CNE_FIB6_MAXDEPTH; i++) {
        ret = cne_fib6_add(fib, ip_add, CNE_FIB6_MAXDEPTH - i, CNE_FIB6_MAXDEPTH - i);
        CNE_TEST_ASSERT(ret == 0, "Failed to add a route\n");
        ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, i + 1);
        CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
    }

    for (i = 1; i <= CNE_FIB6_MAXDEPTH; i++) {
        ret = cne_fib6_delete(fib, ip_add, i);
        CNE_TEST_ASSERT(ret == 0, "Failed to delete a route\n");
        ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, CNE_FIB6_MAXDEPTH - i);
        CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
    }

    return TEST_SUCCESS;
}

int32_t
test_lookup(void)
{
    struct cne_fib6 *fib = NULL;
    struct cne_fib_conf config;
    uint64_t def_nh = 100;
    int ret;

    config.max_routes = MAX_ROUTES;
    config.default_nh = def_nh;
    config.type       = CNE_FIB_DUMMY;

    fib = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
    ret = check_fib(fib);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Check_fib fails for DUMMY type\n");
    cne_fib6_free(fib);

    config.type = CNE_FIB_TRIE;

    config.trie.nh_sz    = CNE_FIB_TRIE_2B;
    config.trie.num_tbl8 = MAX_TBL8 - 1;
    fib                  = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
    ret = check_fib(fib);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Check_fib fails for TRIE_2B type\n");
    cne_fib6_free(fib);

    config.trie.nh_sz    = CNE_FIB_TRIE_4B;
    config.trie.num_tbl8 = MAX_TBL8;
    fib                  = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
    ret = check_fib(fib);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Check_fib fails for TRIE_4B type\n");
    cne_fib6_free(fib);

    config.trie.nh_sz    = CNE_FIB_TRIE_8B;
    config.trie.num_tbl8 = MAX_TBL8;
    fib                  = cne_fib6_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
    ret = check_fib(fib);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Check_fib fails for TRIE_8B type\n");
    cne_fib6_free(fib);

    return TEST_SUCCESS;
}

static struct unit_test_suite fib6_fast_tests = {
    .suite_name      = "fib6 autotest",
    .setup           = NULL,
    .teardown        = NULL,
    .unit_test_cases = {TEST_CASE(test_create_invalid), TEST_CASE(test_free_null),
                        TEST_CASE(test_add_del_invalid), TEST_CASE(test_get_invalid),
                        TEST_CASE(test_lookup), TEST_CASES_END()}};

static struct unit_test_suite fib6_slow_tests = {
    .suite_name      = "fib6 slow autotest",
    .setup           = NULL,
    .teardown        = NULL,
    .unit_test_cases = {TEST_CASE(test_multiple_create), TEST_CASES_END()}};

/*
 * Do all unit tests.
 */
static int
test_fib6(void)
{
    return unit_test_suite_runner(&fib6_fast_tests);
}

static int
test_slow_fib6(void)
{
    return unit_test_suite_runner(&fib6_slow_tests);
}

int
fib6_main(int argc, char **argv)
{
    tst_info_t *tst;
    int opt, flags = 0;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "v", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'v':
            break;
        default:
            break;
        }
    }
    (void)flags;

    tst = tst_start("FIB6");

    if (test_fib6() < 0)
        goto leave;

    if (test_slow_fib6() < 0)
        goto leave;

    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_end(tst, TST_FAILED);
    return -1;
}
