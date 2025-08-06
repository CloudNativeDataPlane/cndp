/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2025 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

#include <net/cne_ip.h>
#include <cne_log.h>
#include <cne_fib.h>
#include <tst_info.h>

#include "test.h"
#include "fib_test.h"

typedef int32_t (*cne_fib_test)(void);

static int32_t test_create_invalid(void);
static int32_t test_multiple_create(void);
static int32_t test_free_null(void);
static int32_t test_add_del_invalid(void);
static int32_t test_get_invalid(void);
static int32_t test_lookup(void);

#define MAX_ROUTES (1 << 16)
#define MAX_TBL8   (1 << 15)

/*
 * Check that cne_fib_create fails gracefully for incorrect user input
 * arguments
 */
int32_t
test_create_invalid(void)
{
    struct cne_fib *fib = NULL;
    struct cne_fib_conf config;

    config.max_routes = MAX_ROUTES;
    config.default_nh = 0;
    config.type       = CNE_FIB_DUMMY;

    /* cne_fib_create: fib name == NULL */
    fib = cne_fib_create(NULL, &config);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");

    /* cne_fib_create: config == NULL */
    fib = cne_fib_create(__func__, NULL);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");

    /* cne_fib_create: max_routes = 0 */
    config.max_routes = 0;
    fib               = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");
    config.max_routes = MAX_ROUTES;

    config.type = CNE_FIB_DIR24_8 + 1;
    fib         = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");

    config.type             = CNE_FIB_DIR24_8;
    config.dir24_8.num_tbl8 = MAX_TBL8;

    config.dir24_8.nh_sz = CNE_FIB_DIR24_8_8B + 1;
    fib                  = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib == NULL, "Call succeeded with invalid parameters\n");
    config.dir24_8.nh_sz = CNE_FIB_DIR24_8_8B;

    config.dir24_8.num_tbl8 = 0;
    fib                     = cne_fib_create(__func__, &config);
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
    struct cne_fib *fib = NULL;
    struct cne_fib_conf config;
    int32_t i;

    config.default_nh = 0;
    config.type       = CNE_FIB_DUMMY;

    for (i = 0; i < 100; i++) {
        config.max_routes = MAX_ROUTES - i;
        fib               = cne_fib_create(__func__, &config);
        CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
        cne_fib_free(fib);
    }
    /* Can not test free so return success */
    return TEST_SUCCESS;
}

/*
 * Call cne_fib_free for NULL pointer user input. Note: free has no return and
 * therefore it is impossible to check for failure but this test is added to
 * increase function coverage metrics and to validate that freeing null does
 * not crash.
 */
int32_t
test_free_null(void)
{
    struct cne_fib *fib = NULL;
    struct cne_fib_conf config;

    config.max_routes = MAX_ROUTES;
    config.default_nh = 0;
    config.type       = CNE_FIB_DUMMY;

    fib = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

    cne_fib_free(fib);
    cne_fib_free(NULL);
    return TEST_SUCCESS;
}

/*
 * Check that cne_fib_add and cne_fib_delete fails gracefully
 * for incorrect user input arguments
 */
int32_t
test_add_del_invalid(void)
{
    struct cne_fib *fib = NULL;
    struct cne_fib_conf config;
    uint64_t nh = 100;
    uint32_t ip = CNE_IPV4(0, 0, 0, 0);
    int ret;
    uint8_t depth = 24;

    config.max_routes = MAX_ROUTES;
    config.default_nh = 0;
    config.type       = CNE_FIB_DUMMY;

    /* cne_fib_add: fib == NULL */
    ret = cne_fib_add(NULL, ip, depth, nh);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /* cne_fib_delete: fib == NULL */
    ret = cne_fib_delete(NULL, ip, depth);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /*Create valid fib to use in rest of test. */
    fib = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

    /* cne_fib_add: depth > CNE_FIB_MAXDEPTH */
    ret = cne_fib_add(fib, ip, CNE_FIB_MAXDEPTH + 1, nh);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /* cne_fib_delete: depth > CNE_FIB_MAXDEPTH */
    ret = cne_fib_delete(fib, ip, CNE_FIB_MAXDEPTH + 1);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    cne_fib_free(fib);

    return TEST_SUCCESS;
}

/*
 * Check that cne_fib_get_dp and cne_fib_get_rib fails gracefully
 * for incorrect user input arguments
 */
int32_t
test_get_invalid(void)
{
    void *p;

    p = cne_fib_get_dp(NULL);
    CNE_TEST_ASSERT(p == NULL, "Call succeeded with invalid parameters\n");

    p = cne_fib_get_rib(NULL);
    CNE_TEST_ASSERT(p == NULL, "Call succeeded with invalid parameters\n");

    return TEST_SUCCESS;
}

/*
 * Add routes for one supernet with all possible depths and do lookup
 * on each step
 * After delete routes with doing lookup on each step
 */
static int
lookup_and_check_asc(struct cne_fib *fib, uint32_t ip_arr[CNE_FIB_MAXDEPTH], uint32_t ip_missing,
                     uint64_t def_nh, uint32_t n)
{
    uint64_t nh_arr[CNE_FIB_MAXDEPTH];
    int ret;
    uint32_t i = 0;

    ret = cne_fib_lookup_bulk(fib, ip_arr, nh_arr, CNE_FIB_MAXDEPTH);
    CNE_TEST_ASSERT(ret == 0, "Failed to lookup\n");

    for (; i <= CNE_FIB_MAXDEPTH - n; i++)
        CNE_TEST_ASSERT(nh_arr[i] == n, "Failed to get proper nexthop\n");

    for (; i < CNE_FIB_MAXDEPTH; i++)
        CNE_TEST_ASSERT(nh_arr[i] == --n, "Failed to get proper nexthop\n");

    ret = cne_fib_lookup_bulk(fib, &ip_missing, nh_arr, 1);
    CNE_TEST_ASSERT((ret == 0) && (nh_arr[0] == def_nh), "Failed to get proper nexthop\n");

    return TEST_SUCCESS;
}

static int
lookup_and_check_desc(struct cne_fib *fib, uint32_t ip_arr[CNE_FIB_MAXDEPTH], uint32_t ip_missing,
                      uint64_t def_nh, uint32_t n)
{
    uint64_t nh_arr[CNE_FIB_MAXDEPTH];
    int ret;
    uint32_t i = 0;

    ret = cne_fib_lookup_bulk(fib, ip_arr, nh_arr, CNE_FIB_MAXDEPTH);
    CNE_TEST_ASSERT(ret == 0, "Failed to lookup\n");

    for (; i < n; i++)
        CNE_TEST_ASSERT(nh_arr[i] == CNE_FIB_MAXDEPTH - i, "Failed to get proper nexthop\n");

    for (; i < CNE_FIB_MAXDEPTH; i++)
        CNE_TEST_ASSERT(nh_arr[i] == def_nh, "Failed to get proper nexthop\n");

    ret = cne_fib_lookup_bulk(fib, &ip_missing, nh_arr, 1);
    CNE_TEST_ASSERT((ret == 0) && (nh_arr[0] == def_nh), "Failed to get proper nexthop\n");

    return TEST_SUCCESS;
}

static int
check_fib(struct cne_fib *fib)
{
    uint64_t def_nh = 100;
    uint32_t ip_arr[CNE_FIB_MAXDEPTH];
    uint32_t ip_add = CNE_IPV4(128, 0, 0, 0);
    uint32_t i, ip_missing = CNE_IPV4(127, 255, 255, 255);
    int ret;

    for (i = 0; i < CNE_FIB_MAXDEPTH; i++)
        ip_arr[i] = ip_add + (1ULL << i) - 1;

    ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, 0);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");

    for (i = 1; i <= CNE_FIB_MAXDEPTH; i++) {
        ret = cne_fib_add(fib, ip_add, i, i);
        CNE_TEST_ASSERT(ret == 0, "Failed to add a route\n");
        ret = lookup_and_check_asc(fib, ip_arr, ip_missing, def_nh, i);
        CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
    }

    for (i = CNE_FIB_MAXDEPTH; i > 1; i--) {
        ret = cne_fib_delete(fib, ip_add, i);
        CNE_TEST_ASSERT(ret == 0, "Failed to delete a route\n");
        ret = lookup_and_check_asc(fib, ip_arr, ip_missing, def_nh, i - 1);

        CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
    }
    ret = cne_fib_delete(fib, ip_add, i);
    CNE_TEST_ASSERT(ret == 0, "Failed to delete a route\n");
    ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, 0);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");

    for (i = 0; i < CNE_FIB_MAXDEPTH; i++) {
        ret = cne_fib_add(fib, ip_add, CNE_FIB_MAXDEPTH - i, CNE_FIB_MAXDEPTH - i);
        CNE_TEST_ASSERT(ret == 0, "Failed to add a route\n");
        ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, i + 1);
        CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
    }

    for (i = 1; i <= CNE_FIB_MAXDEPTH; i++) {
        ret = cne_fib_delete(fib, ip_add, i);
        CNE_TEST_ASSERT(ret == 0, "Failed to delete a route\n");
        ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, CNE_FIB_MAXDEPTH - i);
        CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
    }

    return TEST_SUCCESS;
}

int32_t
test_lookup(void)
{
    struct cne_fib *fib = NULL;
    struct cne_fib_conf config;
    uint64_t def_nh = 100;
    int ret;

    config.max_routes = MAX_ROUTES;
    config.default_nh = def_nh;
    config.type       = CNE_FIB_DUMMY;

    fib = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
    ret = check_fib(fib);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Check_fib fails for DUMMY type\n");
    cne_fib_free(fib);

    config.type = CNE_FIB_DIR24_8;

    config.dir24_8.nh_sz    = CNE_FIB_DIR24_8_1B;
    config.dir24_8.num_tbl8 = 127;
    fib                     = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
    ret = check_fib(fib);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Check_fib fails for DIR24_8_1B type\n");
    cne_fib_free(fib);

    config.dir24_8.nh_sz    = CNE_FIB_DIR24_8_2B;
    config.dir24_8.num_tbl8 = MAX_TBL8 - 1;
    fib                     = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
    ret = check_fib(fib);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Check_fib fails for DIR24_8_2B type\n");
    cne_fib_free(fib);

    config.dir24_8.nh_sz    = CNE_FIB_DIR24_8_4B;
    config.dir24_8.num_tbl8 = MAX_TBL8;
    fib                     = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
    ret = check_fib(fib);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Check_fib fails for DIR24_8_4B type\n");
    cne_fib_free(fib);

    config.dir24_8.nh_sz    = CNE_FIB_DIR24_8_8B;
    config.dir24_8.num_tbl8 = MAX_TBL8;
    fib                     = cne_fib_create(__func__, &config);
    CNE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
    ret = check_fib(fib);
    CNE_TEST_ASSERT(ret == TEST_SUCCESS, "Check_fib fails for DIR24_8_8B type\n");
    cne_fib_free(fib);

    return TEST_SUCCESS;
}

// clang-format off
static struct unit_test_suite fib_fast_tests = {
    .suite_name      = "fib autotest",
    .setup           = NULL,
    .teardown        = NULL,
    .unit_test_cases = {
		TEST_CASE(test_create_invalid),
		TEST_CASE(test_free_null),
        TEST_CASE(test_add_del_invalid),
		TEST_CASE(test_get_invalid),
        TEST_CASE(test_lookup),
		TEST_CASES_END()
	}
};

static struct unit_test_suite fib_slow_tests = {
    .suite_name      = "fib slow autotest",
    .setup           = NULL,
    .teardown        = NULL,
    .unit_test_cases = {
		TEST_CASE(test_multiple_create),
		TEST_CASES_END()
	}
};
// clang-format on
/*
 * Do all unit tests.
 */
static int
test_fib(void)
{
    return unit_test_suite_runner(&fib_fast_tests);
}

static int
test_slow_fib(void)
{
    return unit_test_suite_runner(&fib_slow_tests);
}

int
fib_main(int argc, char **argv)
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

    tst = tst_start("FIB");

    if (test_fib() < 0)
        goto leave;

    if (test_slow_fib() < 0)
        goto leave;

    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_end(tst, TST_FAILED);
    return -1;
}
