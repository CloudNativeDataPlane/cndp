/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2023 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

#include <net/cne_ip.h>
#include <cne_rib.h>
#include <tst_info.h>

#include "test.h"
#include "rib_test.h"

typedef int32_t (*cne_rib_test)(void);

static int32_t test_create_invalid(void);
static int32_t test_multiple_create(void);
static int32_t test_free_null(void);
static int32_t test_insert_invalid(void);
static int32_t test_get_fn(void);
static int32_t test_basic(void);
static int32_t test_tree_traversal(void);

#define MAX_DEPTH 32
#define MAX_RULES (1 << 22)

/*
 * Check that cne_rib_create fails gracefully for incorrect user input
 * arguments
 */
int32_t
test_create_invalid(void)
{
    struct cne_rib *rib = NULL;
    struct cne_rib_conf config;

    config.max_nodes = MAX_RULES;
    config.ext_sz    = 0;

    /* cne_rib_create: rib name == NULL */
    rib = cne_rib_create(NULL, &config);
    CNE_TEST_ASSERT(rib == NULL, "Call succeeded with invalid parameters\n");

    /* cne_rib_create: config == NULL */
    rib = cne_rib_create(__func__, NULL);
    CNE_TEST_ASSERT(rib == NULL, "Call succeeded with invalid parameters\n");

    /* cne_rib_create: max_nodes = 0 */
    config.max_nodes = 0;
    rib              = cne_rib_create(__func__, &config);
    CNE_TEST_ASSERT(rib == NULL, "Call succeeded with invalid parameters\n");
    config.max_nodes = MAX_RULES;

    return TEST_SUCCESS;
}

/*
 * Create rib table then delete rib table 10 times
 * Use a slightly different rules size each time
 */
int32_t
test_multiple_create(void)
{
    struct cne_rib *rib = NULL;
    struct cne_rib_conf config;
    int32_t i;

    config.ext_sz = 0;

    for (i = 0; i < 100; i++) {
        config.max_nodes = MAX_RULES - i;
        rib              = cne_rib_create(__func__, &config);
        CNE_TEST_ASSERT(rib != NULL, "Failed to create RIB\n");
        cne_rib_free(rib);
    }
    /* Can not test free so return success */
    return TEST_SUCCESS;
}

/*
 * Call cne_rib_free for NULL pointer user input. Note: free has no return and
 * therefore it is impossible to check for failure but this test is added to
 * increase function coverage metrics and to validate that freeing null does
 * not crash.
 */
int32_t
test_free_null(void)
{
    struct cne_rib *rib = NULL;
    struct cne_rib_conf config;

    config.max_nodes = MAX_RULES;
    config.ext_sz    = 0;

    rib = cne_rib_create(__func__, &config);
    CNE_TEST_ASSERT(rib != NULL, "Failed to create RIB\n");

    cne_rib_free(rib);
    cne_rib_free(NULL);
    return TEST_SUCCESS;
}

/*
 * Check that cne_rib_insert fails gracefully for incorrect user input arguments
 */
int32_t
test_insert_invalid(void)
{
    struct cne_rib *rib = NULL;
    struct cne_rib_node *node, *node1;
    struct cne_rib_conf config;
    uint32_t ip   = CNE_IPV4(0, 0, 0, 0);
    uint8_t depth = 24;

    config.max_nodes = MAX_RULES;
    config.ext_sz    = 0;

    /* cne_rib_insert: rib == NULL */
    node = cne_rib_insert(NULL, ip, depth);
    CNE_TEST_ASSERT(node == NULL, "Call succeeded with invalid parameters\n");

    /*Create valid rib to use in rest of test. */
    rib = cne_rib_create(__func__, &config);
    CNE_TEST_ASSERT(rib != NULL, "Failed to create RIB\n");

    /* cne_rib_insert: depth > MAX_DEPTH */
    node = cne_rib_insert(rib, ip, MAX_DEPTH + 1);
    CNE_TEST_ASSERT(node == NULL, "Call succeeded with invalid parameters\n");

    /* insert the same ip/depth twice*/
    node = cne_rib_insert(rib, ip, depth);
    CNE_TEST_ASSERT(node != NULL, "Failed to insert rule\n");
    node1 = cne_rib_insert(rib, ip, depth);
    CNE_TEST_ASSERT(node1 == NULL, "Call succeeded with invalid parameters\n");

    cne_rib_free(rib);

    return TEST_SUCCESS;
}

/*
 * Call cne_rib_node access functions with incorrect input.
 * After call cne_rib_node access functions with correct args
 * and check the return values for correctness
 */
int32_t
test_get_fn(void)
{
    struct cne_rib *rib = NULL;
    struct cne_rib_node *node;
    struct cne_rib_conf config;
    void *ext;
    uint32_t ip = CNE_IPV4(192, 0, 2, 0);
    uint32_t ip_ret;
    uint64_t nh_set = 10;
    uint64_t nh_ret;
    uint8_t depth = 24;
    uint8_t depth_ret;
    int ret;

    config.max_nodes = MAX_RULES;
    config.ext_sz    = 0;

    rib = cne_rib_create(__func__, &config);
    CNE_TEST_ASSERT(rib != NULL, "Failed to create RIB\n");

    node = cne_rib_insert(rib, ip, depth);
    CNE_TEST_ASSERT(node != NULL, "Failed to insert rule\n");

    /* test cne_rib_get_ip() with incorrect args */
    ret = cne_rib_get_ip(NULL, &ip_ret);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");
    ret = cne_rib_get_ip(node, NULL);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /* test cne_rib_get_depth() with incorrect args */
    ret = cne_rib_get_depth(NULL, &depth_ret);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");
    ret = cne_rib_get_depth(node, NULL);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /* test cne_rib_set_nh() with incorrect args */
    ret = cne_rib_set_nh(NULL, nh_set);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /* test cne_rib_get_nh() with incorrect args */
    ret = cne_rib_get_nh(NULL, &nh_ret);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");
    ret = cne_rib_get_nh(node, NULL);
    CNE_TEST_ASSERT(ret < 0, "Call succeeded with invalid parameters\n");

    /* test cne_rib_get_ext() with incorrect args */
    ext = cne_rib_get_ext(NULL);
    CNE_TEST_ASSERT(ext == NULL, "Call succeeded with invalid parameters\n");

    /* check the return values */
    ret = cne_rib_get_ip(node, &ip_ret);
    CNE_TEST_ASSERT((ret == 0) && (ip_ret == ip), "Failed to get proper node ip\n");
    ret = cne_rib_get_depth(node, &depth_ret);
    CNE_TEST_ASSERT((ret == 0) && (depth_ret == depth), "Failed to get proper node depth\n");
    ret = cne_rib_set_nh(node, nh_set);
    CNE_TEST_ASSERT(ret == 0, "Failed to set cne_rib_node nexthop\n");
    ret = cne_rib_get_nh(node, &nh_ret);
    CNE_TEST_ASSERT((ret == 0) && (nh_ret == nh_set), "Failed to get proper nexthop\n");

    cne_rib_free(rib);

    return TEST_SUCCESS;
}

/*
 * Call insert, lookup/lookup_exact and delete for a single rule
 */
int32_t
test_basic(void)
{
    struct cne_rib *rib = NULL;
    struct cne_rib_node *node;
    struct cne_rib_conf config;

    uint32_t ip           = CNE_IPV4(192, 0, 2, 0);
    uint64_t next_hop_add = 10;
    uint64_t next_hop_return;
    uint8_t depth = 24;
    int ret;

    config.max_nodes = MAX_RULES;
    config.ext_sz    = 0;

    rib = cne_rib_create(__func__, &config);
    CNE_TEST_ASSERT(rib != NULL, "Failed to create RIB\n");

    node = cne_rib_insert(rib, ip, depth);
    CNE_TEST_ASSERT(node != NULL, "Failed to insert rule\n");

    ret = cne_rib_set_nh(node, next_hop_add);
    CNE_TEST_ASSERT(ret == 0, "Failed to set cne_rib_node field\n");

    node = cne_rib_lookup(rib, ip);
    CNE_TEST_ASSERT(node != NULL, "Failed to lookup\n");

    ret = cne_rib_get_nh(node, &next_hop_return);
    CNE_TEST_ASSERT((ret == 0) && (next_hop_add == next_hop_return),
                    "Failed to get proper nexthop\n");

    node = cne_rib_lookup_exact(rib, ip, depth);
    CNE_TEST_ASSERT(node != NULL, "Failed to lookup\n");

    ret = cne_rib_get_nh(node, &next_hop_return);
    CNE_TEST_ASSERT((ret == 0) && (next_hop_add == next_hop_return),
                    "Failed to get proper nexthop\n");

    cne_rib_remove(rib, ip, depth);

    node = cne_rib_lookup(rib, ip);
    CNE_TEST_ASSERT(node == NULL, "Lookup returns non existent rule\n");
    node = cne_rib_lookup_exact(rib, ip, depth);
    CNE_TEST_ASSERT(node == NULL, "Lookup returns non existent rule\n");

    cne_rib_free(rib);

    return TEST_SUCCESS;
}

int32_t
test_tree_traversal(void)
{
    struct cne_rib *rib = NULL;
    struct cne_rib_node *node;
    struct cne_rib_conf config;

    uint32_t ip1  = CNE_IPV4(10, 10, 10, 0);
    uint32_t ip2  = CNE_IPV4(10, 10, 130, 80);
    uint8_t depth = 30;

    config.max_nodes = MAX_RULES;
    config.ext_sz    = 0;

    rib = cne_rib_create(__func__, &config);
    CNE_TEST_ASSERT(rib != NULL, "Failed to create RIB\n");

    node = cne_rib_insert(rib, ip1, depth);
    CNE_TEST_ASSERT(node != NULL, "Failed to insert rule\n");

    node = cne_rib_insert(rib, ip2, depth);
    CNE_TEST_ASSERT(node != NULL, "Failed to insert rule\n");

    node = NULL;
    node = cne_rib_get_nxt(rib, CNE_IPV4(10, 10, 130, 0), 24, node, CNE_RIB_GET_NXT_ALL);
    CNE_TEST_ASSERT(node != NULL, "Failed to get rib_node\n");

    cne_rib_free(rib);

    return TEST_SUCCESS;
}

// clang-format off
static struct unit_test_suite rib_tests = {
    .suite_name      = "rib autotest",
    .setup           = NULL,
    .teardown        = NULL,
    .unit_test_cases = {
		TEST_CASE(test_create_invalid),
		TEST_CASE(test_free_null),
        TEST_CASE(test_insert_invalid),
		TEST_CASE(test_get_fn),
        TEST_CASE(test_basic),
		TEST_CASE(test_tree_traversal),
		TEST_CASES_END()
	}
};

static struct unit_test_suite rib_slow_tests = {
    .suite_name      = "rib slow autotest",
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
test_rib(void)
{
    return unit_test_suite_runner(&rib_tests);
}

static int
test_slow_rib(void)
{
    return unit_test_suite_runner(&rib_slow_tests);
}

int
rib_main(int argc, char **argv)
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

    tst = tst_start("RIB");

    if (test_rib() < 0)
        goto leave;

    if (test_slow_rib() < 0)
        goto leave;

    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_end(tst, TST_FAILED);
    return -1;
}
