/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2015 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>

#include <cne_common.h>
#include <cne_cycles.h>
#include <net/cne_ip.h>
#include <cne_strings.h>

#include <tst_info.h>

#include "test.h"
#include "hash_test.h"

#include <cne_hash.h>
#include <cne_fbk_hash.h>
#include <cne_jhash.h>
#include <cne_hash_crc.h>

/*******************************************************************************
 * Hash function performance test configuration section. Each performance test
 * will be performed HASHTEST_ITERATIONS times.
 *
 * The five arrays below control what tests are performed. Every combination
 * from the array entries is tested.
 */
static cne_hash_function hashtest_funcs[] = {cne_jhash, cne_hash_crc};
static uint32_t hashtest_initvals[]       = {0};
static uint32_t hashtest_key_lens[] = {0, 2, 4, 5, 6, 7, 8, 10, 11, 15, 16, 21, 31, 32, 33, 63, 64};
#define MAX_KEYSIZE 64
/******************************************************************************/
#define LOCAL_FBK_HASH_ENTRIES_MAX (1 << 15)

/*
 * Check condition and return an error if true. Assumes that "handle" is the
 * name of the hash structure pointer to be freed.
 */
#define RETURN_IF_ERROR(cond, str, ...)                                      \
    do {                                                                     \
        if (cond) {                                                          \
            cne_printf("ERROR line %d: " str "\n", __LINE__, ##__VA_ARGS__); \
            if (handle)                                                      \
                cne_hash_free(handle);                                       \
            return -1;                                                       \
        }                                                                    \
    } while (0)

#define RETURN_IF_ERROR_FBK(cond, str, ...)                                  \
    do {                                                                     \
        if (cond) {                                                          \
            cne_printf("ERROR line %d: " str "\n", __LINE__, ##__VA_ARGS__); \
            if (handle)                                                      \
                cne_fbk_hash_free(handle);                                   \
            return -1;                                                       \
        }                                                                    \
    } while (0)

/* 5-tuple key type */
struct flow_key {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    uint8_t proto;
} __cne_packed;

/*
 * Hash function that always returns the same value, to easily test what
 * happens when a bucket is full.
 */
static uint32_t
pseudo_hash(__cne_unused const void *keys, __cne_unused uint32_t key_len,
            __cne_unused uint32_t init_val)
{
    return 3;
}

/*
 * Print out result of unit test hash operation.
 */
static void
print_key_info(const char *msg, const struct flow_key *key, int32_t pos)
{
    const uint8_t *p = (const uint8_t *)key;
    unsigned int i;

    CNE_DEBUG("%s key:0x", msg);
    for (i = 0; i < sizeof(struct flow_key); i++)
        CNE_DEBUG("%02X", p[i]);
    CNE_DEBUG(" @ pos %d\n", pos);
}

/* Keys used by unit test functions */
// clang-format off
static struct flow_key keys[5] = {
    {
        .ip_src   = CNE_IPV4(0x03, 0x02, 0x01, 0x00),
        .ip_dst   = CNE_IPV4(0x07, 0x06, 0x05, 0x04),
        .port_src = 0x0908,
        .port_dst = 0x0b0a,
        .proto    = 0x0c,
    },
    {
        .ip_src   = CNE_IPV4(0x13, 0x12, 0x11, 0x10),
        .ip_dst   = CNE_IPV4(0x17, 0x16, 0x15, 0x14),
        .port_src = 0x1918,
        .port_dst = 0x1b1a,
        .proto    = 0x1c,
    },
    {
        .ip_src   = CNE_IPV4(0x23, 0x22, 0x21, 0x20),
        .ip_dst   = CNE_IPV4(0x27, 0x26, 0x25, 0x24),
        .port_src = 0x2928,
        .port_dst = 0x2b2a,
        .proto    = 0x2c,
    },
    {
        .ip_src   = CNE_IPV4(0x33, 0x32, 0x31, 0x30),
        .ip_dst   = CNE_IPV4(0x37, 0x36, 0x35, 0x34),
        .port_src = 0x3938,
        .port_dst = 0x3b3a,
        .proto    = 0x3c,
    },
    {
        .ip_src   = CNE_IPV4(0x43, 0x42, 0x41, 0x40),
        .ip_dst   = CNE_IPV4(0x47, 0x46, 0x45, 0x44),
        .port_src = 0x4948,
        .port_dst = 0x4b4a,
        .proto    = 0x4c,
    }
};
// clang-format on

/* Parameters used for hash table in unit test functions. Name set later. */
static struct cne_hash_parameters ut_params = {
    .entries            = 64,
    .key_len            = sizeof(struct flow_key), /* 13 */
    .hash_func          = cne_jhash,
    .hash_func_init_val = 0,
    .socket_id          = 0,
};

#define CRC32_ITERATIONS (1U << 10)
#define CRC32_DWORDS     (1U << 6)
/*
 * Test if all CRC32 implementations yield the same hash value
 */
static int
test_crc32_hash_alg_equiv(void)
{
    uint32_t hash_val;
    uint32_t init_val;
    uint64_t data64[CRC32_DWORDS];
    unsigned i, j;
    size_t data_len;

    tst_info("CRC32 implementations equivalence test");
    for (i = 0; i < CRC32_ITERATIONS; i++) {
        /* Randomizing data_len of data set */
        data_len = (size_t)((rand() % sizeof(data64)) + 1);
        init_val = (uint32_t)rand();

        /* Fill the data set */
        for (j = 0; j < CRC32_DWORDS; j++)
            data64[j] = rand();

        /* Calculate software CRC32 */
        cne_hash_crc_set_alg(CRC32_SW);
        hash_val = cne_hash_crc(data64, data_len, init_val);

        /* Check against 4-byte-operand sse4.2 CRC32 if available */
        cne_hash_crc_set_alg(CRC32_SSE42);
        if (hash_val != cne_hash_crc(data64, data_len, init_val)) {
            tst_error("Failed checking CRC32_SW against CRC32_SSE42");
            break;
        }

        /* Check against 8-byte-operand sse4.2 CRC32 if available */
        cne_hash_crc_set_alg(CRC32_SSE42_x64);
        if (hash_val != cne_hash_crc(data64, data_len, init_val)) {
            tst_error("Failed checking CRC32_SW against CRC32_SSE42_x64");
            break;
        }
    }

    /* Resetting to best available algorithm */
    cne_hash_crc_set_alg(CRC32_SSE42_x64);

    if (i == CRC32_ITERATIONS)
        return 0;

    tst_error("Failed test data (hex, %zu bytes total):", data_len);
    for (j = 0; j < data_len; j++)
        cne_printf("%02X%c", ((uint8_t *)data64)[j],
                   ((j + 1) % 16 == 0 || j == data_len - 1) ? '\n' : ' ');

    return -1;
}

/*
 * Test a hash function.
 */
static void
run_hash_func_test(cne_hash_function f, uint32_t init_val, uint32_t key_len)
{
    static uint8_t key[MAX_KEYSIZE];
    unsigned i;

    for (i = 0; i < key_len; i++)
        key[i] = (uint8_t)rand();

    /* just to be on the safe side */
    if (!f)
        return;

    f(key, key_len, init_val);
}

/*
 * Test all hash functions.
 */
static void
run_hash_func_tests(void)
{
    unsigned i, j, k;

    for (i = 0; i < CNE_DIM(hashtest_funcs); i++) {
        for (j = 0; j < CNE_DIM(hashtest_initvals); j++) {
            for (k = 0; k < CNE_DIM(hashtest_key_lens); k++) {
                run_hash_func_test(hashtest_funcs[i], hashtest_initvals[j], hashtest_key_lens[k]);
            }
        }
    }
}

/*
 * Basic sequence of operations for a single key:
 *	- add
 *	- lookup (hit)
 *	- delete
 *	- lookup (miss)
 *
 * Repeat the test case when 'free on delete' is disabled.
 *	- add
 *	- lookup (hit)
 *	- delete
 *	- lookup (miss)
 *	- free
 */
static int
test_add_delete(void)
{
    struct cne_hash *handle;
    /* test with standard add/lookup/delete functions */
    int pos0, expectedPos0;

    ut_params.name = "test1";
    handle         = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");

    pos0 = cne_hash_add_key(handle, &keys[0]);
    print_key_info("Add", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 < 0, "failed to add key (pos0=%d)", pos0);
    expectedPos0 = pos0;

    pos0 = cne_hash_lookup(handle, &keys[0]);
    print_key_info("Lkp", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != expectedPos0, "failed to find key (pos0=%d)", pos0);

    pos0 = cne_hash_del_key(handle, &keys[0]);
    print_key_info("Del", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != expectedPos0, "failed to delete key (pos0=%d)", pos0);

    pos0 = cne_hash_lookup(handle, &keys[0]);
    print_key_info("Lkp", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != -ENOENT, "fail: found key after deleting! (pos0=%d)", pos0);

    cne_hash_free(handle);

    /* repeat test with precomputed hash functions */
    hash_sig_t hash_value;
    int pos1, expectedPos1, delPos1;

    ut_params.extra_flag = CNE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL;
    handle               = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");
    ut_params.extra_flag = 0;

    hash_value = cne_hash_hash(handle, &keys[0]);
    pos1       = cne_hash_add_key_with_hash(handle, &keys[0], hash_value);
    print_key_info("Add", &keys[0], pos1);
    RETURN_IF_ERROR(pos1 < 0, "failed to add key (pos1=%d)", pos1);
    expectedPos1 = pos1;

    pos1 = cne_hash_lookup_with_hash(handle, &keys[0], hash_value);
    print_key_info("Lkp", &keys[0], pos1);
    RETURN_IF_ERROR(pos1 != expectedPos1, "failed to find key (pos1=%d)", pos1);

    pos1 = cne_hash_del_key_with_hash(handle, &keys[0], hash_value);
    print_key_info("Del", &keys[0], pos1);
    RETURN_IF_ERROR(pos1 != expectedPos1, "failed to delete key (pos1=%d)", pos1);
    delPos1 = pos1;

    pos1 = cne_hash_lookup_with_hash(handle, &keys[0], hash_value);
    print_key_info("Lkp", &keys[0], pos1);
    RETURN_IF_ERROR(pos1 != -ENOENT, "fail: found key after deleting! (pos1=%d)", pos1);

    pos1 = cne_hash_free_key_with_position(handle, delPos1);
    print_key_info("Free", &keys[0], delPos1);
    RETURN_IF_ERROR(pos1 != 0, "failed to free key (pos1=%d)", delPos1);

    cne_hash_free(handle);

    return 0;
}

/*
 * Sequence of operations for a single key:
 *	- delete: miss
 *	- add
 *	- lookup: hit
 *	- add: update
 *	- lookup: hit (updated data)
 *	- delete: hit
 *	- delete: miss
 *	- lookup: miss
 */
static int
test_add_update_delete(void)
{
    struct cne_hash *handle;
    int pos0, expectedPos0;

    ut_params.name = "test2";
    handle         = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");

    pos0 = cne_hash_del_key(handle, &keys[0]);
    print_key_info("Del", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != -ENOENT, "fail: found non-existent key (pos0=%d)", pos0);

    pos0 = cne_hash_add_key(handle, &keys[0]);
    print_key_info("Add", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 < 0, "failed to add key (pos0=%d)", pos0);
    expectedPos0 = pos0;

    pos0 = cne_hash_lookup(handle, &keys[0]);
    print_key_info("Lkp", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != expectedPos0, "failed to find key (pos0=%d)", pos0);

    pos0 = cne_hash_add_key(handle, &keys[0]);
    print_key_info("Add", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != expectedPos0, "failed to re-add key (pos0=%d)", pos0);

    pos0 = cne_hash_lookup(handle, &keys[0]);
    print_key_info("Lkp", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != expectedPos0, "failed to find key (pos0=%d)", pos0);

    pos0 = cne_hash_del_key(handle, &keys[0]);
    print_key_info("Del", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != expectedPos0, "failed to delete key (pos0=%d)", pos0);

    pos0 = cne_hash_del_key(handle, &keys[0]);
    print_key_info("Del", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != -ENOENT, "fail: deleted already deleted key (pos0=%d)", pos0);

    pos0 = cne_hash_lookup(handle, &keys[0]);
    print_key_info("Lkp", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != -ENOENT, "fail: found key after deleting! (pos0=%d)", pos0);

    cne_hash_free(handle);
    return 0;
}

/*
 * Sequence of operations for a single key with 'disable free on del' set:
 *	- delete: miss
 *	- add
 *	- lookup: hit
 *	- add: update
 *	- lookup: hit (updated data)
 *	- delete: hit
 *	- delete: miss
 *	- lookup: miss
 *	- free: hit
 *	- lookup: miss
 */
static int
test_add_update_delete_free(void)
{
    struct cne_hash *handle;
    int pos0, expectedPos0, delPos0, result;

    ut_params.name       = "test2";
    ut_params.extra_flag = CNE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL;
    handle               = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");
    ut_params.extra_flag = 0;

    pos0 = cne_hash_del_key(handle, &keys[0]);
    print_key_info("Del", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != -ENOENT, "fail: found non-existent key (pos0=%d)", pos0);

    pos0 = cne_hash_add_key(handle, &keys[0]);
    print_key_info("Add", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 < 0, "failed to add key (pos0=%d)", pos0);
    expectedPos0 = pos0;

    pos0 = cne_hash_lookup(handle, &keys[0]);
    print_key_info("Lkp", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != expectedPos0, "failed to find key (pos0=%d)", pos0);

    pos0 = cne_hash_add_key(handle, &keys[0]);
    print_key_info("Add", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != expectedPos0, "failed to re-add key (pos0=%d)", pos0);

    pos0 = cne_hash_lookup(handle, &keys[0]);
    print_key_info("Lkp", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != expectedPos0, "failed to find key (pos0=%d)", pos0);

    delPos0 = cne_hash_del_key(handle, &keys[0]);
    print_key_info("Del", &keys[0], delPos0);
    RETURN_IF_ERROR(delPos0 != expectedPos0, "failed to delete key (pos0=%d)", delPos0);

    pos0 = cne_hash_del_key(handle, &keys[0]);
    print_key_info("Del", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != -ENOENT, "fail: deleted already deleted key (pos0=%d)", pos0);

    pos0 = cne_hash_lookup(handle, &keys[0]);
    print_key_info("Lkp", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != -ENOENT, "fail: found key after deleting! (pos0=%d)", pos0);

    result = cne_hash_free_key_with_position(handle, delPos0);
    print_key_info("Free", &keys[0], delPos0);
    RETURN_IF_ERROR(result != 0, "failed to free key (pos1=%d)", delPos0);

    pos0 = cne_hash_lookup(handle, &keys[0]);
    print_key_info("Lkp", &keys[0], pos0);
    RETURN_IF_ERROR(pos0 != -ENOENT, "fail: found key after deleting! (pos0=%d)", pos0);

    cne_hash_free(handle);
    return 0;
}

/*
 * Sequence of operations for a single key with 'rw concurrency lock free' set:
 *	- add
 *	- delete: hit
 *	- free: hit
 * Repeat the test case when 'multi writer add' is enabled.
 *	- add
 *	- delete: hit
 *	- free: hit
 */
static int
test_add_delete_free_lf(void)
{
/* Should match the #define LCORE_CACHE_SIZE value in cne_cuckoo_hash.h */
#define LCORE_CACHE_SIZE 64
    struct cne_hash *handle;
    hash_sig_t hash_value;
    int pos, expectedPos, delPos;
    uint8_t extra_flag;
    uint32_t i, ip_src;

    extra_flag           = ut_params.extra_flag;
    ut_params.extra_flag = 0 /*CNE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF*/;
    handle               = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");
    ut_params.extra_flag = extra_flag;

    /*
     * The number of iterations is at least the same as the number of slots
     * cne_hash allocates internally. This is to reveal potential issues of
     * not freeing keys successfully.
     */
    for (i = 0; i < ut_params.entries + 1; i++) {
        hash_value = cne_hash_hash(handle, &keys[0]);
        pos        = cne_hash_add_key_with_hash(handle, &keys[0], hash_value);
        print_key_info("Add", &keys[0], pos);
        RETURN_IF_ERROR(pos < 0, "failed to add key (pos=%d)", pos);
        expectedPos = pos;

        pos = cne_hash_del_key_with_hash(handle, &keys[0], hash_value);
        print_key_info("Del", &keys[0], pos);
        RETURN_IF_ERROR(pos != expectedPos, "failed to delete key (pos=%d)", pos);
        delPos = pos;

        pos = cne_hash_free_key_with_position(handle, delPos);
        print_key_info("Free", &keys[0], delPos);
        RETURN_IF_ERROR(pos != 0, "failed to free key (pos=%d)", delPos);
    }

    cne_hash_free(handle);

    extra_flag = ut_params.extra_flag;
    ut_params.extra_flag =
        0 /*CNE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | CNE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD*/;
    handle = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");
    ut_params.extra_flag = extra_flag;

    ip_src = keys[0].ip_src;
    /*
     * The number of iterations is at least the same as the number of slots
     * cne_hash allocates internally. This is to reveal potential issues of
     * not freeing keys successfully.
     */
    for (i = 0; i < ut_params.entries + (cne_max_threads() - 1) * (LCORE_CACHE_SIZE - 1) + 1; i++) {
        keys[0].ip_src++;
        hash_value = cne_hash_hash(handle, &keys[0]);
        pos        = cne_hash_add_key_with_hash(handle, &keys[0], hash_value);
        print_key_info("Add", &keys[0], pos);
        RETURN_IF_ERROR(pos < 0, "failed to add key (pos=%d)", pos);
        expectedPos = pos;

        pos = cne_hash_del_key_with_hash(handle, &keys[0], hash_value);
        print_key_info("Del", &keys[0], pos);
        RETURN_IF_ERROR(pos != expectedPos, "failed to delete key (pos=%d)", pos);
        delPos = pos;

        pos = cne_hash_free_key_with_position(handle, delPos);
        print_key_info("Free", &keys[0], delPos);
        RETURN_IF_ERROR(pos != 0, "failed to free key (pos=%d)", delPos);
    }
    keys[0].ip_src = ip_src;

    cne_hash_free(handle);

    return 0;
}

/*
 * Sequence of operations for retrieving a key with its position
 *
 *  - create table
 *  - add key
 *  - get the key with its position: hit
 *  - delete key
 *  - try to get the deleted key: miss
 *
 * Repeat the test case when 'free on delete' is disabled.
 *  - create table
 *  - add key
 *  - get the key with its position: hit
 *  - delete key
 *  - try to get the deleted key: hit
 *  - free key
 *  - try to get the deleted key: miss
 *
 */
static int
test_hash_get_key_with_position(void)
{
    struct cne_hash *handle = NULL;
    int pos, expectedPos, delPos, result;
    void *key;

    ut_params.name = "hash_get_key_w_pos";
    handle         = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");

    pos = cne_hash_add_key(handle, &keys[0]);
    print_key_info("Add", &keys[0], pos);
    RETURN_IF_ERROR(pos < 0, "failed to add key (pos0=%d)", pos);
    expectedPos = pos;

    result = cne_hash_get_key_with_position(handle, pos, &key);
    RETURN_IF_ERROR(result != 0, "error retrieving a key");

    pos = cne_hash_del_key(handle, &keys[0]);
    print_key_info("Del", &keys[0], pos);
    RETURN_IF_ERROR(pos != expectedPos, "failed to delete key (pos0=%d)", pos);

    result = cne_hash_get_key_with_position(handle, pos, &key);
    RETURN_IF_ERROR(result != -ENOENT, "non valid key retrieved");

    cne_hash_free(handle);

    ut_params.name       = "hash_get_key_w_pos";
    ut_params.extra_flag = CNE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL;
    handle               = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");
    ut_params.extra_flag = 0;

    pos = cne_hash_add_key(handle, &keys[0]);
    print_key_info("Add", &keys[0], pos);
    RETURN_IF_ERROR(pos < 0, "failed to add key (pos0=%d)", pos);
    expectedPos = pos;

    result = cne_hash_get_key_with_position(handle, pos, &key);
    RETURN_IF_ERROR(result != 0, "error retrieving a key");

    delPos = cne_hash_del_key(handle, &keys[0]);
    print_key_info("Del", &keys[0], delPos);
    RETURN_IF_ERROR(delPos != expectedPos, "failed to delete key (pos0=%d)", delPos);

    result = cne_hash_get_key_with_position(handle, delPos, &key);
    RETURN_IF_ERROR(result != -ENOENT, "non valid key retrieved");

    result = cne_hash_free_key_with_position(handle, delPos);
    print_key_info("Free", &keys[0], delPos);
    RETURN_IF_ERROR(result != 0, "failed to free key (pos1=%d)", delPos);

    result = cne_hash_get_key_with_position(handle, delPos, &key);
    RETURN_IF_ERROR(result != -ENOENT, "non valid key retrieved");

    cne_hash_free(handle);
    return 0;
}

/*
 * Sequence of operations for 5 keys
 *	- add keys
 *	- lookup keys: hit
 *	- add keys (update)
 *	- lookup keys: hit (updated data)
 *	- delete keys : hit
 *	- lookup keys: miss
 */
static int
test_five_keys(void)
{
    struct cne_hash *handle;
    const void *key_array[5] = {0};
    int pos[5];
    int expected_pos[5];
    unsigned i;
    int ret;

    ut_params.name = "test3";
    handle         = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");

    /* Add */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_add_key(handle, &keys[i]);
        print_key_info("Add", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] < 0, "failed to add key (pos[%u]=%d)", i, pos[i]);
        expected_pos[i] = pos[i];
    }

    /* Lookup */
    for (i = 0; i < 5; i++)
        key_array[i] = &keys[i];

    ret = cne_hash_lookup_bulk(handle, &key_array[0], 5, (int32_t *)pos);
    if (ret == 0)
        for (i = 0; i < 5; i++) {
            print_key_info("Lkp", key_array[i], pos[i]);
            RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to find key (pos[%u]=%d)", i,
                            pos[i]);
        }

    /* Add - update */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_add_key(handle, &keys[i]);
        print_key_info("Add", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to add key (pos[%u]=%d)", i, pos[i]);
    }

    /* Lookup */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_lookup(handle, &keys[i]);
        print_key_info("Lkp", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to find key (pos[%u]=%d)", i, pos[i]);
    }

    /* Delete */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_del_key(handle, &keys[i]);
        print_key_info("Del", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to delete key (pos[%u]=%d)", i, pos[i]);
    }

    /* Lookup */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_lookup(handle, &keys[i]);
        print_key_info("Lkp", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != -ENOENT, "found non-existent key (pos[%u]=%d)", i, pos[i]);
    }

    /* Lookup multi */
    ret = cne_hash_lookup_bulk(handle, &key_array[0], 5, (int32_t *)pos);
    if (ret == 0)
        for (i = 0; i < 5; i++) {
            print_key_info("Lkp", key_array[i], pos[i]);
            RETURN_IF_ERROR(pos[i] != -ENOENT, "found not-existent key (pos[%u]=%d)", i, pos[i]);
        }

    cne_hash_free(handle);

    return 0;
}

/*
 * Add keys to the same bucket until bucket full.
 *	- add 5 keys to the same bucket (hash created with 4 keys per bucket):
 *	  first 4 successful, 5th successful, pushing existing item in bucket
 *	- lookup the 5 keys: 5 hits
 *	- add the 5 keys again: 5 OK
 *	- lookup the 5 keys: 5 hits (updated data)
 *	- delete the 5 keys: 5 OK
 *	- lookup the 5 keys: 5 misses
 */
static int
test_full_bucket(void)
{
    struct cne_hash_parameters params_pseudo_hash = {
        .name               = "test4",
        .entries            = 64,
        .key_len            = sizeof(struct flow_key), /* 13 */
        .hash_func          = pseudo_hash,
        .hash_func_init_val = 0,
        .socket_id          = 0,
    };
    struct cne_hash *handle;
    int pos[5];
    int expected_pos[5];
    unsigned i;

    handle = cne_hash_create(&params_pseudo_hash);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");

    /* Fill bucket */
    for (i = 0; i < 4; i++) {
        pos[i] = cne_hash_add_key(handle, &keys[i]);
        print_key_info("Add", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] < 0, "failed to add key (pos[%u]=%d)", i, pos[i]);
        expected_pos[i] = pos[i];
    }
    /*
     * This should work and will push one of the items
     * in the bucket because it is full
     */
    pos[4] = cne_hash_add_key(handle, &keys[4]);
    print_key_info("Add", &keys[4], pos[4]);
    RETURN_IF_ERROR(pos[4] < 0, "failed to add key (pos[4]=%d)", pos[4]);
    expected_pos[4] = pos[4];

    /* Lookup */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_lookup(handle, &keys[i]);
        print_key_info("Lkp", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to find key (pos[%u]=%d)", i, pos[i]);
    }

    /* Add - update */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_add_key(handle, &keys[i]);
        print_key_info("Add", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to add key (pos[%u]=%d)", i, pos[i]);
    }

    /* Lookup */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_lookup(handle, &keys[i]);
        print_key_info("Lkp", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to find key (pos[%u]=%d)", i, pos[i]);
    }

    /* Delete 1 key, check other keys are still found */
    pos[1] = cne_hash_del_key(handle, &keys[1]);
    print_key_info("Del", &keys[1], pos[1]);
    RETURN_IF_ERROR(pos[1] != expected_pos[1], "failed to delete key (pos[1]=%d)", pos[1]);
    pos[3] = cne_hash_lookup(handle, &keys[3]);
    print_key_info("Lkp", &keys[3], pos[3]);
    RETURN_IF_ERROR(pos[3] != expected_pos[3],
                    "failed lookup after deleting key from same bucket "
                    "(pos[3]=%d)",
                    pos[3]);

    /* Go back to previous state */
    pos[1] = cne_hash_add_key(handle, &keys[1]);
    print_key_info("Add", &keys[1], pos[1]);
    expected_pos[1] = pos[1];
    RETURN_IF_ERROR(pos[1] < 0, "failed to add key (pos[1]=%d)", pos[1]);

    /* Delete */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_del_key(handle, &keys[i]);
        print_key_info("Del", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to delete key (pos[%u]=%d)", i, pos[i]);
    }

    /* Lookup */
    for (i = 0; i < 5; i++) {
        pos[i] = cne_hash_lookup(handle, &keys[i]);
        print_key_info("Lkp", &keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != -ENOENT, "fail: found non-existent key (pos[%u]=%d)", i, pos[i]);
    }

    cne_hash_free(handle);

    /* Cover the NULL case. */
    cne_hash_free(0);
    return 0;
}

/*
 * Similar to the test above (full bucket test), but for extendable buckets.
 */
static int
test_extendable_bucket(void)
{
    // clang-format off
    struct cne_hash_parameters params_pseudo_hash = {
        .name      = "test5",
        .entries   = 64,
        .key_len   = sizeof(struct flow_key), /* 13 */
        .hash_func = pseudo_hash,
        .hash_func_init_val = 0,
        .socket_id          = 0,
        .extra_flag = CNE_HASH_EXTRA_FLAGS_EXT_TABLE
    };
    // clang-format on
    struct cne_hash *handle;
    int pos[64];
    int expected_pos[64];
    unsigned int i;
    struct flow_key rand_keys[64];

    for (i = 0; i < 64; i++) {
        rand_keys[i].port_dst = i;
        rand_keys[i].port_src = i + 1;
    }

    handle = cne_hash_create(&params_pseudo_hash);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");

    /* Fill bucket */
    for (i = 0; i < 64; i++) {
        pos[i] = cne_hash_add_key(handle, &rand_keys[i]);
        print_key_info("Add", &rand_keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] < 0, "failed to add key (pos[%u]=%d)", i, pos[i]);
        expected_pos[i] = pos[i];
    }

    /* Lookup */
    for (i = 0; i < 64; i++) {
        pos[i] = cne_hash_lookup(handle, &rand_keys[i]);
        print_key_info("Lkp", &rand_keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to find key (pos[%u]=%d)", i, pos[i]);
    }

    /* Add - update */
    for (i = 0; i < 64; i++) {
        pos[i] = cne_hash_add_key(handle, &rand_keys[i]);
        print_key_info("Add", &rand_keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to add key (pos[%u]=%d)", i, pos[i]);
    }

    /* Lookup */
    for (i = 0; i < 64; i++) {
        pos[i] = cne_hash_lookup(handle, &rand_keys[i]);
        print_key_info("Lkp", &rand_keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to find key (pos[%u]=%d)", i, pos[i]);
    }

    /* Delete 1 key, check other keys are still found */
    pos[35] = cne_hash_del_key(handle, &rand_keys[35]);
    print_key_info("Del", &rand_keys[35], pos[35]);
    RETURN_IF_ERROR(pos[35] != expected_pos[35], "failed to delete key (pos[1]=%d)", pos[35]);
    pos[20] = cne_hash_lookup(handle, &rand_keys[20]);
    print_key_info("Lkp", &rand_keys[20], pos[20]);
    RETURN_IF_ERROR(pos[20] != expected_pos[20],
                    "failed lookup after deleting key from same bucket "
                    "(pos[20]=%d)",
                    pos[20]);

    /* Go back to previous state */
    pos[35] = cne_hash_add_key(handle, &rand_keys[35]);
    print_key_info("Add", &rand_keys[35], pos[35]);
    expected_pos[35] = pos[35];
    RETURN_IF_ERROR(pos[35] < 0, "failed to add key (pos[1]=%d)", pos[35]);

    /* Delete */
    for (i = 0; i < 64; i++) {
        pos[i] = cne_hash_del_key(handle, &rand_keys[i]);
        print_key_info("Del", &rand_keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != expected_pos[i], "failed to delete key (pos[%u]=%d)", i, pos[i]);
    }

    /* Lookup */
    for (i = 0; i < 64; i++) {
        pos[i] = cne_hash_lookup(handle, &rand_keys[i]);
        print_key_info("Lkp", &rand_keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] != -ENOENT, "fail: found non-existent key (pos[%u]=%d)", i, pos[i]);
    }

    /* Add again */
    for (i = 0; i < 64; i++) {
        pos[i] = cne_hash_add_key(handle, &rand_keys[i]);
        print_key_info("Add", &rand_keys[i], pos[i]);
        RETURN_IF_ERROR(pos[i] < 0, "failed to add key (pos[%u]=%d)", i, pos[i]);
        expected_pos[i] = pos[i];
    }

    cne_hash_free(handle);

    /* Cover the NULL case. */
    cne_hash_free(0);
    return 0;
}

/******************************************************************************/
static int
fbk_hash_unit_test(void)
{
    struct cne_fbk_hash_params params = {
        .name               = "fbk_hash_test",
        .entries            = LOCAL_FBK_HASH_ENTRIES_MAX,
        .entries_per_bucket = 4,
        .socket_id          = 0,
    };

    struct cne_fbk_hash_params invalid_params_1 = {
        .name               = "invalid_1",
        .entries            = LOCAL_FBK_HASH_ENTRIES_MAX + 1, /* Not power of 2 */
        .entries_per_bucket = 4,
        .socket_id          = 0,
    };

    struct cne_fbk_hash_params invalid_params_2 = {
        .name               = "invalid_2",
        .entries            = 4,
        .entries_per_bucket = 3, /* Not power of 2 */
        .socket_id          = 0,
    };

    struct cne_fbk_hash_params invalid_params_3 = {
        .name               = "invalid_3",
        .entries            = 0, /* Entries is 0 */
        .entries_per_bucket = 4,
        .socket_id          = 0,
    };

    struct cne_fbk_hash_params invalid_params_4 = {
        .name               = "invalid_4",
        .entries            = LOCAL_FBK_HASH_ENTRIES_MAX,
        .entries_per_bucket = 0, /* Entries per bucket is 0 */
        .socket_id          = 0,
    };

    struct cne_fbk_hash_params invalid_params_5 = {
        .name               = "invalid_5",
        .entries            = 4,
        .entries_per_bucket = 8, /* Entries per bucket > entries */
        .socket_id          = 0,
    };

    struct cne_fbk_hash_params invalid_params_6 = {
        .name               = "invalid_6",
        .entries            = CNE_FBK_HASH_ENTRIES_MAX * 2, /* Entries > max allowed */
        .entries_per_bucket = 4,
        .socket_id          = 0,
    };

    struct cne_fbk_hash_params invalid_params_7 = {
        .name               = "invalid_7",
        .entries            = CNE_FBK_HASH_ENTRIES_MAX,
        .entries_per_bucket = CNE_FBK_HASH_ENTRIES_PER_BUCKET_MAX * 2, /* Entries > max allowed */
        .socket_id          = 0,
    };

    /* try to create two hashes with identical names
     * in this case, trying to create a second one will not
     * fail but will simply return pointer to the existing
     * hash with that name. sort of like a "find hash by name" :-)
     */
    struct cne_fbk_hash_params invalid_params_same_name_1 = {
        .name               = "same_name", /* hash with identical name */
        .entries            = 4,
        .entries_per_bucket = 2,
        .socket_id          = 0,
    };

    /* this is a sanity check for "same name" test
     * creating this hash will check if we are actually able to create
     * multiple hashes with different names (instead of having just one).
     */
    struct cne_fbk_hash_params different_name = {
        .name               = "different_name", /* different name */
        .entries            = LOCAL_FBK_HASH_ENTRIES_MAX,
        .entries_per_bucket = 4,
        .socket_id          = 0,
    };

    struct cne_fbk_hash_params params_jhash = {
        .name               = "valid",
        .entries            = LOCAL_FBK_HASH_ENTRIES_MAX,
        .entries_per_bucket = 4,
        .socket_id          = 0,
        .hash_func          = cne_jhash_1word, /* Tests for different hash_func */
        .init_val           = CNE_FBK_HASH_INIT_VAL_DEFAULT,
    };

    struct cne_fbk_hash_params params_nohash = {
        .name               = "valid nohash",
        .entries            = LOCAL_FBK_HASH_ENTRIES_MAX,
        .entries_per_bucket = 4,
        .socket_id          = 0,
        .hash_func          = NULL, /* Tests for null hash_func */
        .init_val           = CNE_FBK_HASH_INIT_VAL_DEFAULT,
    };

    struct cne_fbk_hash_table *handle, *tmp;
    uint32_t keys[5] = {0xc6e18639, 0xe67c201c, 0xd4c8cffd, 0x44728691, 0xd5430fa9};
    uint16_t vals[5] = {28108, 5699, 38490, 2166, 61571};
    int status;
    unsigned i;
    double used_entries;

    /* Try creating hashes with invalid parameters */
    tst_info("Testing hash creation with invalid parameters - expect error msgs");
    handle = cne_fbk_hash_create(&invalid_params_1);
    RETURN_IF_ERROR_FBK(handle != NULL, "fbk hash creation should have failed");

    handle = cne_fbk_hash_create(&invalid_params_2);
    RETURN_IF_ERROR_FBK(handle != NULL, "fbk hash creation should have failed");

    handle = cne_fbk_hash_create(&invalid_params_3);
    RETURN_IF_ERROR_FBK(handle != NULL, "fbk hash creation should have failed");

    handle = cne_fbk_hash_create(&invalid_params_4);
    RETURN_IF_ERROR_FBK(handle != NULL, "fbk hash creation should have failed");

    handle = cne_fbk_hash_create(&invalid_params_5);
    RETURN_IF_ERROR_FBK(handle != NULL, "fbk hash creation should have failed");

    handle = cne_fbk_hash_create(&invalid_params_6);
    RETURN_IF_ERROR_FBK(handle != NULL, "fbk hash creation should have failed");

    handle = cne_fbk_hash_create(&invalid_params_7);
    RETURN_IF_ERROR_FBK(handle != NULL, "fbk hash creation should have failed");

    handle = cne_fbk_hash_create(&invalid_params_same_name_1);
    RETURN_IF_ERROR_FBK(handle == NULL, "fbk hash creation should have succeeded");

    /* we are not freeing  handle here because we need a hash list
     * to be not empty for the next test */

    /* create a hash in non-empty list - good for coverage */
    tmp = cne_fbk_hash_create(&different_name);
    RETURN_IF_ERROR_FBK(tmp == NULL, "fbk hash creation should have succeeded");

    /* free both hashes */
    cne_fbk_hash_free(handle);
    cne_fbk_hash_free(tmp);

    /* Create empty jhash hash. */
    handle = cne_fbk_hash_create(&params_jhash);
    RETURN_IF_ERROR_FBK(handle == NULL, "fbk jhash hash creation failed");

    /* Cleanup. */
    cne_fbk_hash_free(handle);

    /* Create empty jhash hash. */
    handle = cne_fbk_hash_create(&params_nohash);
    RETURN_IF_ERROR_FBK(handle == NULL, "fbk nohash hash creation failed");

    /* Cleanup. */
    cne_fbk_hash_free(handle);

    /* Create empty hash. */
    handle = cne_fbk_hash_create(&params);
    RETURN_IF_ERROR_FBK(handle == NULL, "fbk hash creation failed");

    used_entries = cne_fbk_hash_get_load_factor(handle) * LOCAL_FBK_HASH_ENTRIES_MAX;
    RETURN_IF_ERROR_FBK((unsigned)used_entries != 0,
                        "load factor right after creation is not zero but it should be");
    /* Add keys. */
    for (i = 0; i < 5; i++) {
        status = cne_fbk_hash_add_key(handle, keys[i], vals[i]);
        RETURN_IF_ERROR_FBK(status != 0, "fbk hash add failed");
    }

    used_entries = cne_fbk_hash_get_load_factor(handle) * LOCAL_FBK_HASH_ENTRIES_MAX;
    RETURN_IF_ERROR_FBK(
        (unsigned)used_entries !=
            (unsigned)((((double)5) / LOCAL_FBK_HASH_ENTRIES_MAX) * LOCAL_FBK_HASH_ENTRIES_MAX),
        "load factor now is not as expected");
    /* Find value of added keys. */
    for (i = 0; i < 5; i++) {
        status = cne_fbk_hash_lookup(handle, keys[i]);
        RETURN_IF_ERROR_FBK(status != vals[i], "fbk hash lookup failed");
    }

    /* Change value of added keys. */
    for (i = 0; i < 5; i++) {
        status = cne_fbk_hash_add_key(handle, keys[i], vals[4 - i]);
        RETURN_IF_ERROR_FBK(status != 0, "fbk hash update failed");
    }

    /* Find new values. */
    for (i = 0; i < 5; i++) {
        status = cne_fbk_hash_lookup(handle, keys[i]);
        RETURN_IF_ERROR_FBK(status != vals[4 - i], "fbk hash lookup failed");
    }

    /* Delete keys individually. */
    for (i = 0; i < 5; i++) {
        status = cne_fbk_hash_delete_key(handle, keys[i]);
        RETURN_IF_ERROR_FBK(status != 0, "fbk hash delete failed");
    }

    used_entries = cne_fbk_hash_get_load_factor(handle) * LOCAL_FBK_HASH_ENTRIES_MAX;
    RETURN_IF_ERROR_FBK((unsigned)used_entries != 0,
                        "load factor right after deletion is not zero but it should be");
    /* Lookup should now fail. */
    for (i = 0; i < 5; i++) {
        status = cne_fbk_hash_lookup(handle, keys[i]);
        RETURN_IF_ERROR_FBK(status == 0, "fbk hash lookup should have failed");
    }

    /* Add keys again. */
    for (i = 0; i < 5; i++) {
        status = cne_fbk_hash_add_key(handle, keys[i], vals[i]);
        RETURN_IF_ERROR_FBK(status != 0, "fbk hash add failed");
    }

    /* Make sure they were added. */
    for (i = 0; i < 5; i++) {
        status = cne_fbk_hash_lookup(handle, keys[i]);
        RETURN_IF_ERROR_FBK(status != vals[i], "fbk hash lookup failed");
    }

    /* Clear all entries. */
    cne_fbk_hash_clear_all(handle);

    /* Lookup should fail. */
    for (i = 0; i < 5; i++) {
        status = cne_fbk_hash_lookup(handle, keys[i]);
        RETURN_IF_ERROR_FBK(status == 0, "fbk hash lookup should have failed");
    }

    /* coverage */

    /* fill up the hash_table */
    for (i = 0; i < CNE_FBK_HASH_ENTRIES_MAX + 1; i++)
        cne_fbk_hash_add_key(handle, i, (uint16_t)i);

    /* Find non-existent key in a full hashtable */
    status = cne_fbk_hash_lookup(handle, CNE_FBK_HASH_ENTRIES_MAX + 1);
    RETURN_IF_ERROR_FBK(status != -ENOENT, "fbk hash lookup succeeded");

    /* Delete non-existent key in a full hashtable */
    status = cne_fbk_hash_delete_key(handle, CNE_FBK_HASH_ENTRIES_MAX + 1);
    RETURN_IF_ERROR_FBK(status != -ENOENT, "fbk hash delete succeeded");

    /* Delete one key from a full hashtable */
    status = cne_fbk_hash_delete_key(handle, 1);
    RETURN_IF_ERROR_FBK(status != 0, "fbk hash delete failed");

    /* Clear all entries. */
    cne_fbk_hash_clear_all(handle);

    /* Cleanup. */
    cne_fbk_hash_free(handle);

    /* Cover the NULL case. */
    cne_fbk_hash_free(0);

    return 0;
}

#define BUCKET_ENTRIES 4
/*
 * Do tests for hash creation with bad parameters.
 */
static int
test_hash_creation_with_bad_parameters(void)
{
    struct cne_hash *handle;
    struct cne_hash_parameters params;

    handle = cne_hash_create(NULL);
    if (handle != NULL) {
        cne_hash_free(handle);
        tst_error("Impossible creating hash successfully without any parameter");
        return -1;
    }

    memcpy(&params, &ut_params, sizeof(params));
    params.name    = "creation_with_bad_parameters_0";
    params.entries = CNE_HASH_ENTRIES_MAX + 1;
    handle         = cne_hash_create(&params);
    if (handle != NULL) {
        cne_hash_free(handle);
        tst_error("Impossible creating hash successfully with entries in parameter exceeded");
        return -1;
    }

    memcpy(&params, &ut_params, sizeof(params));
    params.name    = "creation_with_bad_parameters_2";
    params.entries = BUCKET_ENTRIES - 1;
    handle         = cne_hash_create(&params);
    if (handle != NULL) {
        cne_hash_free(handle);
        tst_error("Impossible creating hash successfully if entries less than bucket_entries in "
                  "parameter");
        return -1;
    }

    memcpy(&params, &ut_params, sizeof(params));
    params.name    = "creation_with_bad_parameters_3";
    params.key_len = 0;
    handle         = cne_hash_create(&params);
    if (handle != NULL) {
        cne_hash_free(handle);
        tst_error("Impossible creating hash successfully if key_len in parameter is zero");
        return -1;
    }

    /* test with same name should fail */
    memcpy(&params, &ut_params, sizeof(params));
    params.name = "same_name";
    handle      = cne_hash_create(&params);
    if (handle == NULL) {
        tst_error("Cannot create first hash table with 'same_name'");
        return -1;
    }
    cne_hash_free(handle);

    tst_ok("Test successful. No more errors expected");

    return 0;
}

/*
 * Do tests for hash creation with parameters that look incorrect
 * but are actually valid.
 */
static int
test_hash_creation_with_good_parameters(void)
{
    struct cne_hash *handle;
    struct cne_hash_parameters params;

    /* create with null hash function - should choose DEFAULT_HASH_FUNC */
    memcpy(&params, &ut_params, sizeof(params));
    params.name      = "name";
    params.hash_func = NULL;
    handle           = cne_hash_create(&params);
    if (handle == NULL) {
        tst_error("Creating hash with null hash_func failed");
        return -1;
    }

    cne_hash_free(handle);

    return 0;
}

#define ITERATIONS 3
/*
 * Test to see the average table utilization (entries added/max entries)
 * before hitting a random entry that cannot be added
 */
static int
test_average_table_utilization(uint32_t ext_table)
{
    struct cne_hash *handle;
    uint8_t simple_key[MAX_KEYSIZE];
    unsigned i, j;
    unsigned added_keys, average_keys_added = 0;
    int ret;
    unsigned int cnt;

    tst_info("Running test to determine average utilization"
             " before adding elements begins to fail");
    if (ext_table)
        tst_info("ext table is enabled");
    else
        tst_info("ext table is disabled");

    tst_info("Measuring performance, please wait");
    fflush(stdout);
    ut_params.entries   = 1 << 16;
    ut_params.name      = "test_average_utilization";
    ut_params.hash_func = cne_jhash;
    if (ext_table)
        ut_params.extra_flag |= CNE_HASH_EXTRA_FLAGS_EXT_TABLE;
    else
        ut_params.extra_flag &= ~CNE_HASH_EXTRA_FLAGS_EXT_TABLE;

    handle = cne_hash_create(&ut_params);

    RETURN_IF_ERROR(handle == NULL, "hash creation failed");

    for (j = 0; j < ITERATIONS; j++) {
        ret = 0;
        /* Add random entries until key cannot be added */
        for (added_keys = 0; ret >= 0; added_keys++) {
            for (i = 0; i < ut_params.key_len; i++)
                simple_key[i] = rand() % 255;
            ret = cne_hash_add_key(handle, simple_key);
            if (ret < 0)
                break;
        }

        if (ret != -ENOSPC) {
            CNE_ERR("Unexpected error when adding keys\n");
            cne_hash_free(handle);
            return -1;
        }

        cnt = cne_hash_count(handle);
        if (cnt != added_keys) {
            CNE_ERR("cne_hash_count returned wrong value %u, %u,%u\n", j, added_keys, cnt);
            cne_hash_free(handle);
            return -1;
        }
        if (ext_table) {
            if (cnt != ut_params.entries) {
                CNE_ERR("cne_hash_count returned wrong value %u, %u, %u\n", j, added_keys, cnt);
                cne_hash_free(handle);
                return -1;
            }
        }

        average_keys_added += added_keys;

        /* Reset the table */
        cne_hash_reset(handle);

        /* Print a dot to show progress on operations */
        cne_printf(".");
        fflush(stdout);
    }

    average_keys_added /= ITERATIONS;

    tst_info("\nAverage table utilization = %.2f%% (%u/%u)",
             ((double)average_keys_added / ut_params.entries * 100), average_keys_added,
             ut_params.entries);
    cne_hash_free(handle);

    return 0;
}

#define NUM_ENTRIES 256
static int
test_hash_iteration(uint32_t ext_table)
{
    struct cne_hash *handle;
    unsigned i;
    uint8_t keys[NUM_ENTRIES][MAX_KEYSIZE];
    const void *next_key;
    void *next_data;
    void *data[NUM_ENTRIES];
    unsigned added_keys;
    uint32_t iter = 0;
    int ret       = 0;

    ut_params.entries   = NUM_ENTRIES;
    ut_params.name      = "test_hash_iteration";
    ut_params.hash_func = cne_jhash;
    ut_params.key_len   = 16;
    if (ext_table)
        ut_params.extra_flag |= CNE_HASH_EXTRA_FLAGS_EXT_TABLE;
    else
        ut_params.extra_flag &= ~CNE_HASH_EXTRA_FLAGS_EXT_TABLE;

    handle = cne_hash_create(&ut_params);
    RETURN_IF_ERROR(handle == NULL, "hash creation failed");

    /* Add random entries until key cannot be added */
    for (added_keys = 0; added_keys < NUM_ENTRIES; added_keys++) {
        data[added_keys] = (void *)((uintptr_t)rand());
        for (i = 0; i < ut_params.key_len; i++)
            keys[added_keys][i] = rand() % 255;
        ret = cne_hash_add_key_data(handle, keys[added_keys], data[added_keys]);
        if (ret < 0) {
            if (ext_table) {
                tst_error("Insertion failed for ext table");
                goto err;
            }
            break;
        }
    }

    /* Iterate through the hash table */
    while (cne_hash_iterate(handle, &next_key, &next_data, &iter) >= 0) {
        /* Search for the key in the list of keys added */
        for (i = 0; i < NUM_ENTRIES; i++) {
            if (memcmp(next_key, keys[i], ut_params.key_len) == 0) {
                if (next_data != data[i]) {
                    tst_error("Data found in the hash table is"
                              "not the data added with the key");
                    goto err;
                }
                added_keys--;
                break;
            }
        }
        if (i == NUM_ENTRIES) {
            tst_error("Key found in the hash table was not added");
            goto err;
        }
    }

    /* Check if all keys have been iterated */
    if (added_keys != 0) {
        tst_error("There were still %u keys to iterate", added_keys);
        goto err;
    }

    cne_hash_free(handle);
    return 0;

err:
    tst_error("tst_hash_iteration() failed");

    cne_hash_free(handle);
    return -1;
}

// clang-format off
static uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static struct cne_hash_parameters hash_params_ex = {
    .name               = NULL,
    .entries            = 64,
    .key_len            = 0,
    .hash_func          = NULL,
    .hash_func_init_val = 0,
    .socket_id          = 0,
};
// clang-format on

/*
 * add/delete key with jhash2
 */
static int
test_hash_add_delete_jhash2(void)
{
    int ret = -1;
    struct cne_hash *handle;
    int32_t pos1, pos2;

    hash_params_ex.name      = "hash_test_jhash2";
    hash_params_ex.key_len   = 4;
    hash_params_ex.hash_func = (cne_hash_function)cne_jhash_32b;

    handle = cne_hash_create(&hash_params_ex);
    if (handle == NULL) {
        tst_error("test_hash_add_delete_jhash2 fail to create hash");
        goto fail_jhash2;
    }
    pos1 = cne_hash_add_key(handle, (void *)&key[0]);
    if (pos1 < 0) {
        tst_error("test_hash_add_delete_jhash2 fail to add hash key");
        goto fail_jhash2;
    }

    pos2 = cne_hash_del_key(handle, (void *)&key[0]);
    if (pos2 < 0 || pos1 != pos2) {
        tst_error("test_hash_add_delete_jhash2 delete different key from being added");
        goto fail_jhash2;
    }
    ret = 0;

fail_jhash2:
    if (handle != NULL)
        cne_hash_free(handle);

    return ret;
}

/*
 * add/delete (2) key with jhash2
 */
static int
test_hash_add_delete_2_jhash2(void)
{
    int ret = -1;
    struct cne_hash *handle;
    int32_t pos1, pos2;

    hash_params_ex.name      = "hash_test_2_jhash2";
    hash_params_ex.key_len   = 8;
    hash_params_ex.hash_func = (cne_hash_function)cne_jhash_32b;

    handle = cne_hash_create(&hash_params_ex);
    if (handle == NULL)
        goto fail_2_jhash2;

    pos1 = cne_hash_add_key(handle, (void *)&key[0]);
    if (pos1 < 0)
        goto fail_2_jhash2;

    pos2 = cne_hash_del_key(handle, (void *)&key[0]);
    if (pos2 < 0 || pos1 != pos2)
        goto fail_2_jhash2;

    ret = 0;

fail_2_jhash2:
    if (handle != NULL)
        cne_hash_free(handle);

    return ret;
}

static uint32_t
test_hash_jhash_1word(const void *key, uint32_t length, uint32_t initval)
{
    const uint32_t *k = key;

    CNE_SET_USED(length);

    return cne_jhash_1word(k[0], initval);
}

static uint32_t
test_hash_jhash_2word(const void *key, uint32_t length, uint32_t initval)
{
    const uint32_t *k = key;

    CNE_SET_USED(length);

    return cne_jhash_2words(k[0], k[1], initval);
}

static uint32_t
test_hash_jhash_3word(const void *key, uint32_t length, uint32_t initval)
{
    const uint32_t *k = key;

    CNE_SET_USED(length);

    return cne_jhash_3words(k[0], k[1], k[2], initval);
}

/*
 * add/delete key with jhash 1word
 */
static int
test_hash_add_delete_jhash_1word(void)
{
    int ret = -1;
    struct cne_hash *handle;
    int32_t pos1, pos2;

    hash_params_ex.name      = "hash_test_jhash_1word";
    hash_params_ex.key_len   = 4;
    hash_params_ex.hash_func = test_hash_jhash_1word;

    handle = cne_hash_create(&hash_params_ex);
    if (handle == NULL)
        goto fail_jhash_1word;

    pos1 = cne_hash_add_key(handle, (void *)&key[0]);
    if (pos1 < 0)
        goto fail_jhash_1word;

    pos2 = cne_hash_del_key(handle, (void *)&key[0]);
    if (pos2 < 0 || pos1 != pos2)
        goto fail_jhash_1word;

    ret = 0;

fail_jhash_1word:
    if (handle != NULL)
        cne_hash_free(handle);

    return ret;
}

/*
 * add/delete key with jhash 2word
 */
static int
test_hash_add_delete_jhash_2word(void)
{
    int ret = -1;
    struct cne_hash *handle;
    int32_t pos1, pos2;

    hash_params_ex.name      = "hash_test_jhash_2word";
    hash_params_ex.key_len   = 8;
    hash_params_ex.hash_func = test_hash_jhash_2word;

    handle = cne_hash_create(&hash_params_ex);
    if (handle == NULL)
        goto fail_jhash_2word;

    pos1 = cne_hash_add_key(handle, (void *)&key[0]);
    if (pos1 < 0)
        goto fail_jhash_2word;

    pos2 = cne_hash_del_key(handle, (void *)&key[0]);
    if (pos2 < 0 || pos1 != pos2)
        goto fail_jhash_2word;

    ret = 0;

fail_jhash_2word:
    if (handle != NULL)
        cne_hash_free(handle);

    return ret;
}

/*
 * add/delete key with jhash 3word
 */
static int
test_hash_add_delete_jhash_3word(void)
{
    int ret = -1;
    struct cne_hash *handle;
    int32_t pos1, pos2;

    hash_params_ex.name      = "hash_test_jhash_3word";
    hash_params_ex.key_len   = 12;
    hash_params_ex.hash_func = test_hash_jhash_3word;

    handle = cne_hash_create(&hash_params_ex);
    if (handle == NULL)
        goto fail_jhash_3word;

    pos1 = cne_hash_add_key(handle, (void *)&key[0]);
    if (pos1 < 0)
        goto fail_jhash_3word;

    pos2 = cne_hash_del_key(handle, (void *)&key[0]);
    if (pos2 < 0 || pos1 != pos2)
        goto fail_jhash_3word;

    ret = 0;

fail_jhash_3word:
    if (handle != NULL)
        cne_hash_free(handle);

    return ret;
}

struct flow_key g_rand_keys[9];

/*
 * Do all unit and performance tests.
 */
static int
test_hash(void)
{
    if (test_add_delete() < 0)
        return -1;
    if (test_hash_add_delete_jhash2() < 0)
        return -1;
    if (test_hash_add_delete_2_jhash2() < 0)
        return -1;
    if (test_hash_add_delete_jhash_1word() < 0)
        return -1;
    if (test_hash_add_delete_jhash_2word() < 0)
        return -1;
    if (test_hash_add_delete_jhash_3word() < 0)
        return -1;
    if (test_hash_get_key_with_position() < 0)
        return -1;
    if (test_add_update_delete() < 0)
        return -1;
    if (test_add_update_delete_free() < 0)
        return -1;
    if (test_add_delete_free_lf() < 0)
        return -1;
    if (test_five_keys() < 0)
        return -1;
    if (test_full_bucket() < 0)
        return -1;
    if (test_extendable_bucket() < 0)
        return -1;

    if (fbk_hash_unit_test() < 0)
        return -1;
    if (test_hash_creation_with_bad_parameters() < 0)
        return -1;
    if (test_hash_creation_with_good_parameters() < 0)
        return -1;

    /* ext table disabled */
    if (test_average_table_utilization(0) < 0)
        return -1;
    if (test_hash_iteration(0) < 0)
        return -1;

    /* ext table enabled */
    if (test_average_table_utilization(1) < 0)
        return -1;
    if (test_hash_iteration(1) < 0)
        return -1;

    run_hash_func_tests();

    if (test_crc32_hash_alg_equiv() < 0)
        return -1;

    return 0;
}

int
hash_main(int argc, char **argv)
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

    tst = tst_start("Hash");

    if (test_hash() < 0)
        goto leave;

    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_end(tst, TST_FAILED);
    return -1;
}
