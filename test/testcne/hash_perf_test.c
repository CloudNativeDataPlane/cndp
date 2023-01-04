/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2015 Intel Corporation
 */

#include <stdio.h>               // for NULL, fflush, snprintf, stdout, EOF
#include <inttypes.h>            // for PRIu64
#include <cne_cycles.h>          // for cne_rdtsc
#include <cne_hash.h>            // for hash_sig_t, cne_hash_parameters, cne_hash_...
#include <cne_jhash.h>           // for cne_jhash
#include <cne_fbk_hash.h>        // for cne_fbk_hash_add_key, cne_fbk_hash_create
#include <tst_info.h>            // for tst_end, tst_start, TST_FAILED, TST_PASSED
#include <getopt.h>              // for getopt_long, option
#include <stdint.h>              // for int32_t, uint64_t, uint8_t, uint32_t, uint...
#include <stdlib.h>              // for rand, free, calloc
#include <string.h>              // for memcpy, memset, strndup

#include "hash_test.h"         // for hash_perf_main
#include "cne_stdio.h"         // for cne_printf
#include "cne_system.h"        // for cne_lcore_id, cne_socket_id

struct cne_hash;

#define MAX_ENTRIES (1 << 19)
#define KEYS_TO_ADD (MAX_ENTRIES)
#define ADD_PERCENT 0.75              /* 75% table utilization */
#define NUM_LOOKUPS (KEYS_TO_ADD * 5) /* Loop among keys added, several times */
/* BUCKET_SIZE should be same as CNE_HASH_BUCKET_ENTRIES in cne_hash library */
#define BUCKET_SIZE  8
#define NUM_BUCKETS  (MAX_ENTRIES / BUCKET_SIZE)
#define MAX_KEYSIZE  64
#define NUM_KEYSIZES 10
#define NUM_SHUFFLES 10
#define BURST_SIZE   16

enum operations { ADD = 0, LOOKUP, LOOKUP_MULTI, DELETE, NUM_OPERATIONS };

static uint32_t hashtest_key_lens[] = {
    /* standard key sizes */
    4, 8, 16, 32, 48, 64,
    /* IPv4 SRC + DST + protocol, unpadded */
    9,
    /* IPv4 5-tuple, unpadded */
    13,
    /* IPv6 5-tuple, unpadded */
    37,
    /* IPv6 5-tuple, padded to 8-byte boundary */
    40};

struct cne_hash *htables[NUM_KEYSIZES];

/* Array that stores if a slot is full */
static uint8_t slot_taken[MAX_ENTRIES];

/* Array to store number of cycles per operation */
static uint64_t cycles[NUM_KEYSIZES][NUM_OPERATIONS][2][2];

/* Array to store all input keys */
static uint8_t keys[KEYS_TO_ADD][MAX_KEYSIZE];

/* Array to store the precomputed hash for 'keys' */
static hash_sig_t signatures[KEYS_TO_ADD];

/* Array to store how many busy entries have each bucket */
static uint8_t buckets[NUM_BUCKETS];

/* Array to store the positions where keys are added */
static int32_t positions[KEYS_TO_ADD];

/* Parameters used for hash table in unit test functions. */
static struct cne_hash_parameters ut_params = {
    .entries            = MAX_ENTRIES,
    .hash_func          = cne_jhash,
    .hash_func_init_val = 0,
};

static void
free_table(unsigned table_index)
{
    if (htables[table_index])
        cne_hash_free(htables[table_index]);
    htables[table_index] = NULL;
}

static void
reset_table(unsigned table_index)
{
    cne_hash_reset(htables[table_index]);
}

static int
create_table(unsigned int with_data, unsigned int table_index, unsigned int ext)
{
    char name[CNE_HASH_NAMESIZE + 1] = {0};

    if (with_data)
        /* Table will store 8-byte data */
        snprintf(name, sizeof(name), "test_hash%u_data", hashtest_key_lens[table_index]);
    else
        snprintf(name, sizeof(name), "test_hash%u", hashtest_key_lens[table_index]);

    ut_params.extra_flag = 0;

    if (ext)
        ut_params.extra_flag |= CNE_HASH_EXTRA_FLAGS_EXT_TABLE;

    ut_params.name      = strndup(name, CNE_HASH_NAMESIZE);
    ut_params.key_len   = hashtest_key_lens[table_index];
    ut_params.socket_id = cne_socket_id(cne_lcore_id());
    /*
     * If table was already created, free it to create it again,
     * so we force it is empty
     */
    free_table(table_index);
    htables[table_index] = cne_hash_create(&ut_params);
    if (htables[table_index] == NULL) {
        tst_error("Error creating table");
        free((void *)(uintptr_t)ut_params.name);
        return -1;
    }
    free((void *)(uintptr_t)ut_params.name);
    return 0;
}

/* Shuffle the keys that have been added, so lookups will be totally random */
static void
shuffle_input_keys(unsigned int table_index, unsigned int ext)
{
    unsigned i;
    uint32_t swap_idx;
    uint8_t temp_key[MAX_KEYSIZE];
    hash_sig_t temp_signature;
    int32_t temp_position;
    unsigned int keys_to_add;

    if (!ext)
        keys_to_add = KEYS_TO_ADD * ADD_PERCENT;
    else
        keys_to_add = KEYS_TO_ADD;

    for (i = keys_to_add - 1; i > 0; i--) {
        swap_idx = rand() % i;

        memcpy(temp_key, keys[i], hashtest_key_lens[table_index]);
        temp_signature = signatures[i];
        temp_position  = positions[i];

        memcpy(keys[i], keys[swap_idx], hashtest_key_lens[table_index]);
        signatures[i] = signatures[swap_idx];
        positions[i]  = positions[swap_idx];

        memcpy(keys[swap_idx], temp_key, hashtest_key_lens[table_index]);
        signatures[swap_idx] = temp_signature;
        positions[swap_idx]  = temp_position;
    }
}

/*
 * Looks for random keys which
 * ALL can fit in hash table (no errors)
 */
static int
get_input_keys(unsigned int with_pushes, unsigned int table_index, unsigned int ext)
{
    unsigned i, j;
    unsigned bucket_idx, incr, success = 1;
    uint8_t k = 0;
    int32_t ret;
    const uint32_t bucket_bitmask = NUM_BUCKETS - 1;
    unsigned int keys_to_add;

    if (!ext)
        keys_to_add = KEYS_TO_ADD * ADD_PERCENT;
    else
        keys_to_add = KEYS_TO_ADD;
    /* Reset all arrays */
    for (i = 0; i < MAX_ENTRIES; i++)
        slot_taken[i] = 0;

    for (i = 0; i < NUM_BUCKETS; i++)
        buckets[i] = 0;

    for (j = 0; j < hashtest_key_lens[table_index]; j++)
        keys[0][j] = 0;

    /*
     * Add only entries that are not duplicated and that fits in the table
     * (cannot store more than BUCKET_SIZE entries in a bucket).
     * Regardless a key has been added correctly or not (success),
     * the next one to try will be increased by 1.
     */
    for (i = 0; i < keys_to_add;) {
        incr = 0;
        if (i != 0) {
            keys[i][0] = ++k;
            /* Overflow, need to increment the next byte */
            if (keys[i][0] == 0)
                incr = 1;
            for (j = 1; j < hashtest_key_lens[table_index]; j++) {
                /* Do not increase next byte */
                if (incr == 0) {
                    if (success == 1)
                        keys[i][j] = keys[i - 1][j];
                    /* Increase next byte by one */
                } else {
                    if (success == 1)
                        keys[i][j] = keys[i - 1][j] + 1;
                    else
                        keys[i][j] = keys[i][j] + 1;
                    if (keys[i][j] == 0)
                        incr = 1;
                    else
                        incr = 0;
                }
            }
        }
        success       = 0;
        signatures[i] = cne_hash_hash(htables[table_index], keys[i]);
        bucket_idx    = signatures[i] & bucket_bitmask;
        /*
         * If we are not inserting keys in secondary location,
         * when bucket is full, do not try to insert the key
         */
        if (with_pushes == 0)
            if (buckets[bucket_idx] == BUCKET_SIZE)
                continue;

        /* If key can be added, leave in successful key arrays "keys" */
        ret = cne_hash_add_key_with_hash(htables[table_index], keys[i], signatures[i]);
        if (ret >= 0) {
            /* If key is already added, ignore the entry and do not store */
            if (slot_taken[ret])
                continue;
            else {
                /* Store the returned position and mark slot as taken */
                slot_taken[ret] = 1;
                positions[i]    = ret;
                buckets[bucket_idx]++;
                success = 1;
                i++;
            }
        }
    }

    /* Reset the table, so we can measure the time to add all the entries */
    free_table(table_index);
    htables[table_index] = cne_hash_create(&ut_params);

    return 0;
}

static int
timed_adds(unsigned int with_hash, unsigned int with_data, unsigned int table_index,
           unsigned int ext)
{
    unsigned i;
    const uint64_t start_tsc = cne_rdtsc();
    void *data;
    int32_t ret;
    unsigned int keys_to_add;
    if (!ext)
        keys_to_add = KEYS_TO_ADD * ADD_PERCENT;
    else
        keys_to_add = KEYS_TO_ADD;

    for (i = 0; i < keys_to_add; i++) {
        data = (void *)((uintptr_t)signatures[i]);
        if (with_hash && with_data) {
            ret = cne_hash_add_key_with_hash_data(htables[table_index], (const void *)keys[i],
                                                  signatures[i], data);
            if (ret < 0) {
                tst_error("H+D: Failed to add key number %u", i);
                return -1;
            }
        } else if (with_hash && !with_data) {
            ret = cne_hash_add_key_with_hash(htables[table_index], (const void *)keys[i],
                                             signatures[i]);
            if (ret >= 0)
                positions[i] = ret;
            else {
                tst_error("H: Failed to add key number %u", i);
                return -1;
            }
        } else if (!with_hash && with_data) {
            ret = cne_hash_add_key_data(htables[table_index], (const void *)keys[i], data);
            if (ret < 0) {
                tst_error("D: Failed to add key number %u", i);
                return -1;
            }
        } else {
            ret = cne_hash_add_key(htables[table_index], keys[i]);
            if (ret >= 0)
                positions[i] = ret;
            else {
                tst_error("Failed to add key number %u", i);
                return -1;
            }
        }
    }

    const uint64_t end_tsc    = cne_rdtsc();
    const uint64_t time_taken = end_tsc - start_tsc;

    cycles[table_index][ADD][with_hash][with_data] = time_taken / keys_to_add;

    return 0;
}

static int
timed_lookups(unsigned int with_hash, unsigned int with_data, unsigned int table_index,
              unsigned int ext)
{
    unsigned i, j;
    const uint64_t start_tsc = cne_rdtsc();
    void *ret_data;
    void *expected_data;
    int32_t ret;
    unsigned int keys_to_add, num_lookups;

    if (!ext) {
        keys_to_add = KEYS_TO_ADD * ADD_PERCENT;
        num_lookups = NUM_LOOKUPS * ADD_PERCENT;
    } else {
        keys_to_add = KEYS_TO_ADD;
        num_lookups = NUM_LOOKUPS;
    }
    for (i = 0; i < num_lookups / keys_to_add; i++) {
        for (j = 0; j < keys_to_add; j++) {
            if (with_hash && with_data) {
                ret = cne_hash_lookup_with_hash_data(htables[table_index], (const void *)keys[j],
                                                     signatures[j], &ret_data);
                if (ret < 0) {
                    tst_error("Key number %u was not found", j);
                    return -1;
                }
                expected_data = (void *)((uintptr_t)signatures[j]);
                if (ret_data != expected_data) {
                    tst_error("Data returned for key number %u is %p,"
                              " but should be %p",
                              j, ret_data, expected_data);
                    return -1;
                }
            } else if (with_hash && !with_data) {
                ret = cne_hash_lookup_with_hash(htables[table_index], (const void *)keys[j],
                                                signatures[j]);
                if (ret < 0 || ret != positions[j]) {
                    tst_error("Key looked up in %d, should be in %d", ret, positions[j]);
                    return -1;
                }
            } else if (!with_hash && with_data) {
                ret = cne_hash_lookup_data(htables[table_index], (const void *)keys[j], &ret_data);
                if (ret < 0) {
                    tst_error("Key number %u was not found", j);
                    return -1;
                }
                expected_data = (void *)((uintptr_t)signatures[j]);
                if (ret_data != expected_data) {
                    tst_error("Data returned for key number %u is %p, but should be %p", j,
                              ret_data, expected_data);
                    return -1;
                }
            } else {
                ret = cne_hash_lookup(htables[table_index], keys[j]);
                if (ret < 0 || ret != positions[j]) {
                    tst_error("Key looked up in %d, should be in %d", ret, positions[j]);
                    return -1;
                }
            }
        }
    }

    const uint64_t end_tsc    = cne_rdtsc();
    const uint64_t time_taken = end_tsc - start_tsc;

    cycles[table_index][LOOKUP][with_hash][with_data] = time_taken / num_lookups;

    return 0;
}

static int
timed_lookups_multi(unsigned int with_hash, unsigned int with_data, unsigned int table_index,
                    unsigned int ext)
{
    unsigned i, j, k;
    int32_t positions_burst[BURST_SIZE];
    const void *keys_burst[BURST_SIZE];
    void *expected_data[BURST_SIZE];
    void *ret_data[BURST_SIZE];
    uint64_t hit_mask;
    int ret;
    unsigned int keys_to_add, num_lookups;

    if (!ext) {
        keys_to_add = KEYS_TO_ADD * ADD_PERCENT;
        num_lookups = NUM_LOOKUPS * ADD_PERCENT;
    } else {
        keys_to_add = KEYS_TO_ADD;
        num_lookups = NUM_LOOKUPS;
    }

    const uint64_t start_tsc = cne_rdtsc();

    for (i = 0; i < num_lookups / keys_to_add; i++) {
        for (j = 0; j < keys_to_add / BURST_SIZE; j++) {
            for (k = 0; k < BURST_SIZE; k++)
                keys_burst[k] = keys[j * BURST_SIZE + k];
            if (!with_hash && with_data) {
                ret = cne_hash_lookup_bulk_data(htables[table_index], (const void **)keys_burst,
                                                BURST_SIZE, &hit_mask, ret_data);
                if (ret != BURST_SIZE) {
                    tst_error("Expect to find %u keys, but found %d", BURST_SIZE, ret);
                    return -1;
                }
                for (k = 0; k < BURST_SIZE; k++) {
                    if ((hit_mask & (1ULL << k)) == 0) {
                        tst_error("Key number %u not found", j * BURST_SIZE + k);
                        return -1;
                    }
                    expected_data[k] = (void *)((uintptr_t)signatures[j * BURST_SIZE + k]);
                    if (ret_data[k] != expected_data[k]) {
                        tst_error("Data returned for key number %u is %p, but should be %p",
                                  j * BURST_SIZE + k, ret_data[k], expected_data[k]);
                        return -1;
                    }
                }
            } else if (with_hash && with_data) {
                ret = cne_hash_lookup_with_hash_bulk_data(
                    htables[table_index], (const void **)keys_burst, &signatures[j * BURST_SIZE],
                    BURST_SIZE, &hit_mask, ret_data);
                if (ret != BURST_SIZE) {
                    tst_error("Expect to find %u keys, but found %d", BURST_SIZE, ret);
                    return -1;
                }
                for (k = 0; k < BURST_SIZE; k++) {
                    if ((hit_mask & (1ULL << k)) == 0) {
                        tst_error("Key number %u not found", j * BURST_SIZE + k);
                        return -1;
                    }
                    expected_data[k] = (void *)((uintptr_t)signatures[j * BURST_SIZE + k]);
                    if (ret_data[k] != expected_data[k]) {
                        tst_error("Data returned for key number %u is %p, but should be %p",
                                  j * BURST_SIZE + k, ret_data[k], expected_data[k]);
                        return -1;
                    }
                }
            } else if (with_hash && !with_data) {
                ret = cne_hash_lookup_with_hash_bulk(
                    htables[table_index], (const void **)keys_burst, &signatures[j * BURST_SIZE],
                    BURST_SIZE, positions_burst);
                for (k = 0; k < BURST_SIZE; k++) {
                    if (positions_burst[k] != positions[j * BURST_SIZE + k]) {
                        tst_error("Key looked up in %d, should be in %d", positions_burst[k],
                                  positions[j * BURST_SIZE + k]);
                        return -1;
                    }
                }
            } else {
                cne_hash_lookup_bulk(htables[table_index], (const void **)keys_burst, BURST_SIZE,
                                     positions_burst);
                for (k = 0; k < BURST_SIZE; k++) {
                    if (positions_burst[k] != positions[j * BURST_SIZE + k]) {
                        tst_error("Key looked up in %d, should be in %d", positions_burst[k],
                                  positions[j * BURST_SIZE + k]);
                        return -1;
                    }
                }
            }
        }
    }

    const uint64_t end_tsc    = cne_rdtsc();
    const uint64_t time_taken = end_tsc - start_tsc;

    cycles[table_index][LOOKUP_MULTI][with_hash][with_data] = time_taken / num_lookups;

    return 0;
}

static int
timed_deletes(unsigned int with_hash, unsigned int with_data, unsigned int table_index,
              unsigned int ext)
{
    unsigned i;
    const uint64_t start_tsc = cne_rdtsc();
    int32_t ret;
    unsigned int keys_to_add;
    if (!ext)
        keys_to_add = KEYS_TO_ADD * ADD_PERCENT;
    else
        keys_to_add = KEYS_TO_ADD;

    for (i = 0; i < keys_to_add; i++) {
        /* There are no delete functions with data, so just call two functions */
        if (with_hash)
            ret = cne_hash_del_key_with_hash(htables[table_index], (const void *)keys[i],
                                             signatures[i]);
        else
            ret = cne_hash_del_key(htables[table_index], (const void *)keys[i]);
        if (ret >= 0)
            positions[i] = ret;
        else {
            tst_error("Failed to delete key number %u", i);
            return -1;
        }
    }

    const uint64_t end_tsc    = cne_rdtsc();
    const uint64_t time_taken = end_tsc - start_tsc;

    cycles[table_index][DELETE][with_hash][with_data] = time_taken / keys_to_add;

    return 0;
}

static int
run_all_tbl_perf_tests(unsigned int with_pushes, unsigned int ext)
{
    unsigned i, j, with_data, with_hash;

    for (with_data = 0; with_data <= 1; with_data++) {
        for (i = 0; i < NUM_KEYSIZES; i++) {
            if (create_table(with_data, i, ext) < 0)
                return -1;

            if (get_input_keys(with_pushes, i, ext) < 0)
                return -1;
            for (with_hash = 0; with_hash <= 1; with_hash++) {
                if (timed_adds(with_hash, with_data, i, ext) < 0)
                    return -1;

                for (j = 0; j < NUM_SHUFFLES; j++)
                    shuffle_input_keys(i, ext);

                if (timed_lookups(with_hash, with_data, i, ext) < 0)
                    return -1;

                if (timed_lookups_multi(with_hash, with_data, i, ext) < 0)
                    return -1;

                if (timed_deletes(with_hash, with_data, i, ext) < 0)
                    return -1;

                reset_table(i);
            }
            free_table(i);
        }
    }

    cne_printf("\nResults (in CPU cycles/operation)\n");
    cne_printf("-----------------------------------\n");
    for (with_data = 0; with_data <= 1; with_data++) {
        if (with_data)
            cne_printf("Operations with 8-byte data\n");
        else
            cne_printf("Operations without data\n");
        for (with_hash = 0; with_hash <= 1; with_hash++) {
            if (with_hash)
                cne_printf("  With pre-computed hash values\n");
            else
                cne_printf("  Without pre-computed hash values\n");

            cne_printf("    %-18s%-18s%-18s%-18s%-18s\n", "Keysize", "Add", "Lookup", "Lookup_bulk",
                       "Delete");
            for (i = 0; i < NUM_KEYSIZES; i++) {
                cne_printf("    %-18d", hashtest_key_lens[i]);
                for (j = 0; j < NUM_OPERATIONS; j++)
                    cne_printf("%-18" PRIu64, cycles[i][j][with_hash][with_data]);
                cne_printf("\n");
            }
        }
        cne_printf("\n");
    }
    return 0;
}

/* Control operation of performance testing of fbk hash. */
#define LOAD_FACTOR     0.667     /* How full to make the hash table. */
#define TEST_SIZE       1000000   /* How many operations to time. */
#define TEST_ITERATIONS 30        /* How many measurements to take. */
#define ENTRIES         (1 << 15) /* How many entries. */

static int
fbk_hash_perf_test(void)
{
    struct cne_fbk_hash_params params = {
        .name               = "fbk_hash_test",
        .entries            = ENTRIES,
        .entries_per_bucket = 4,
        .socket_id          = cne_socket_id(cne_lcore_id()),
    };
    struct cne_fbk_hash_table *handle = NULL;
    uint32_t *keys                    = NULL;
    unsigned indexes[TEST_SIZE];
    uint64_t lookup_time = 0;
    unsigned added       = 0;
    unsigned value       = 0;
    uint32_t key;
    uint16_t val;
    unsigned i, j;

    handle = cne_fbk_hash_create(&params);
    if (handle == NULL) {
        tst_error("Error creating table");
        return -1;
    }

    keys = calloc(ENTRIES, sizeof(*keys));
    if (keys == NULL) {
        tst_error("fbk hash: memory allocation for key store failed");
        cne_fbk_hash_free(handle);
        return -1;
    }

    /* Generate random keys and values. */
    for (i = 0; i < ENTRIES; i++) {
        key = (uint32_t)rand();
        key = ((uint64_t)key << 32) | (uint64_t)rand();
        val = (uint16_t)rand();

        if (cne_fbk_hash_add_key(handle, key, val) == 0) {
            keys[added] = key;
            added++;
        }
        if (added > (LOAD_FACTOR * ENTRIES))
            break;
    }
    if (added == 0) {
        tst_error("Failed to add keys to key store");
        free(keys);
        return -1;
    }

    for (i = 0; i < TEST_ITERATIONS; i++) {
        uint64_t begin;
        uint64_t end;

        /* Generate random indexes into keys[] array. */
        for (j = 0; j < TEST_SIZE; j++)
            indexes[j] = rand() % added;

        begin = cne_rdtsc();
        /* Do lookups */
        for (j = 0; j < TEST_SIZE; j++)
            value += cne_fbk_hash_lookup(handle, keys[indexes[j]]);

        end = cne_rdtsc();
        lookup_time += (double)(end - begin);
    }

    tst_info("FBK Hash function performance test results:");
    /*
     * The use of the 'value' variable ensures that the hash lookup is not
     * being optimised out by the compiler.
     */
    if (value != 0)
        tst_info("Number of ticks per lookup = %g",
                 (double)lookup_time / ((double)TEST_ITERATIONS * (double)TEST_SIZE));

    cne_fbk_hash_free(handle);
    free(keys);

    return 0;
}

static int
test_hash_perf(void)
{
    int rc;

    tst_info("ALL ELEMENTS IN PRIMARY LOCATION");
    rc = run_all_tbl_perf_tests(0, 0);
    if (rc < 0)
        return rc;

    tst_info("ELEMENTS IN PRIMARY OR SECONDARY LOCATION");
    rc = run_all_tbl_perf_tests(1, 0);
    if (rc < 0)
        return rc;

    tst_info("EXTENDABLE BUCKETS PERFORMANCE");
    rc = run_all_tbl_perf_tests(1, 1);
    if (rc < 0)
        return rc;

    if (fbk_hash_perf_test() < 0)
        return -1;

    return 0;
}

int
hash_perf_main(int argc, char **argv)
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

    memset(htables, 0, sizeof(htables));

    if (test_hash_perf() < 0)
        goto leave;

    tst_ok("PASS --- %s tests passed", tst->name);
    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_error("FAILED --- %s tests failed", tst->name);
    tst_end(tst, TST_FAILED);
    return -1;
}
