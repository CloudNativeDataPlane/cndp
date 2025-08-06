/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2025 Intel Corporation
 * Copyright (c) 2018 Arm Limited
 */

#ifndef _CNE_CUCKOO_HASH_H_
#define _CNE_CUCKOO_HASH_H_
/**
 * @file
 *
 * This file hold Cuckoo Hash private data structures to allows include from
 * platform specific files like cne_cuckoo_hash_x86.h
 */
#include "cne_cmp_x86.h"        // for cne_hash_k112_cmp_eq, cne_hash_k128_cmp_eq
#include "cne_common.h"         // for __cne_cache_aligned, CNE_IS_POWER_OF_2
#include "cne_hash.h"           // for cne_hash_cmp_eq_t, CNE_HASH_NAMESIZE, cne_h...
#include "cne_ring.h"           // for cne_ring_t
#include "cne_rwlock.h"         // for cne_rwlock_t

/* Macro to enable/disable run-time checking of function parameters */
#if defined(CNE_LIBCNE_HASH_DEBUG)
#define RETURN_IF_TRUE(cond, retval) \
    do {                             \
        if (cond)                    \
            return retval;           \
    } while (0)
#else
#define RETURN_IF_TRUE(cond, retval)
#endif

#if defined(CNE_LIBCNE_HASH_DEBUG)
#define ERR_IF_TRUE(cond, fmt, args...) \
    do {                                \
        if (cond)                       \
            CNE_RET(fmt, ##args);       \
    } while (0)
#else
#define ERR_IF_TRUE(cond, fmt, args...)
#endif

#include <cne_hash_crc.h>
#include <cne_jhash.h>
#include <stdint.h>        // for uint32_t, uint8_t, uint16_t, uintptr_t
#include <string.h>        // for memcmp, NULL

/*
 * All different options to select a key compare function,
 * based on the key size and custom function.
 */
// clang-format off
enum cmp_jump_table_case {
    KEY_CUSTOM = 0,
    KEY_16_BYTES,
    KEY_32_BYTES,
    KEY_48_BYTES,
    KEY_64_BYTES,
    KEY_80_BYTES,
    KEY_96_BYTES,
    KEY_112_BYTES,
    KEY_128_BYTES,
    KEY_OTHER_BYTES,
    NUM_KEY_CMP_CASES,
};
// clang-format on

/*
 * Table storing all different key compare functions
 * (multi-process supported)
 */
// clang-format off
const cne_hash_cmp_eq_t cmp_jump_table[NUM_KEY_CMP_CASES] = {
	NULL,
	cne_hash_k16_cmp_eq,
	cne_hash_k32_cmp_eq,
	cne_hash_k48_cmp_eq,
	cne_hash_k64_cmp_eq,
	cne_hash_k80_cmp_eq,
	cne_hash_k96_cmp_eq,
	cne_hash_k112_cmp_eq,
	cne_hash_k128_cmp_eq,
	memcmp
};
// clang-format on

/** Number of items per bucket. */
#define CNE_HASH_BUCKET_ENTRIES 8

#if !CNE_IS_POWER_OF_2(CNE_HASH_BUCKET_ENTRIES)
#error CNE_HASH_BUCKET_ENTRIES must be a power of 2
#endif

#define NULL_SIGNATURE 0

#define EMPTY_SLOT 0

#define KEY_ALIGNMENT 16

#define LCORE_CACHE_SIZE 64

#define CNE_HASH_BFS_QUEUE_MAX_LEN 1000

#define CNE_XABORT_CUCKOO_PATH_INVALIDED 0x4

#define CNE_HASH_TSX_MAX_RETRY 10

struct lcore_cache {
    unsigned len;                    /**< Cache len */
    uint32_t objs[LCORE_CACHE_SIZE]; /**< Cache objects */
} __cne_cache_aligned;

/* Structure that stores key-value pair */
struct cne_hash_key {
    union {
        uintptr_t idata;
        void *pdata;
    };
    /* Variable key size */
    char key[0];
};

/* All different signature compare functions */
enum cne_hash_sig_compare_function {
    CNE_HASH_COMPARE_SCALAR = 0,
    CNE_HASH_COMPARE_SSE,
    CNE_HASH_COMPARE_NEON,
    CNE_HASH_COMPARE_NUM
};

/** Bucket structure */
struct cne_hash_bucket {
    uint16_t sig_current[CNE_HASH_BUCKET_ENTRIES];

    uint32_t key_idx[CNE_HASH_BUCKET_ENTRIES];

    uint8_t flag[CNE_HASH_BUCKET_ENTRIES];

    void *next;
} __cne_cache_aligned;

/** A hash table structure. */
struct cne_hash {
    char name[CNE_HASH_NAMESIZE]; /**< Name of the hash. */
    uint32_t entries;             /**< Total table entries. */
    uint32_t num_buckets;         /**< Number of buckets in table. */

    cne_ring_t *free_slots;
    /**< Ring that stores all indexes of the free slots in the key table */

    /* Fields used in lookup */
    uint32_t key_len __cne_cache_aligned;
    /**< Length of hash key. */
    uint8_t hw_trans_mem_support;
    /**< If hardware transactional memory is used. */
    uint8_t readwrite_concur_support;
    /**< If read-write concurrency support is enabled */
    uint8_t ext_table_support; /**< Enable extendable bucket table */
    uint8_t no_free_on_del;
    /**< If key index should be freed on calling cne_hash_del_xxx APIs.
     * If this is set, cne_hash_free_key_with_position must be called to
     * free the key index associated with the deleted entry.
     * This flag is enabled by default.
     */
    uint8_t readwrite_concur_lf_support;
    /**< If read-write concurrency lock free support is enabled */
    uint8_t writer_takes_lock;
    /**< Indicates if the writer threads need to take lock */
    cne_hash_function hash_func; /**< Function used to calculate hash. */
    uint32_t hash_func_init_val; /**< Init value used by hash_func. */
    cne_hash_cmp_eq_t cne_hash_custom_cmp_eq;
    /**< Custom function used to compare keys. */
    enum cmp_jump_table_case cmp_jump_table_idx;
    /**< Indicates which compare function to use. */
    enum cne_hash_sig_compare_function sig_cmp_fn;
    /**< Indicates which signature compare function to use. */
    uint32_t bucket_bitmask;
    /**< Bitmask for getting bucket index from hash signature. */
    uint32_t key_entry_size; /**< Size of each key entry. */

    void *key_store; /**< Table storing all keys and data */
    struct cne_hash_bucket *buckets;
    /**< Table with buckets storing all the hash values and key indexes
     * to the key table.
     */
    cne_rwlock_t *readwrite_lock;        /**< Read-write lock thread-safety. */
    struct cne_hash_bucket *buckets_ext; /**< Extra buckets array */
    cne_ring_t *free_ext_bkts;           /**< Ring of indexes of free buckets */
    /* Stores index of an empty ext bkt to be recycled on calling
     * cne_hash_del_xxx APIs. When lock free read-write concurrency is
     * enabled, an empty ext bkt cannot be put into free list immediately
     * (as readers might be using it still). Hence freeing of the ext bkt
     * is piggy-backed to freeing of the key index.
     */
    uint32_t *ext_bkt_to_free;
    uint32_t *tbl_chng_cnt;
    /**< Indicates if the hash table changed from last read. */
} __cne_cache_aligned;

struct queue_node {
    struct cne_hash_bucket *bkt; /* Current bucket on the bfs search */
    uint32_t cur_bkt_idx;

    struct queue_node *prev; /* Parent(bucket) in search path */
    int prev_slot;           /* Parent(slot) in search path */
};

#endif
