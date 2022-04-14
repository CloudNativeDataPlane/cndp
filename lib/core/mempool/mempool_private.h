/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 * Copyright (c) 2016 6WIND S.A.
 */

#ifndef _MEMPOOL_PRIVATE_H_
#define _MEMPOOL_PRIVATE_H_

/**
 * @file
 * CNE Mempool.
 *
 * Private mempool information
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <cne_branch_prediction.h>
#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEMPOOL_PG_SHIFT_MAX (sizeof(uintptr_t) * CHAR_BIT - 1)

#ifndef CNE_MEMPOOL_ALIGN
#define CNE_MEMPOOL_ALIGN CNE_CACHE_LINE_SIZE
#endif

#define CNE_MEMPOOL_ALIGN_MASK (CNE_MEMPOOL_ALIGN - 1)

/**
 * A structure that stores the mempool statistics.
 */
struct mempool_stats {
    uint64_t put_bulk;         /**< Number of puts. */
    uint64_t put_objs;         /**< Number of objects successfully put. */
    uint64_t get_success_bulk; /**< Successful allocation number. */
    uint64_t get_success_objs; /**< Objects successfully allocated. */
    uint64_t get_fail_bulk;    /**< Failed allocation number. */
    uint64_t get_fail_objs;    /**< Objects that failed to be allocated. */
    uint64_t get_success_blks; /**< Successful allocation number of contiguous blocks. */
    uint64_t get_fail_blks;    /**< Failed allocation number of contiguous blocks. */
} __cne_cache_aligned;

/**
 * A structure that stores a per-thread object cache.
 * The CNE mempool_cache structure.
 */

struct mempool_cache {
    uint32_t size;        /**< Size of the cache */
    uint32_t flushthresh; /**< Threshold before we flush excess elements */
    uint32_t len;         /**< Current cache count */
    /*
     * Cache is allocated to this size to allow it to overflow in certain
     * cases to avoid needless emptying of cache.
     */
    void *objs[MEMPOOL_CACHE_MAX_SIZE * 3]; /**< Cache objects */
} __cne_cache_aligned;

struct cne_mempool {
    void *objring;               /**< Ring or pool to store objects. */
    void *objmem;                /**< Pointer to the memory of objects */
    ssize_t objmem_sz;           /**< Size of allocated object memory */
    uint32_t obj_cnt;            /**< Max count of mempool objects */
    uint32_t obj_sz;             /**< Size of an element. */
    uint32_t cache_sz;           /**< size of the cache */
    uint32_t populated_sz;       /**< Number of objects in obj_list */
    uint32_t free_objmem;        /**< buffer memory needs to be freed */
    struct mempool_cache *cache; /**< Per-thread local cache */
    struct mempool_stats *stats; /**< Stats for each thread */
} __cne_cache_aligned;

// clang-format off
#define __MEMPOOL_STAT_ADD(mp, name, n) do {    \
        int __uid = cne_id();                   \
        mp->stats[__uid].name##_objs += n;      \
        mp->stats[__uid].name##_bulk += 1;      \
    } while(0)
// clang-format on

#ifdef __cplusplus
}
#endif

#endif /* _MEMPOOL_PRIVATE_H_ */
