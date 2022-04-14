/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation
 */

#ifndef _RING_PRIVATE_H_
#define _RING_PRIVATE_H_

#include <cne_atomic.h>

/**
 * @file
 * CNDP internal ring structures
 */

#ifdef __cplusplus
extern "C" {
#endif

/* @internal defines for passing to the enqueue dequeue worker functions */
#define __IS_SP 1
#define __IS_MP 0
#define __IS_SC 1
#define __IS_MC 0

enum cne_ring_queue_behavior {
    CNE_RING_QUEUE_FIXED_ITEMS = 0, /* Enq/Deq a fixed number of items from a ring */
    CNE_RING_QUEUE_VARIABLE_ITEMS   /* Enq/Deq as many items as possible from ring */
};

/*  @internal structure to hold a pair of head/tail values and other metadata */
struct cne_ring_headtail {
    CNE_ATOMIC(uint_least32_t) head; /**< Prod/consumer head. */
    CNE_ATOMIC(uint_least32_t) tail; /**< Prod/consumer tail. */
    uint32_t single;                 /**< True if single prod/cons */
};

/**
 *  @internal An CNDP ring structure.
 *
 * The producer and the consumer have a head and a tail index. The particularity
 * of these index is that they are not between 0 and size(ring). These indexes
 * are between 0 and 2^32, and we mask their value when we access the ring[]
 * field. Thanks to this assumption, we can do subtractions between 2 index
 * values in a modulo-32bit base: that's why the overflow of the indexes is not
 * a problem.
 */
struct cne_ring {
    char name[CNE_RING_NAMESIZE] __cne_cache_aligned;
    void *ring_mem;    /**< memory used to allocate this memory region. */
    int flags;         /**< Flags supplied at creation. */
    uint32_t size;     /**< Size of ring. */
    uint32_t mask;     /**< Mask (size-1) of ring. */
    uint32_t capacity; /**< Usable size of ring */

    char pad0 __cne_cache_aligned; /**< empty cache line */

    /** Ring producer status. */
    struct cne_ring_headtail prod __cne_cache_aligned;
    char pad1 __cne_cache_aligned; /**< empty cache line */

    /** Ring consumer status. */
    struct cne_ring_headtail cons __cne_cache_aligned;
    char pad2 __cne_cache_aligned; /**< empty cache line */
};

#ifdef __cplusplus
}
#endif

#endif /* _RING_PRIVATE_H_ */
