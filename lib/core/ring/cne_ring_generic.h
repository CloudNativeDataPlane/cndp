/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2019-2022 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */
#include <sched.h>
#include <cne_atomic.h>

#ifndef _CNE_RING_GENERIC_H_
#define _CNE_RING_GENERIC_H_

/**
 * @file
 * CNDP generic ring functions
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <cne_branch_prediction.h>

#include "ring_private.h"
#include "cne_ring.h"

// clang-format off
/*
 * The actual enqueue of pointers on the ring.
 * Placed here since identical code needed in both
 * single and multi producer enqueue functions
 */
#define ENQUEUE_PTRS(r, ring_start, prod_head, obj_table, n, obj_type) do { \
    unsigned int i; \
    const uint32_t size = (r)->size; \
    uint32_t idx = prod_head & (r)->mask; \
    obj_type *ring = (obj_type *)ring_start; \
    if (likely(idx + n < size)) { \
        for (i = 0; i < (n & ((~(unsigned)0x3))); i+=4, idx+=4) { \
            ring[idx] = obj_table[i]; \
            ring[idx+1] = obj_table[i+1]; \
            ring[idx+2] = obj_table[i+2]; \
            ring[idx+3] = obj_table[i+3]; \
        } \
        switch (n & 0x3) { \
        case 3: \
            ring[idx++] = obj_table[i++]; /* fallthrough */ \
        case 2: \
            ring[idx++] = obj_table[i++]; /* fallthrough */ \
        case 1: \
            ring[idx++] = obj_table[i++]; \
        } \
    } else { \
        for (i = 0; idx < size; i++, idx++)\
            ring[idx] = obj_table[i]; \
        for (idx = 0; i < n; i++, idx++) \
            ring[idx] = obj_table[i]; \
    } \
} while (0)

/* The actual copy of pointers on the ring to obj_table.
 * Placed here since identical code needed in both
 * single and multi consumer dequeue functions
 */
#define DEQUEUE_PTRS(r, ring_start, cons_head, obj_table, n, obj_type) do { \
    unsigned int i; \
    uint32_t idx = cons_head &r->mask; \
    const uint32_t size = r->size; \
    obj_type *ring = (obj_type *)ring_start; \
    if (likely(idx + n < size)) { \
        for (i = 0; i < (n & (~(unsigned)0x3)); i+=4, idx+=4) {\
            obj_table[i] = ring[idx]; \
            obj_table[i+1] = ring[idx+1]; \
            obj_table[i+2] = ring[idx+2]; \
            obj_table[i+3] = ring[idx+3]; \
        } \
        switch (n & 0x3) { \
        case 3: \
            obj_table[i++] = ring[idx++]; /* fallthrough */ \
        case 2: \
            obj_table[i++] = ring[idx++]; /* fallthrough */ \
        case 1: \
            obj_table[i++] = ring[idx++]; \
        } \
    } else { \
        for (i = 0; idx < size; i++, idx++) \
            obj_table[i] = ring[idx]; \
        for (idx = 0; i < n; i++, idx++) \
            obj_table[i] = ring[idx]; \
    } \
} while (0)
// clang-format on

__cne_always_inline void
update_tail(struct cne_ring_headtail *ht, uint32_t old_val, uint32_t new_val, uint32_t single)
{
    /*
     * If there are other enqueues/dequeues in progress that preceded us,
     * we need to wait for them to complete
     */
    if (!single) {
        uint64_t timo = 1000;
        /* Need another implementation of this here. Not preemptible. */
        while (unlikely(atomic_load_explicit(&ht->tail, CNE_MEMORY_ORDER(relaxed)) != old_val)) {
            if (--timo == 0) {
                timo = 1000;
                sched_yield();
            }
        }
    }

    atomic_store_explicit(&ht->tail, new_val, CNE_MEMORY_ORDER(release));
}

/**
 * @internal This function updates the producer head for enqueue
 *
 * @param r
 *   A pointer to the ring structure
 * @param is_sp
 *   Indicates whether multi-producer path is needed or not
 * @param n
 *   The number of elements we will want to enqueue, i.e. how far should the
 *   head be moved
 * @param behavior
 *   CNE_RING_QUEUE_FIXED_ITEMS:    Enqueue a fixed number of items from a ring
 *   CNE_RING_QUEUE_VARIABLE_ITEMS: Enqueue as many items as possible from ring
 * @param old_head
 *   Returns head value as it was before the move, i.e. where enqueue starts
 * @param new_head
 *   Returns the current/new head value i.e. where enqueue finishes
 * @param free_entries
 *   Returns the amount of free space in the ring BEFORE head was moved
 * @return
 *   Actual number of objects enqueued.
 *   If behavior == CNE_RING_QUEUE_FIXED_ITEMS, this will be 0 or n only.
 */
static __cne_always_inline unsigned int
__cne_ring_move_prod_head(struct cne_ring *r, unsigned int is_sp, unsigned int n,
                          enum cne_ring_queue_behavior behavior, uint32_t *old_head,
                          uint32_t *new_head, uint32_t *free_entries)
{
    const uint32_t capacity = r->capacity;
    unsigned int max        = n;
    uint32_t cons_tail;
    _Bool success;

    *old_head = atomic_load_explicit(&r->prod.head, CNE_MEMORY_ORDER(relaxed));
    do {
        /* Reset n to the initial burst count */
        n = max;

        /* add rmb barrier to avoid load/load reorder in weak
         * memory model. It is noop on x86
         */
        atomic_thread_fence(CNE_MEMORY_ORDER(acquire));

        /* load-acquire synchronize with store-release of ht->tail
         * in update_tail.
         */
        cons_tail = atomic_load_explicit(&r->cons.tail, CNE_MEMORY_ORDER(acquire));

        /*
         *  The subtraction is done between two unsigned 32bits value
         * (the result is always modulo 32 bits even if we have
         * *old_head > cons_tail). So 'free_entries' is always between 0
         * and capacity (which is < size).
         */
        *free_entries = (capacity + cons_tail - *old_head);

        /* check that we have enough room in ring */
        if (unlikely(n > *free_entries))
            n = (behavior == CNE_RING_QUEUE_FIXED_ITEMS) ? 0 : *free_entries;

        if (n == 0)
            return 0;

        *new_head = *old_head + n;
        if (is_sp) {
            r->prod.head = *new_head;
            success      = 1;
        } else {
            success = atomic_compare_exchange_strong_explicit(&r->prod.head, old_head, *new_head,
                                                              CNE_MEMORY_ORDER(relaxed),
                                                              CNE_MEMORY_ORDER(relaxed));
        }
    } while (unlikely(success == 0));
    return n;
}

/**
 * @internal This function updates the consumer head for dequeue
 *
 * @param r
 *   A pointer to the ring structure
 * @param is_sc
 *   Indicates whether multi-consumer path is needed or not
 * @param n
 *   The number of elements we will want to enqueue, i.e. how far should the
 *   head be moved
 * @param behavior
 *   CNE_RING_QUEUE_FIXED_ITEMS:    Dequeue a fixed number of items from a ring
 *   CNE_RING_QUEUE_VARIABLE_ITEMS: Dequeue as many items as possible from ring
 * @param old_head
 *   Returns head value as it was before the move, i.e. where dequeue starts
 * @param new_head
 *   Returns the current/new head value i.e. where dequeue finishes
 * @param entries
 *   Returns the number of entries in the ring BEFORE head was moved
 * @return
 *   - Actual number of objects dequeued.
 *     If behavior == CNE_RING_QUEUE_FIXED_ITEMS, this will be 0 or n only.
 */
static __cne_always_inline unsigned int
__cne_ring_move_cons_head(struct cne_ring *r, unsigned int is_sc, unsigned int n,
                          enum cne_ring_queue_behavior behavior, uint32_t *old_head,
                          uint32_t *new_head, uint32_t *entries)
{
    unsigned int max = n;
    uint32_t prod_tail;
    _Bool success;

    /* move cons.head atomically */
    *old_head = atomic_load_explicit(&r->cons.head, CNE_MEMORY_ORDER(relaxed));
    do {
        /* Restore n as it may change every loop */
        n = max;

        /* add rmb barrier to avoid load/load reorder in weak
         * memory model. It is noop on x86
         */
        atomic_thread_fence(CNE_MEMORY_ORDER(acquire));

        /* this load-acquire synchronize with store-release of ht->tail
         * in update_tail.
         */
        prod_tail = atomic_load_explicit(&r->prod.tail, CNE_MEMORY_ORDER(acquire));

        /* The subtraction is done between two unsigned 32bits value
         * (the result is always modulo 32 bits even if we have
         * cons_head > prod_tail). So 'entries' is always between 0
         * and size(ring)-1.
         */
        *entries = (prod_tail - *old_head);

        /* Set the actual entries for dequeue */
        if (n > *entries)
            n = (behavior == CNE_RING_QUEUE_FIXED_ITEMS) ? 0 : *entries;

        if (unlikely(n == 0))
            return 0;

        *new_head = *old_head + n;
        if (is_sc) {
            r->cons.head = *new_head;
            success      = 1;
        } else {
            success = atomic_compare_exchange_strong_explicit(&r->cons.head, old_head, *new_head,
                                                              CNE_MEMORY_ORDER(relaxed),
                                                              CNE_MEMORY_ORDER(relaxed));
        }
    } while (unlikely(success == 0));
    return n;
}

/**
 * @internal Enqueue several objects on the ring
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param behavior
 *   CNE_RING_QUEUE_FIXED_ITEMS:    Enqueue a fixed number of items from a ring
 *   CNE_RING_QUEUE_VARIABLE_ITEMS: Enqueue as many items as possible from ring
 * @param is_sp
 *   Indicates whether to use single producer or multi-producer head update
 * @param free_space
 *   returns the amount of space after the enqueue operation has finished
 * @return
 *   Actual number of objects enqueued.
 *   If behavior == CNE_RING_QUEUE_FIXED_ITEMS, this will be 0 or n only.
 */
static __cne_always_inline unsigned int
__cne_ring_do_enqueue(struct cne_ring *r, void *const *obj_table, unsigned int n,
                      enum cne_ring_queue_behavior behavior, unsigned int is_sp,
                      unsigned int *free_space)
{
    uint32_t prod_head, prod_next;
    uint32_t free_entries;

    n = __cne_ring_move_prod_head(r, is_sp, n, behavior, &prod_head, &prod_next, &free_entries);
    if (n == 0)
        goto end;

    ENQUEUE_PTRS(r, &r[1], prod_head, obj_table, n, void *);

    update_tail(&r->prod, prod_head, prod_next, is_sp);
end:
    if (free_space != NULL)
        *free_space = free_entries - n;
    return n;
}

/**
 * @internal Dequeue several objects from the ring
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to pull from the ring.
 * @param behavior
 *   CNE_RING_QUEUE_FIXED_ITEMS:    Dequeue a fixed number of items from a ring
 *   CNE_RING_QUEUE_VARIABLE_ITEMS: Dequeue as many items as possible from ring
 * @param is_sc
 *   Indicates whether to use single consumer or multi-consumer head update
 * @param available
 *   returns the number of remaining ring entries after the dequeue has finished
 * @return
 *   - Actual number of objects dequeued.
 *     If behavior == CNE_RING_QUEUE_FIXED_ITEMS, this will be 0 or n only.
 */
static __cne_always_inline unsigned int
__cne_ring_do_dequeue(struct cne_ring *r, void **obj_table, unsigned int n,
                      enum cne_ring_queue_behavior behavior, unsigned int is_sc,
                      unsigned int *available)
{
    uint32_t cons_head, cons_next;
    uint32_t entries;

    n = __cne_ring_move_cons_head(r, (int)is_sc, n, behavior, &cons_head, &cons_next, &entries);
    if (n == 0)
        goto end;

    DEQUEUE_PTRS(r, &r[1], cons_head, obj_table, n, void *);

    update_tail(&r->cons, cons_head, cons_next, is_sc);

end:
    if (available != NULL)
        *available = entries - n;
    return n;
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_RING_GENERIC_H_ */
