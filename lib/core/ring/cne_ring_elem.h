/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2019 Arm Limited
 * Copyright (c) 2010-2022 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _CNE_RING_ELEM_H_
#define _CNE_RING_ELEM_H_

/**
 * @file
 * CNDP Ring with user defined element size
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include <errno.h>
#include <cne_common.h>
#include <cne_branch_prediction.h>

#include "ring_private.h"

static __cne_always_inline void
__cne_ring_enqueue_elems_32(struct cne_ring *r, const uint32_t size, uint32_t idx,
                            const void *obj_table, uint32_t n)
{
    unsigned int i;
    uint32_t *ring      = (uint32_t *)&r[1];
    const uint32_t *obj = (const uint32_t *)obj_table;
    if (likely(idx + n < size)) {
        for (i = 0; i < (n & ~0x7); i += 8, idx += 8) {
            ring[idx]     = obj[i];
            ring[idx + 1] = obj[i + 1];
            ring[idx + 2] = obj[i + 2];
            ring[idx + 3] = obj[i + 3];
            ring[idx + 4] = obj[i + 4];
            ring[idx + 5] = obj[i + 5];
            ring[idx + 6] = obj[i + 6];
            ring[idx + 7] = obj[i + 7];
        }
        switch (n & 0x7) {
        case 7:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 6:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 5:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 4:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 3:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 2:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 1:
            ring[idx++] = obj[i++]; /* fallthrough */
        }
    } else {
        for (i = 0; idx < size; i++, idx++)
            ring[idx] = obj[i];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            ring[idx] = obj[i];
    }
}

static __cne_always_inline void
__cne_ring_enqueue_elems_64(struct cne_ring *r, uint32_t prod_head, const void *obj_table,
                            uint32_t n)
{
    unsigned int i;
    const uint32_t size           = r->size;
    uint32_t idx                  = prod_head & r->mask;
    uint64_t *ring                = (uint64_t *)&r[1];
    const unaligned_uint64_t *obj = (const unaligned_uint64_t *)obj_table;
    if (likely(idx + n < size)) {
        for (i = 0; i < (n & ~0x3); i += 4, idx += 4) {
            ring[idx]     = obj[i];
            ring[idx + 1] = obj[i + 1];
            ring[idx + 2] = obj[i + 2];
            ring[idx + 3] = obj[i + 3];
        }
        switch (n & 0x3) {
        case 3:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 2:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 1:
            ring[idx++] = obj[i++];
        }
    } else {
        for (i = 0; idx < size; i++, idx++)
            ring[idx] = obj[i];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            ring[idx] = obj[i];
    }
}

/* The actual enqueue of elements on the ring.
 * Placed here since identical code needed in both
 * single and multi producer enqueue functions.
 */
static __cne_always_inline void
__cne_ring_enqueue_elems(struct cne_ring *r, uint32_t prod_head, const void *obj_table,
                         uint32_t esize, uint32_t num)
{
    /* 8B copies implemented individually to retain
     * the current performance.
     */
    if (esize == 8)
        __cne_ring_enqueue_elems_64(r, prod_head, obj_table, num);
    else {
        uint32_t idx, scale, nr_idx, nr_num, nr_size;

        /* Normalize to uint32_t */
        scale   = esize / sizeof(uint32_t);
        nr_num  = num * scale;
        idx     = prod_head & r->mask;
        nr_idx  = idx * scale;
        nr_size = r->size * scale;
        __cne_ring_enqueue_elems_32(r, nr_size, nr_idx, obj_table, nr_num);
    }
}

static __cne_always_inline void
__cne_ring_dequeue_elems_32(struct cne_ring *r, const uint32_t size, uint32_t idx, void *obj_table,
                            uint32_t n)
{
    unsigned int i;
    uint32_t *ring = (uint32_t *)&r[1];
    uint32_t *obj  = (uint32_t *)obj_table;
    if (likely(idx + n < size)) {
        for (i = 0; i < (n & ~0x7); i += 8, idx += 8) {
            obj[i]     = ring[idx];
            obj[i + 1] = ring[idx + 1];
            obj[i + 2] = ring[idx + 2];
            obj[i + 3] = ring[idx + 3];
            obj[i + 4] = ring[idx + 4];
            obj[i + 5] = ring[idx + 5];
            obj[i + 6] = ring[idx + 6];
            obj[i + 7] = ring[idx + 7];
        }
        switch (n & 0x7) {
        case 7:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 6:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 5:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 4:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 3:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 2:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 1:
            obj[i++] = ring[idx++]; /* fallthrough */
        }
    } else {
        for (i = 0; idx < size; i++, idx++)
            obj[i] = ring[idx];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            obj[i] = ring[idx];
    }
}

static __cne_always_inline void
__cne_ring_dequeue_elems_64(struct cne_ring *r, uint32_t prod_head, void *obj_table, uint32_t n)
{
    unsigned int i;
    const uint32_t size     = r->size;
    uint32_t idx            = prod_head & r->mask;
    uint64_t *ring          = (uint64_t *)&r[1];
    unaligned_uint64_t *obj = (unaligned_uint64_t *)obj_table;
    if (likely(idx + n < size)) {
        for (i = 0; i < (n & ~0x3); i += 4, idx += 4) {
            obj[i]     = ring[idx];
            obj[i + 1] = ring[idx + 1];
            obj[i + 2] = ring[idx + 2];
            obj[i + 3] = ring[idx + 3];
        }
        switch (n & 0x3) {
        case 3:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 2:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 1:
            obj[i++] = ring[idx++]; /* fallthrough */
        }
    } else {
        for (i = 0; idx < size; i++, idx++)
            obj[i] = ring[idx];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            obj[i] = ring[idx];
    }
}

/* The actual dequeue of elements from the ring.
 * Placed here since identical code needed in both
 * single and multi producer enqueue functions.
 */
static __cne_always_inline void
__cne_ring_dequeue_elems(struct cne_ring *r, uint32_t cons_head, void *obj_table, uint32_t esize,
                         uint32_t num)
{
    /* 8B copies implemented individually to retain
     * the current performance.
     */
    if (esize == 8)
        __cne_ring_dequeue_elems_64(r, cons_head, obj_table, num);
    else {
        uint32_t idx, scale, nr_idx, nr_num, nr_size;

        /* Normalize to uint32_t */
        scale   = esize / sizeof(uint32_t);
        nr_num  = num * scale;
        idx     = cons_head & r->mask;
        nr_idx  = idx * scale;
        nr_size = r->size * scale;
        __cne_ring_dequeue_elems_32(r, nr_size, nr_idx, obj_table, nr_num);
    }
}

#include "cne_ring_generic.h"

/**
 * @internal Enqueue several objects on the ring
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of objects.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
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
__cne_ring_do_enqueue_elem(struct cne_ring *r, const void *obj_table, unsigned int esize,
                           unsigned int n, enum cne_ring_queue_behavior behavior,
                           unsigned int is_sp, unsigned int *free_space)
{
    uint32_t prod_head, prod_next;
    uint32_t free_entries;

    n = __cne_ring_move_prod_head(r, is_sp, n, behavior, &prod_head, &prod_next, &free_entries);
    if (n == 0)
        goto end;

    __cne_ring_enqueue_elems(r, prod_head, obj_table, esize, n);

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
 *   A pointer to a table of objects.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
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
__cne_ring_do_dequeue_elem(struct cne_ring *r, void *obj_table, unsigned int esize, unsigned int n,
                           enum cne_ring_queue_behavior behavior, unsigned int is_sc,
                           unsigned int *available)
{
    uint32_t cons_head, cons_next;
    uint32_t entries;

    n = __cne_ring_move_cons_head(r, (int)is_sc, n, behavior, &cons_head, &cons_next, &entries);
    if (n == 0)
        goto end;

    __cne_ring_dequeue_elems(r, cons_head, obj_table, esize, n);

    update_tail(&r->cons, cons_head, cons_next, is_sc);

end:
    if (available != NULL)
        *available = entries - n;
    return n;
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_RING_ELEM_H_ */
