/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2019-2022 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _CNE_RING_API_H_
#define _CNE_RING_API_H_

/**
 * @file
 * CNDP Ring API
 *
 * The Ring Manager is a fixed-size queue, implemented as a table of
 * pointers. Head and tail pointers are modified atomically, allowing
 * concurrent access to it. It has the following features:
 *
 * - FIFO (First In First Out)
 * - Maximum size is fixed; the pointers are stored in a table.
 * - Lockless implementation.
 * - Multi- or single-consumer dequeue.
 * - Multi- or single-producer enqueue.
 * - Bulk dequeue.
 * - Bulk enqueue.
 *
 * Note: the ring implementation is not preemptible. Refer to Programmer's
 * guide/Cloud Native Environment/Multiple pthread/Known Issues/cne_ring
 * for more information.
 *
 * Note: no global list of rings is maintained by this library. It's expected
 * that the application will maintain a list of the rings it uses. As such, the
 * application should ensure that the ring names it uses are unique.
 *
 */

#include <errno.h>
#include <stdio.h>
#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void cne_ring_t;

#define RING_F_SP_ENQ    0x0001 /**< The default enqueue is "single-producer". */
#define RING_F_SC_DEQ    0x0002 /**< The default dequeue is "single-consumer". */
#define RING_F_ALLOCATED 0x8000 /**< The ring structure and data was allocated (internal only) */

/**
 * Ring is to hold exactly requested number of entries.
 * Without this flag set, the ring size requested must be a power of 2, and the
 * usable space will be that size - 1. With the flag, the requested size will
 * be rounded up to the next power of two, but the usable space will be exactly
 * that requested. Worst case, if a power-of-2 size is requested, half the
 * ring space will be wasted.
 */
#define RING_F_EXACT_SZ  0x0004
#define CNE_RING_SZ_MASK (0x7fffffffU) /**< Ring size mask */

/**
 * Calculate the memory size needed for a ring with given element size
 *
 * This function returns the number of bytes needed for a ring, given
 * the number of elements in it and the size of the element. This value
 * is the sum of the size of the structure cne_ring and the size of the
 * memory needed for storing the elements. The value is aligned to a cache
 * line size.
 *
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 * @param count
 *   The number of elements in the ring (must be a power of 2).
 * @return
 *   - The memory size needed for the ring on success.
 *   - -EINVAL - esize is not a multiple of 4 or count provided is not a
 *       power of 2.
 */
CNDP_API ssize_t cne_ring_get_memsize_elem(unsigned int esize, unsigned int count);

/**
 * Calculate the memory size needed for a ring
 *
 * This function returns the number of bytes needed for a ring, given
 * the number of elements in it. This value is the sum of the size of
 * the structure cne_ring and the size of the memory needed by the
 * objects pointers. The value is aligned to a cache line size.
 *
 * @param count
 *   The number of elements in the ring (must be a power of 2).
 * @return
 *   - The memory size needed for the ring on success.
 *   - -EINVAL if count is not a power of 2.
 */
CNDP_API ssize_t cne_ring_get_memsize(unsigned count);

/**
 * Create a new ring in memory.
 *
 * The new ring size is set to *count*, which must be a power of
 * two. Water marking is disabled by default. The real usable ring size
 * is *count-1* instead of *count* to differentiate a free ring from an
 * empty ring.
 *
 * @param name
 *   The name of the ring.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4, or 0
 *   to assign the default element size.
 * @param count
 *   The size of the ring (must be a power of 2).
 * @param flags
 *   An OR of the following:
 *    - RING_F_SP_ENQ: If this flag is set, the default behavior when
 *      using ``cne_ring_enqueue()`` or ``cne_ring_enqueue_bulk()``
 *      is "single-producer". Otherwise, it is "multi-producers".
 *    - RING_F_SC_DEQ: If this flag is set, the default behavior when
 *      using ``cne_ring_dequeue()`` or ``cne_ring_dequeue_bulk()``
 *      is "single-consumer". Otherwise, it is "multi-consumers".
 * @return
 *   On success, the pointer to the new allocated ring. NULL on error with
 *    errno set appropriately. Possible errno values include:
 *    - EINVAL - invalid name, esize, count or count provided is not a power of 2
 *    - ENAMETOOLONG - name is too long
 *    - ENOMEM - could not allocate ring
 */
CNDP_API cne_ring_t *cne_ring_create(const char *name, unsigned int esize, unsigned count,
                                     unsigned flags);

/**
 * Create a new ring in memory using the specified address and size of memory
 *
 * The new ring size is set to *count*, which must be a power of
 * two. Water marking is disabled by default. The real usable ring size
 * is *count-1* instead of *count* to differentiate a full ring from an
 * empty ring.
 *
 * @param addr
 *   Address of memory to use for constructing the new ring. Can be NULL to have
 *   memory allocated via calloc() call.
 * @param size
 *   Size of the memory buffer pointed by the addr argument. Can be zero if addr is NULL
 *   and the size must be able to hold the cne_ring_t structure and ring.
 * @param name
 *   The name of the ring.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4, or 0
 *   to assign the default element size.
 * @param count
 *   The size of the ring (must be a power of 2).
 * @param flags
 *   An OR of the following:
 *    - RING_F_SP_ENQ: If this flag is set, the default behavior when
 *      using ``cne_ring_enqueue()`` or ``cne_ring_enqueue_bulk()``
 *      is "single-producer". Otherwise, it is "multi-producers".
 *    - RING_F_SC_DEQ: If this flag is set, the default behavior when
 *      using ``cne_ring_dequeue()`` or ``cne_ring_dequeue_bulk()``
 *      is "single-consumer". Otherwise, it is "multi-consumers".
 * @return
 *   On success, the pointer to the new allocated ring. NULL on error with
 *    errno set appropriately. Possible errno values include:
 *    - EINVAL - invalid name, esize, count or count provided is not a power of 2
 *    - ENAMETOOLONG - name is too long
 *    - ENOMEM - could not allocate ring
 */
CNDP_API cne_ring_t *cne_ring_init(void *addr, ssize_t size, const char *name, unsigned int esize,
                                   unsigned int count, unsigned int flags);

/**
 * De-allocate all memory used by the ring.
 *
 * @param r
 *   Ring to free
 */
CNDP_API void cne_ring_free(cne_ring_t *r);

/**
 * Dump the status of the ring to a file.
 *
 * @param f
 *   A pointer to a file for output
 * @param r
 *   A pointer to the ring structure.
 */
CNDP_API void cne_ring_dump(FILE *f, cne_ring_t *r);

/**
 * Flush a ring.
 *
 * This function flush all the elements in a ring
 *
 * @param r
 *   A pointer to the ring structure.
 */
CNDP_API void cne_ring_reset(cne_ring_t *r);

/**
 * Return the number of entries in a ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The number of entries in the ring.
 */
CNDP_API unsigned cne_ring_count(const cne_ring_t *r);

/**
 * Return the number of free entries in a ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The number of free entries in the ring.
 */
CNDP_API unsigned cne_ring_free_count(const cne_ring_t *r);

/**
 * Test if a ring is full.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   - 1: The ring is full.
 *   - 0: The ring is not full.
 */
CNDP_API int cne_ring_full(const cne_ring_t *r);

/**
 * Test if a ring is empty.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   - 1: The ring is empty.
 *   - 0: The ring is not empty.
 */
CNDP_API int cne_ring_empty(const cne_ring_t *r);

/**
 * Return the size of the ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The size of the data store used by the ring.
 *   NOTE: this is not the same as the usable space in the ring. To query that
 *   use ``cne_ring_get_capacity()``.
 */
CNDP_API unsigned cne_ring_get_size(const cne_ring_t *r);

/**
 * Return the number of elements which can be stored in the ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The usable size of the ring.
 */
CNDP_API unsigned cne_ring_get_capacity(const cne_ring_t *r);

/**
 * Return the ring name
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The the ring name.
 */
CNDP_API const char *cne_ring_get_name(const cne_ring_t *r);

/**
 * Return the ring flags
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The the ring flags.
 */
CNDP_API int cne_ring_get_flags(const cne_ring_t *r);

/**
 * Return the ring mask
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The the ring mask.
 */
CNDP_API uint32_t cne_ring_get_mask(const cne_ring_t *r);

/**
 * Return the ring prod head
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The the ring prod head
 */
CNDP_API uint32_t cne_ring_get_prod_head(const cne_ring_t *r);

/**
 * Return the ring prod tail
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The the ring prod tail
 */
CNDP_API uint32_t cne_ring_get_prod_tail(const cne_ring_t *r);

/**
 * Return the ring cons head
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The the ring cons head
 */
CNDP_API uint32_t cne_ring_get_cons_head(const cne_ring_t *r);

/**
 * Return the ring cons tail
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The the ring cons tail
 */
CNDP_API uint32_t cne_ring_get_cons_tail(const cne_ring_t *r);

/****************************************************************************
 *                    Ring Generic Functions                                *
 ****************************************************************************/
/**
 * Enqueue several objects on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   The number of objects enqueued, either 0 or n
 */
CNDP_API unsigned int cne_ring_enqueue_bulk(cne_ring_t *r, void *const *obj_table, unsigned int n,
                                            unsigned int *free_space);

/**
 * Enqueue one object on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj
 *   A pointer to the object to be added.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
__cne_always_inline int
cne_ring_enqueue(cne_ring_t *r, void *obj)
{
    return cne_ring_enqueue_bulk(r, &obj, 1, NULL) ? 0 : -ENOBUFS;
}

/**
 * Dequeue several objects from a ring.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   The number of objects dequeued, either 0 or n
 */
CNDP_API unsigned int cne_ring_dequeue_bulk(cne_ring_t *r, void **obj_table, unsigned int n,
                                            unsigned int *available);

/**
 * Dequeue one object from a ring.
 *
 * This function calls the multi-consumers or the single-consumer
 * version depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success, objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue, no object is
 *     dequeued.
 */
CNDP_API __cne_always_inline int
cne_ring_dequeue(cne_ring_t *r, void **obj_p)
{
    return cne_ring_dequeue_bulk(r, obj_p, 1, NULL) ? 0 : -ENOENT;
}

/**
 * Enqueue several objects on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   - n: Actual number of objects enqueued.
 */
CNDP_API unsigned cne_ring_enqueue_burst(cne_ring_t *r, void *const *obj_table, unsigned int n,
                                         unsigned int *free_space);

/**
 * Dequeue multiple objects from a ring up to a maximum number.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   - Number of objects dequeued
 */
CNDP_API unsigned cne_ring_dequeue_burst(cne_ring_t *r, void **obj_table, unsigned int n,
                                         unsigned int *available);

/****************************************************************************
 *                    Ring Elem Functions                                   *
 ****************************************************************************/

/**
 * Enqueue several objects on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * ring creation time (see flags).
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
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   The number of objects enqueued, either 0 or n
 */
CNDP_API unsigned int cne_ring_enqueue_bulk_elem(cne_ring_t *r, const void *obj_table,
                                                 unsigned int esize, unsigned int n,
                                                 unsigned int *free_space);

/**
 * Enqueue one object on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj
 *   A pointer to the object to be added.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
CNDP_API __cne_always_inline int
cne_ring_enqueue_elem(cne_ring_t *r, void *obj, unsigned int esize)
{
    return cne_ring_enqueue_bulk_elem(r, obj, esize, 1, NULL) ? 0 : -ENOBUFS;
}

/**
 * Dequeue several objects from a ring.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of objects that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   The number of objects dequeued, either 0 or n
 */
CNDP_API unsigned int cne_ring_dequeue_bulk_elem(cne_ring_t *r, void *obj_table, unsigned int esize,
                                                 unsigned int n, unsigned int *available);

/**
 * Dequeue one object from a ring.
 *
 * This function calls the multi-consumers or the single-consumer
 * version depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to the object that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @return
 *   - 0: Success, objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue, no object is
 *     dequeued.
 */
CNDP_API __cne_always_inline int
cne_ring_dequeue_elem(cne_ring_t *r, void *obj_p, unsigned int esize)
{
    return cne_ring_dequeue_bulk_elem(r, obj_p, esize, 1, NULL) ? 0 : -ENOENT;
}

/**
 * Enqueue several objects on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * ring creation time (see flags).
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
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   - n: Actual number of objects enqueued.
 */
CNDP_API unsigned cne_ring_enqueue_burst_elem(cne_ring_t *r, const void *obj_table,
                                              unsigned int esize, unsigned int n,
                                              unsigned int *free_space);

/**
 * Dequeue multiple objects from a ring up to a maximum number.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of objects that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   This must be the same value used while creating the ring. Otherwise
 *   the results are undefined.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   - Number of objects dequeued
 */
CNDP_API unsigned int cne_ring_dequeue_burst_elem(cne_ring_t *r, void *obj_table,
                                                  unsigned int esize, unsigned int n,
                                                  unsigned int *available);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_RING__API_H_ */
