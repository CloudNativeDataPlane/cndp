/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2019-2022 Intel Corporation
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#include <inttypes.h>          // for PRIu32
#include <bsd/string.h>        // for strlcpy
#include <cne_common.h>        // for cne_align32pow2, CNE_CACHE_LINE_SIZE
#include <cne_log.h>           // for CNE_LOG, CNE_LOG_ERR, CNE_LOG_DEBUG
#include <errno.h>             // for EINVAL, errno, ENAMETOOLONG, ENOMEM
#include <stdio.h>             // for fprintf, NULL, size_t, FILE, stdout
#include <string.h>            // for memset, strnlen
#include <stddef.h>            // for offsetof
#include <stdint.h>            // for uint32_t
#include <stdlib.h>            // for calloc, free
#include <sys/types.h>         // for ssize_t

#include "cne_ring.h"
#include "cne_ring_api_internal.h"        // for cne_ring_mc_dequeue_bulk, cne_rin...
#include "cne_ring_elem.h"                // for __cne_ring_do_dequeue_elem, __cne...
#include "cne_ring_api.h"                 // for CNE_RING_SZ_MASK, RING_F_EXACT_SZ
#include "cne_ring_generic.h"             // for __cne_ring_do_dequeue, __cne_ring...
#include "ring_private.h"                 // for cne_ring, cne_ring_headtail, CNE_...

/* true if x is a power of 2 */
#define POWEROF2(x)       ((((x)-1) & (x)) == 0)
#define RING_DFLT_ELEM_SZ sizeof(void *) /** The default ring element size*/

ssize_t
cne_ring_get_memsize_elem(unsigned int esize, unsigned int count)
{
    ssize_t sz;

    if (esize == 0)
        esize = RING_DFLT_ELEM_SZ;

    /* Check if element size is a multiple of 4B */
    if (esize % 4 != 0)
        CNE_ERR_RET_VAL(-EINVAL, "element size is not a multiple of 4\n");

    /* count must be a power of 2 */
    if ((!POWEROF2(count)) || (count > CNE_RING_SZ_MASK))
        CNE_ERR_RET_VAL(
            -EINVAL,
            "Requested number of elements is invalid, must be power of 2, and not exceed %u\n",
            CNE_RING_SZ_MASK);

    sz = sizeof(struct cne_ring) + (ssize_t)count * esize;
    sz = CNE_ALIGN(sz, CNE_CACHE_LINE_SIZE);
    return sz;
}

/* return the size of memory occupied by a ring */
ssize_t
cne_ring_get_memsize(unsigned int count)
{
    return cne_ring_get_memsize_elem(RING_DFLT_ELEM_SZ, count);
}

void
cne_ring_reset(cne_ring_t *r)
{
    struct cne_ring *_ring = r;

    _ring->prod.head = _ring->cons.head = 0;
    _ring->prod.tail = _ring->cons.tail = 0;
}

/*
 * Initialize a ring structure.
 *
 * Initialize a ring structure in memory pointed by "r". The size of the
 * memory area must be large enough to store the ring structure and the
 * object table. It is advised to use cne_ring_get_memsize() to get the
 * appropriate size.
 *
 * The ring size is set to *count*, which must be a power of two. Water
 * marking is disabled by default. The real usable ring size is
 * *count-1* instead of *count* to differentiate a free ring from an
 * empty ring.
 *
 * The ring is not added in CNE_TAILQ_RING global list. Indeed, the
 * memory given by the caller may not be shareable among CNDP
 * processes.
 *
 * @param r
 *   The pointer to the ring structure followed by the objects table.
 * @param name
 *   The name of the ring to use for searches
 * @param count
 *   The number of elements in the ring (must be a power of 2).
 * @param flags
 *   An OR of the following:
 *    - RING_F_SP_ENQ: If this flag is set, the default behavior when
 *      using ``cne_ring_enqueue()`` or ``cne_ring_enqueue_bulk()``
 *      is "single-producer". Otherwise, it is "multi-producers".
 *    - RING_F_SC_DEQ: If this flag is set, the default behavior when
 *      using ``cne_ring_dequeue()`` or ``cne_ring_dequeue_bulk()``
 *      is "single-consumer". Otherwise, it is "multi-consumers".
 * @return
 *   0 on success, or a negative value on error.
 */
static int
cne_ring_setup(cne_ring_t *r, const char *name, unsigned count, unsigned flags)
{
    struct cne_ring *_ring = r;
    int ret;

    /* compilation-time checks */
    CNE_BUILD_BUG_ON((sizeof(struct cne_ring) & CNE_CACHE_LINE_MASK) != 0);
    CNE_BUILD_BUG_ON((offsetof(struct cne_ring, cons) & CNE_CACHE_LINE_MASK) != 0);
    CNE_BUILD_BUG_ON((offsetof(struct cne_ring, prod) & CNE_CACHE_LINE_MASK) != 0);

    /* init the ring structure */
    memset(_ring, 0, sizeof(struct cne_ring));

    ret = strlcpy(_ring->name, name, sizeof(_ring->name));
    if (ret < 0 || ret >= (int)sizeof(_ring->name))
        return -ENAMETOOLONG;

    _ring->flags       = flags;
    _ring->prod.single = (flags & RING_F_SP_ENQ) ? __IS_SP : __IS_MP;
    _ring->cons.single = (flags & RING_F_SC_DEQ) ? __IS_SC : __IS_MC;

    if (flags & RING_F_EXACT_SZ) {
        _ring->size     = cne_align32pow2(count + 1);
        _ring->mask     = _ring->size - 1;
        _ring->capacity = count;
    } else {
        if ((!POWEROF2(count)) || (count > CNE_RING_SZ_MASK))
            CNE_ERR_RET_VAL(
                -EINVAL,
                "Requested size is invalid, must be power of 2, and not exceed the size "
                "limit %u\n",
                CNE_RING_SZ_MASK);
        _ring->size     = count;
        _ring->mask     = count - 1;
        _ring->capacity = _ring->mask;
    }
    _ring->prod.head = _ring->cons.head = 0;
    _ring->prod.tail = _ring->cons.tail = 0;

    return 0;
}

/* Create the ring using supplied memory and size */
cne_ring_t *
cne_ring_init(void *addr, ssize_t size, const char *name, unsigned int esize, unsigned int count,
              unsigned int flags)
{
    void *ring_mem;
    struct cne_ring *r;
    ssize_t ring_size;
    const unsigned int requested_count = count;

    if (name == NULL) {
        errno = EINVAL;
        CNE_NULL_RET("Ring: Name not provided\n");
    }

    if (strnlen(name, CNE_RING_NAMESIZE) == CNE_RING_NAMESIZE) {
        errno = ENAMETOOLONG;
        CNE_NULL_RET("Ring: Name too long\n");
    }

    if (count == 0) {
        errno = EINVAL;
        CNE_NULL_RET("Ring: No elements requested\n");
    }

    if (flags & ~(RING_F_EXACT_SZ | RING_F_SC_DEQ | RING_F_SP_ENQ)) {
        errno = EINVAL;
        CNE_NULL_RET("Flags can only have (RING_F_EXACT_SZ | RING_F_SC_DEQ | RING_F_SP_ENQ) set\n");
    }

    /* For an exact size ring, round up from count to a power of two */
    if (flags & RING_F_EXACT_SZ)
        count = cne_align32pow2(count + 1);

    ring_size = cne_ring_get_memsize_elem(esize, count);
    if (ring_size < 0) {
        errno = -ring_size;
        return NULL;
    }

    if (addr) {
        /* Address must be aligned to a cacheline boundary */
        if (!cne_is_aligned(addr, CNE_CACHE_LINE_SIZE)) {
            errno = EINVAL;
            CNE_NULL_RET("ring is not cache aligned r=%p aligned=%p\n", addr,
                         CNE_PTR_ALIGN(addr, CNE_CACHE_LINE_SIZE));
        }

        /* Use the supplied buffer as the ring buffer and structure memory */
        if (ring_size > size) {
            errno = ENOMEM;
            return NULL;
        }
        ring_mem = addr;
        memset(ring_mem, 0, ring_size);
    } else {
        /* Reserve a memory region for this ring
         * Calloc can return pointer which is not cache aligned.
         * In that case cne_ring_setup calling memset will segfault on clang compiled
         * with -O3. Tested with clang-10.0.0-4ubuntu1 and gcc-9.3.0-10ubuntu2
         */
        ring_mem = calloc(1, ring_size + CNE_CACHE_LINE_SIZE - 1);
        if (!ring_mem) {
            errno = ENOMEM;
            CNE_NULL_RET("Ring: cannot reserve memory\n");
        }
        flags |= RING_F_ALLOCATED;
    }

    r = ring_mem;
    if (!cne_is_aligned(ring_mem, CNE_CACHE_LINE_SIZE)) {
        CNE_DEBUG("ring is not cache aligned r=%p aligned=%p\n", ring_mem,
                  CNE_PTR_ALIGN(ring_mem, CNE_CACHE_LINE_SIZE));
        r = CNE_PTR_ALIGN(ring_mem, CNE_CACHE_LINE_SIZE);
    }
    /* no need to check return value here, we already checked the arguments above */
    cne_ring_setup(r, name, requested_count, flags);
    r->ring_mem = ring_mem;

    return r;
}

cne_ring_t *
cne_ring_create(const char *name, unsigned int esize, unsigned int count, unsigned int flags)
{
    return cne_ring_init(NULL, 0, name, esize, count, flags);
}

/* free the ring */
void
cne_ring_free(cne_ring_t *r)
{
    struct cne_ring *_ring = r;

    if (!_ring || !_ring->ring_mem)
        return;

    if (_ring->flags & RING_F_ALLOCATED)
        free(_ring->ring_mem);
}

/* dump the status of the ring on the console */
void
cne_ring_dump(FILE *f, cne_ring_t *r)
{
    struct cne_ring *_ring = r;

    if (!f)
        f = stdout;

    fprintf(f, "ring @ %p, flags %08x\n", (void *)_ring, _ring->flags);
    fprintf(f, "  max entries %" PRIu32 "\n", _ring->size);
    fprintf(f, "  max capacity %" PRIu32 "\n", _ring->capacity);
    fprintf(f, "  ct %" PRIu32 "  ch %" PRIu32 "\n", _ring->cons.tail, _ring->cons.head);
    fprintf(f, "  pt %" PRIu32 "  ph %" PRIu32 "\n", _ring->prod.tail, _ring->prod.head);
    fprintf(f, "  used %u, avail %u\n", cne_ring_count(_ring), cne_ring_free_count(_ring));
}

unsigned int
cne_ring_mp_enqueue_bulk(cne_ring_t *r, void *const *obj_table, unsigned int n,
                         unsigned int *free_space)
{
    return __cne_ring_do_enqueue(r, obj_table, n, CNE_RING_QUEUE_FIXED_ITEMS, __IS_MP, free_space);
}

unsigned int
cne_ring_sp_enqueue_bulk(cne_ring_t *r, void *const *obj_table, unsigned int n,
                         unsigned int *free_space)
{
    return __cne_ring_do_enqueue(r, obj_table, n, CNE_RING_QUEUE_FIXED_ITEMS, __IS_SP, free_space);
}

unsigned int
cne_ring_enqueue_bulk(cne_ring_t *r, void *const *obj_table, unsigned int n,
                      unsigned int *free_space)
{
    return __cne_ring_do_enqueue(r, obj_table, n, CNE_RING_QUEUE_FIXED_ITEMS,
                                 ((struct cne_ring *)r)->prod.single, free_space);
}

unsigned int
cne_ring_mc_dequeue_bulk(cne_ring_t *r, void **obj_table, unsigned int n, unsigned int *available)
{
    return __cne_ring_do_dequeue(r, obj_table, n, CNE_RING_QUEUE_FIXED_ITEMS, __IS_MC, available);
}

unsigned int
cne_ring_sc_dequeue_bulk(cne_ring_t *r, void **obj_table, unsigned int n, unsigned int *available)
{
    return __cne_ring_do_dequeue(r, obj_table, n, CNE_RING_QUEUE_FIXED_ITEMS, __IS_SC, available);
}

unsigned int
cne_ring_dequeue_bulk(cne_ring_t *r, void **obj_table, unsigned int n, unsigned int *available)
{

    return __cne_ring_do_dequeue(r, obj_table, n, CNE_RING_QUEUE_FIXED_ITEMS,
                                 ((struct cne_ring *)r)->cons.single, available);
}

unsigned
cne_ring_mp_enqueue_burst(cne_ring_t *r, void *const *obj_table, unsigned int n,
                          unsigned int *free_space)
{
    return __cne_ring_do_enqueue(r, obj_table, n, CNE_RING_QUEUE_VARIABLE_ITEMS, __IS_MP,
                                 free_space);
}

unsigned
cne_ring_sp_enqueue_burst(cne_ring_t *r, void *const *obj_table, unsigned int n,
                          unsigned int *free_space)
{
    return __cne_ring_do_enqueue(r, obj_table, n, CNE_RING_QUEUE_VARIABLE_ITEMS, __IS_SP,
                                 free_space);
}

unsigned
cne_ring_enqueue_burst(cne_ring_t *r, void *const *obj_table, unsigned int n,
                       unsigned int *free_space)
{
    return __cne_ring_do_enqueue(r, obj_table, n, CNE_RING_QUEUE_VARIABLE_ITEMS,
                                 ((struct cne_ring *)r)->prod.single, free_space);
}

unsigned
cne_ring_mc_dequeue_burst(cne_ring_t *r, void **obj_table, unsigned int n, unsigned int *available)
{
    return __cne_ring_do_dequeue(r, obj_table, n, CNE_RING_QUEUE_VARIABLE_ITEMS, __IS_MC,
                                 available);
}

unsigned
cne_ring_sc_dequeue_burst(cne_ring_t *r, void **obj_table, unsigned int n, unsigned int *available)
{
    return __cne_ring_do_dequeue(r, obj_table, n, CNE_RING_QUEUE_VARIABLE_ITEMS, __IS_SC,
                                 available);
}

unsigned
cne_ring_dequeue_burst(cne_ring_t *r, void **obj_table, unsigned int n, unsigned int *available)
{
    return __cne_ring_do_dequeue(r, obj_table, n, CNE_RING_QUEUE_VARIABLE_ITEMS,
                                 ((struct cne_ring *)r)->cons.single, available);
}

unsigned int
cne_ring_get_size(const cne_ring_t *r)
{
    return ((const struct cne_ring *)r)->size;
}

unsigned int
cne_ring_get_capacity(const cne_ring_t *r)
{
    return ((const struct cne_ring *)r)->capacity;
}

const char *
cne_ring_get_name(const cne_ring_t *r)
{
    return ((const struct cne_ring *)r)->name;
}

int
cne_ring_get_flags(const cne_ring_t *r)
{
    return ((const struct cne_ring *)r)->flags;
}

uint32_t
cne_ring_get_mask(const cne_ring_t *r)
{
    return ((const struct cne_ring *)r)->mask;
}

uint32_t
cne_ring_get_prod_head(const cne_ring_t *r)
{
    return ((const struct cne_ring *)r)->prod.head;
}

uint32_t
cne_ring_get_prod_tail(const cne_ring_t *r)
{
    return ((const struct cne_ring *)r)->prod.tail;
}

uint32_t
cne_ring_get_cons_head(const cne_ring_t *r)
{
    return ((const struct cne_ring *)r)->cons.head;
}

uint32_t
cne_ring_get_cons_tail(const cne_ring_t *r)
{
    return ((const struct cne_ring *)r)->cons.tail;
}

unsigned
cne_ring_count(const cne_ring_t *r)
{
    uint32_t prod_tail = cne_ring_get_prod_tail(r);
    uint32_t cons_tail = cne_ring_get_cons_tail(r);
    uint32_t count     = (prod_tail - cons_tail) & cne_ring_get_mask(r);
    return (count > cne_ring_get_capacity(r)) ? cne_ring_get_capacity(r) : count;
}

unsigned
cne_ring_free_count(const cne_ring_t *r)
{
    return (cne_ring_get_capacity(r) - cne_ring_count(r));
}

int
cne_ring_full(const cne_ring_t *r)
{
    return cne_ring_free_count(r) == 0;
}

int
cne_ring_empty(const cne_ring_t *r)
{
    return cne_ring_count(r) == 0;
}

/****************************************************************************
 *                    Ring Elem Functions                                   *
 ****************************************************************************/
unsigned int
cne_ring_mp_enqueue_bulk_elem(cne_ring_t *r, const void *obj_table, unsigned int esize,
                              unsigned int n, unsigned int *free_space)
{
    return __cne_ring_do_enqueue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_FIXED_ITEMS, __IS_MP,
                                      free_space);
}

unsigned int
cne_ring_sp_enqueue_bulk_elem(cne_ring_t *r, const void *obj_table, unsigned int esize,
                              unsigned int n, unsigned int *free_space)
{
    return __cne_ring_do_enqueue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_FIXED_ITEMS, __IS_SP,
                                      free_space);
}

unsigned int
cne_ring_enqueue_bulk_elem(cne_ring_t *r, const void *obj_table, unsigned int esize, unsigned int n,
                           unsigned int *free_space)
{
    return __cne_ring_do_enqueue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_FIXED_ITEMS,
                                      ((struct cne_ring *)r)->prod.single, free_space);
}

unsigned int
cne_ring_mc_dequeue_bulk_elem(cne_ring_t *r, void *obj_table, unsigned int esize, unsigned int n,
                              unsigned int *available)
{
    return __cne_ring_do_dequeue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_FIXED_ITEMS, __IS_MC,
                                      available);
}

unsigned int
cne_ring_sc_dequeue_bulk_elem(cne_ring_t *r, void *obj_table, unsigned int esize, unsigned int n,
                              unsigned int *available)
{
    return __cne_ring_do_dequeue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_FIXED_ITEMS, __IS_SC,
                                      available);
}

unsigned int
cne_ring_dequeue_bulk_elem(cne_ring_t *r, void *obj_table, unsigned int esize, unsigned int n,
                           unsigned int *available)
{
    return __cne_ring_do_dequeue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_FIXED_ITEMS,
                                      ((struct cne_ring *)r)->cons.single, available);
}

unsigned
cne_ring_mp_enqueue_burst_elem(cne_ring_t *r, const void *obj_table, unsigned int esize,
                               unsigned int n, unsigned int *free_space)
{
    return __cne_ring_do_enqueue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_VARIABLE_ITEMS,
                                      __IS_MP, free_space);
}

unsigned
cne_ring_sp_enqueue_burst_elem(cne_ring_t *r, const void *obj_table, unsigned int esize,
                               unsigned int n, unsigned int *free_space)
{
    return __cne_ring_do_enqueue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_VARIABLE_ITEMS,
                                      __IS_SP, free_space);
}

unsigned
cne_ring_enqueue_burst_elem(cne_ring_t *r, const void *obj_table, unsigned int esize,
                            unsigned int n, unsigned int *free_space)
{
    return __cne_ring_do_enqueue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_VARIABLE_ITEMS,
                                      ((struct cne_ring *)r)->prod.single, free_space);
}

unsigned
cne_ring_mc_dequeue_burst_elem(cne_ring_t *r, void *obj_table, unsigned int esize, unsigned int n,
                               unsigned int *available)
{
    return __cne_ring_do_dequeue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_VARIABLE_ITEMS,
                                      __IS_MC, available);
}

unsigned
cne_ring_sc_dequeue_burst_elem(cne_ring_t *r, void *obj_table, unsigned int esize, unsigned int n,
                               unsigned int *available)
{
    return __cne_ring_do_dequeue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_VARIABLE_ITEMS,
                                      __IS_SC, available);
}

unsigned int
cne_ring_dequeue_burst_elem(cne_ring_t *r, void *obj_table, unsigned int esize, unsigned int n,
                            unsigned int *available)
{
    return __cne_ring_do_dequeue_elem(r, obj_table, esize, n, CNE_RING_QUEUE_VARIABLE_ITEMS,
                                      ((struct cne_ring *)r)->cons.single, available);
}
