/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 * Copyright (c) 2016 6WIND S.A.
 */

#include <stdio.h>                        // for NULL, size_t, FILE, stdout
#include <stdint.h>                       // for uint32_t
#include <string.h>                       // for memcpy
#include <inttypes.h>                     // for PRIu32
#include <errno.h>                        // for EINVAL, errno
#include <cne_common.h>                   // for MEMPOOL_CACHE_MAX_SIZE, __cne_unused
#include <cne_log.h>                      // for CNE_LOG_ERR, CNE_NULL_RET, CNE_ER...
#include <cne_branch_prediction.h>        // for unlikely
#include <stdlib.h>                       // for calloc, free

#include "mempool.h"
#include "mempool_private.h"        // for cne_mempool, mempool_cache, mempo...
#include "mempool_ring.h"           // for mempool_ring_dequeue, mempool_rin...
#include "cne.h"                    // for cne_max_threads, cne_id
#include "cne_stdio.h"              // for cne_fprintf

#define CACHE_FLUSHTHRESH_MULTIPLIER 1.5
#define CALC_CACHE_FLUSHTHRESH(c)    ((typeof(c))((c)*CACHE_FLUSHTHRESH_MULTIPLIER))

static void
mempool_add_elem(struct cne_mempool *mp, __cne_unused void *opaque, void *obj __cne_unused)
{
    mp->populated_sz++;
}

/* call obj_cb() for each mempool element */
uint32_t
mempool_obj_iter(mempool_t *_mp, mempool_obj_cb_t *obj_cb, void *obj_cb_arg)
{
    struct cne_mempool *mp = _mp;
    void *obj;
    unsigned n = 0;

    obj = mp->objmem;
    for (uint32_t i = 0; i < mp->obj_cnt; i++) {
        obj_cb(mp, obj_cb_arg, obj, n);
        obj = (void *)((char *)obj + mp->obj_sz);
        n++;
    }

    return n;
}

static int
mempool_alloc_once(struct cne_mempool *mp)
{
    /* create the internal ring if not already done */
    return (!mp->objring) ? mempool_ring_alloc(mp) : 0;
}

/* Add objects in the pool. Return the number of objects added
 * or a negative value on error.
 */
int
mempool_populate(mempool_t *_mp, char *addr, size_t len)
{
    struct cne_mempool *mp = _mp;
    unsigned i             = 0;
    size_t off;
    int ret;

    ret = mempool_alloc_once(mp);
    if (ret)
        return ret;

    if (addr == NULL) {
        addr = calloc(1, len);
        if (!addr)
            goto fail;
        mp->free_objmem = 1;
    }

    off = CNE_PTR_ALIGN_CEIL(addr, 8) - addr;

    if (off > len) {
        ret = -EINVAL;
        goto fail;
    }
    mp->objmem    = addr;
    mp->objmem_sz = len;

    i = mempool_ring_populate(mp, (char *)addr + off, mempool_add_elem, NULL);

    /* not enough room to store one object */
    if (i == 0) {
        ret = -EINVAL;
        goto fail;
    }
    return i;

fail:
    return ret;
}

/* free a mempool */
void
mempool_destroy(mempool_t *_mp)
{
    struct cne_mempool *mp = _mp;

    if (mp == NULL)
        return;

    if (mp->cache)
        free(mp->cache);
    if (mp->stats)
        free(mp->stats);

    if (mp->free_objmem)
        free(mp->objmem);

    mempool_ring_free(mp);
    free(mp);
}

static void
mempool_cache_init(struct mempool_cache *cache, uint32_t size)
{
    cache->size        = size;
    cache->flushthresh = CALC_CACHE_FLUSHTHRESH(size);
    cache->len         = 0;
}

/* create an empty mempool */
mempool_t *
mempool_create_empty(struct mempool_cfg *ci)
{
    struct cne_mempool *mp = NULL;
    int thds               = cne_max_threads();

    if (thds < 0) {
        errno = EINVAL;
        CNE_NULL_RET("Threads have not been initialized\n");
    }

    /* asked for zero items or zero size of each object */
    if (ci->objcnt == 0 || ci->objsz == 0) {
        errno = EINVAL;
        CNE_NULL_RET("Item count is zero\n");
    }

    if (ci->cache_sz > MEMPOOL_CACHE_MAX_SIZE) {
        errno = EINVAL;
        CNE_NULL_RET("Cache size too large %d for mempool\n", ci->cache_sz);
    }

    mp = calloc(1, sizeof(struct cne_mempool));
    if (mp == NULL)
        CNE_ERR_GOTO(exit_mempool_destroy, "calloc(%ld): failed\n", sizeof(struct cne_mempool));

    /* init the mempool structure */
    mp->obj_cnt  = ci->objcnt;
    mp->obj_sz   = ci->objsz;
    mp->cache_sz = ci->cache_sz;
    if (mp->cache_sz) {
        mp->cache = calloc(thds, sizeof(struct mempool_cache));
        if (!mp->cache)
            goto exit_mempool_destroy;
    }

    mp->stats = calloc(thds, sizeof(struct mempool_stats));
    if (!mp->stats)
        goto exit_mempool_destroy;

    /* Init all default caches. */
    if (ci->cache_sz != 0) {
        for (int i = 0; i < thds; i++)
            mempool_cache_init(&mp->cache[i], ci->cache_sz);
    }

    return mp;

exit_mempool_destroy:
    mempool_destroy(mp);
    return NULL;
}

/* create the mempool */
mempool_t *
mempool_create(struct mempool_cfg *ci)
{
    struct cne_mempool *mp;

    if (!ci)
        return NULL;

    mp = mempool_create_empty(ci);
    if (mp == NULL)
        return NULL;

    /* call the mempool private initializer */
    if (ci->mp_init)
        ci->mp_init(mp, ci->mp_init_arg);

    if (mempool_populate(mp, ci->addr, ci->objcnt * ci->objsz) < 0)
        goto fail;

    /* call the object initializers */
    if (ci->obj_init)
        mempool_obj_iter(mp, ci->obj_init, ci->obj_init_arg);

    return mp;

fail:
    mempool_destroy(mp);
    return NULL;
}

struct mempool_cache *
mempool_default_cache(mempool_t *_mp)
{
    struct cne_mempool *mp = _mp;
    int id                 = cne_id();

    if (!mp || (mp->cache_sz == 0))
        return NULL;

    return &mp->cache[id];
}

/**
 * @internal Put several objects back in the mempool; used internally.
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to store back in the mempool, must be strictly
 *   positive.
 * @param cache
 *   A pointer to a mempool cache structure. May be NULL if not needed.
 */
static void
__mempool_generic_put(mempool_t *_mp, void *const *obj_table, unsigned int n,
                      struct mempool_cache *cache)
{
    struct cne_mempool *mp = _mp;
    void **cache_objs;

    /* increment stat now, adding in mempool always success */
    __MEMPOOL_STAT_ADD(mp, put, n);

    /* No cache provided or if put would overflow mem allocated for cache */
    if (unlikely(cache == NULL || n > MEMPOOL_CACHE_MAX_SIZE))
        goto ring_enqueue;

    cache_objs = &cache->objs[cache->len];

    /*
     * The cache follows the following algorithm
     *   1. Add the objects to the cache
     *   2. Anything greater than the cache min value (if it crosses the
     *   cache flush threshold) is flushed to the ring.
     */

    /* Add elements back into the cache */
    memcpy(&cache_objs[0], obj_table, sizeof(void *) * n);

    cache->len += n;

    if (cache->len >= cache->flushthresh) {
        mempool_ring_enqueue(mp, &cache->objs[cache->size], cache->len - cache->size);
        cache->len = cache->size;
    }

    return;

ring_enqueue:

    /* push remaining objects into the backing ring */
    mempool_ring_enqueue(mp, obj_table, n);
}

void
mempool_generic_put(mempool_t *_mp, void *const *obj_table, unsigned int n,
                    struct mempool_cache *cache)
{
    struct cne_mempool *mp = _mp;

    __mempool_generic_put(mp, obj_table, n, cache);
}

void
mempool_put_bulk(mempool_t *_mp, void *const *obj_table, unsigned int n)
{
    struct cne_mempool *mp      = _mp;
    struct mempool_cache *cache = mempool_default_cache(mp);

    /* push objects to ring */
    mempool_generic_put(mp, obj_table, n, cache);
}

void
mempool_put(mempool_t *_mp, void *obj)
{
    struct cne_mempool *mp = _mp;

    mempool_put_bulk(mp, &obj, 1);
}

/**
 * @internal Get several objects from the mempool; used internally.
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to get, must be strictly positive.
 * @param cache
 *   A pointer to a mempool cache structure. May be NULL if not needed.
 * @return
 *   - >=0: Success; number of objects supplied.
 *   - <0: Error; code of ring dequeue function.
 */
static int
__mempool_generic_get(struct cne_mempool *mp, void **obj_table, unsigned int n,
                      struct mempool_cache *cache)
{
    int ret;
    uint32_t index, len;
    void **cache_objs;

    /* No cache provided or cannot be satisfied from cache */
    if (unlikely(cache == NULL || n >= cache->size))
        goto ring_dequeue;

    cache_objs = cache->objs;

    /* Can this be satisfied from the cache? */
    if (cache->len < n) {
        /* No. Backfill the cache first, and then fill from it */
        uint32_t req = n + (cache->size - cache->len);

        /* How many do we require i.e. number to fill the cache + the request */
        ret = mempool_ring_dequeue(mp, &cache->objs[cache->len], req);
        if (unlikely(ret < 0)) {
            /*
             * In the off chance that we are buffer constrained,
             * where we are not able to allocate cache + n, go to
             * the ring directly. If that fails, we are truly out of
             * buffers.
             */
            goto ring_dequeue;
        }

        cache->len += req;
    }

    /* Now fill in the response ... */
    for (index = 0, len = cache->len - 1; index < n; ++index, len--, obj_table++)
        *obj_table = cache_objs[len];

    cache->len -= n;

    __MEMPOOL_STAT_ADD(mp, get_success, n);

    return 0;

ring_dequeue:

    /* get remaining objects from ring */
    ret = mempool_ring_dequeue(mp, obj_table, n);

    if (ret < 0)
        __MEMPOOL_STAT_ADD(mp, get_fail, n);
    else
        __MEMPOOL_STAT_ADD(mp, get_success, n);

    return ret;
}

int
mempool_generic_get(mempool_t *_mp, void **obj_table, unsigned int n, struct mempool_cache *cache)
{
    struct cne_mempool *mp = _mp;

    return __mempool_generic_get(mp, obj_table, n, cache);
}

int
mempool_get_bulk(mempool_t *_mp, void **obj_table, unsigned int n)
{
    struct cne_mempool *mp = _mp;
    /* get objects from ring */
    struct mempool_cache *cache = mempool_default_cache(mp);

    return mempool_generic_get(mp, obj_table, n, cache);
}

int
mempool_get(mempool_t *_mp, void **obj_p)
{
    struct cne_mempool *mp = _mp;

    return mempool_get_bulk(mp, obj_p, 1);
}

/* Return the number of entries in the mempool */
unsigned int
mempool_avail_count(const mempool_t *_mp)
{
    const struct cne_mempool *mp = _mp;

    return mempool_ring_get_count(mp);
}

/* return the number of entries allocated from the mempool */
unsigned int
mempool_in_use_count(const mempool_t *_mp)
{
    const struct cne_mempool *mp = _mp;

    return mp->obj_cnt - mempool_avail_count(mp);
}

int
mempool_full(const mempool_t *_mp)
{
    const struct cne_mempool *mp = _mp;

    return !!(mempool_avail_count(mp) == mp->obj_cnt);
}

int
mempool_empty(const mempool_t *_mp)
{
    const struct cne_mempool *mp = _mp;

    return !!(mempool_avail_count(mp) == 0);
}

/* dump the status of the mempool on the console */
void
mempool_dump(mempool_t *_mp)
{
    struct cne_mempool *mp = _mp;
    unsigned common_count;

    if (mp == NULL)
        return;

    cne_printf("[orange]mempool @ [cyan]%p [magenta]ring [cyan]%p[]\n", (void *)mp, mp->objring);
    cne_printf("   [magenta]obj_cnt [cyan]%" PRIu32 "[]", mp->obj_cnt);
    cne_printf(" [magenta]obj_sz [cyan]%" PRIu32 "[]", mp->obj_sz);

    common_count = mempool_ring_get_count(mp);
    cne_printf(" [magenta]free ring_cnt [cyan]%" PRIu32 " [magenta]cache size [cyan]%" PRIu32
               "[]\n",
               common_count, mp->cache_sz);

    if (mp->stats) {
        cne_printf("   [magenta]Put         Bulk[]: [cyan]%12" PRIu64 "[]\n", mp->stats->put_bulk);
        cne_printf("   [magenta]Put         Objs[]: [cyan]%12" PRIu64 "[]\n", mp->stats->put_objs);
        cne_printf("   [magenta]Get Success Bulk[]: [cyan]%12" PRIu64 "[]\n",
                   mp->stats->get_success_bulk);
        cne_printf("   [magenta]Get Success Objs[]: [cyan]%12" PRIu64 "[]\n",
                   mp->stats->get_success_objs);
        cne_printf("   [magenta]Get failed  Bulk[]: [cyan]%12" PRIu64 "[]\n",
                   mp->stats->get_fail_bulk);
        cne_printf("   [magenta]Get failed  Objs[]: [cyan]%12" PRIu64 "[]\n",
                   mp->stats->get_fail_objs);
    }

    if (!mp->cache_sz)
        return;

    cne_printf("   [orange]Cache Info[]:\n");
    for (uint32_t i = 0; i < (uint32_t)cne_max_threads(); i++) {
        struct mempool_cache *cache = &mp->cache[i];
        if (cache && cache->len)
            cne_printf("     [magenta]cache [cyan]%3" PRIu32 "[]: [magenta]len [cyan]%4" PRIu32
                       "[]\n",
                       i, cache->len);
    }
}

void *
mempool_ring_addr(mempool_t *_mp)
{
    struct cne_mempool *mp = _mp;

    return (mp) ? mp->objring : NULL;
}

void *
mempool_buff_addr(mempool_t *_mp)
{
    struct cne_mempool *mp = _mp;

    return (mp) ? mp->objmem : NULL;
}

int
mempool_objcnt(mempool_t *_mp)
{
    struct cne_mempool *mp = _mp;

    return (mp) ? (int)mp->obj_cnt : -1;
}

int
mempool_objsz(mempool_t *_mp)
{
    struct cne_mempool *mp = _mp;

    return (mp) ? (int)mp->obj_sz : -1;
}

int
mempool_cache_sz(mempool_t *_mp)
{
    struct cne_mempool *mp = _mp;

    return (mp) ? (int)mp->cache_sz : -1;
}

int
mempool_cache_len(mempool_t *_mp, int idx)
{
    struct cne_mempool *mp = _mp;

    if (!mp || mp->cache_sz == 0 || idx > cne_max_threads())
        return -1;
    return (int)mp->cache[idx].len;
}

int
mempool_obj_index(mempool_t *_mp, void *obj)
{
    struct cne_mempool *mp = _mp;

    if (mp) {
        if (obj >= mp->objmem && obj < CNE_PTR_ADD(mp->objmem, (mp->obj_cnt * mp->obj_sz))) {
            uint64_t *addr = CNE_PTR_SUB(obj, (uintptr_t)mp->objmem);
            uintptr_t sz   = (uintptr_t)mp->obj_sz;

            return (int)((uintptr_t)addr / sz);
        }
    }
    return -1;
}

void *
mempool_obj_at_index(mempool_t *_mp, int idx)
{
    struct cne_mempool *mp = _mp;

    if (mp) {
        void *p = CNE_PTR_ADD(mp->objmem, (idx * mp->obj_sz));

        if (p < CNE_PTR_ADD(mp->objmem, (mp->obj_sz * mp->obj_cnt)))
            return p;
    }

    return NULL;
}
