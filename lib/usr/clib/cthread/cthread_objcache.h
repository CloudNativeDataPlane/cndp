/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _CTHREAD_OBJCACHE_H_
#define _CTHREAD_OBJCACHE_H_

#include <string.h>

#include <cne_per_thread.h>

#include "cthread_int.h"
#include "cthread_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

CNE_DECLARE_PER_THREAD(struct cthread_sched *, this_sched);

struct cthread_objcache {
    struct cthread_queue *q;      /**< cthread queue */
    size_t obj_size;              /**< Size of the object cache */
    int prealloc_size;            /**< Preallocated size of the cache */
    char name[CTHREAD_NAME_SIZE]; /**< Name of the object cache */
};

/**
 * Create a cache
 *
 * @param name
 *   The name of the object cache
 * @param obj_size
 *   The size of the object cache
 * @param prealloc_size
 *   The preallocated size of the object cache.
 * @return
 *   The cthread_objcache pointer or NULL on error
 */
static inline struct cthread_objcache *
_cthread_objcache_create(const char *name, size_t obj_size, int prealloc_size)
{
    struct cthread_objcache *c = calloc(1, sizeof(struct cthread_objcache));

    if (c == NULL)
        return NULL;

    c->q = _cthread_queue_create("cache queue");
    if (c->q == NULL) {
        free(c);
        return NULL;
    }
    c->obj_size      = obj_size;
    c->prealloc_size = prealloc_size;

    c->name[0] = '\0';
    if (name != NULL)
        strlcpy(c->name, name, sizeof(c->name));

    return c;
}

/**
 * Destroy an objcache
 *
 * @param c
 *   The objcache to destroy
 * @return
 *   0 on success or -1 on error
 */
static inline int
_cthread_objcache_destroy(struct cthread_objcache *c)
{
    if (c == NULL)
        return 0;
    if (_cthread_queue_destroy(c->q) == 0) {
        free(c);
        return 0;
    }
    return -1;
}

/**
 * Allocate an object from an object cache
 *
 * @param c
 *   The objcache pointer
 * @return
 *   The cthread_objcache pointer or NULL on error
 */
static inline void *
_cthread_objcache_alloc(struct cthread_objcache *c)
{
    int i;
    void *data;
    struct cthread_queue *q = c->q;
    size_t obj_size         = c->obj_size;
    int prealloc_size       = c->prealloc_size;

    data = _cthread_queue_remove(q);

    if (data == NULL) {
        for (i = 0; i < prealloc_size; i++) {
            data = calloc(1, obj_size);
            if (data == NULL)
                return NULL;

            _cthread_queue_insert_mp(q, data);
        }
        data = _cthread_queue_remove(q);
    }
    return data;
}

/**
 * free an object to a cache
 *
 * @param c
 *   The objcache pointer
 */
static inline void
_cthread_objcache_free(struct cthread_objcache *c, void *obj)
{
    _cthread_queue_insert_mp(c->q, obj);
}

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_OBJCACHE_H_ */
