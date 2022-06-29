/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_FIB_INFO_H
#define __CNET_FIB_INFO_H

/**
 * @file
 * CNET FIB support routines and definitions.
 */

#include <stddef.h>               // for NULL
#include <stdint.h>               // for uint8_t, uint32_t
#include <sys/queue.h>            // for TAILQ_HEAD
#include <bsd/sys/queue.h>        // for TAILQ_HEAD

#include <cne_rwlock.h>
#include <cne_fib.h>

struct rt4_entry;
#ifdef __cplusplus
extern "C" {
#endif

typedef struct fib_info {
    struct cne_fib *fib;  /**< fib structure */
    void **idx2obj;       /**< Index to object array */
    cne_rwlock_t lock;    /**< lock to protect idx2obj */
    uint32_t objcnt;      /**< Maximum number of objects (pow2) */
    uint32_t mask;        /**< Mask number of objects */
    uint32_t index_shift; /**< Shift number of bits to get next index */
    uint32_t index;       /**< Current index in idx2obj array */
} fib_info_t;

/**
 * Return the object index for the idx2obj array.
 *
 * @param fi
 *   The fib_info_t structure pointer.
 * @param idx
 *   The index of the object which includes the nexthop of some value in the upper bits.
 * @return
 *   The index of the object or UINT32_MAX if fib_info_t pointer is NULL.
 */
static inline uint32_t
fi_obj_index(fib_info_t *fi, uint32_t idx)
{
    uint32_t obj_idx = UINT32_MAX;

    if (fi)
        obj_idx = (idx & ((1UL << fi->index_shift) - 1));

    return obj_idx;
}

/**
 * Allocate the FIB information structure for a given object. The object
 * is added to the idx2obj table if space is available.
 *
 * @param fi
 *   The FIB information structure pointer.
 * @param obj
 *   The object pointer to put in the idx2obj table.
 * @return
 *   -1 on error or the index value into the idx2obj table.
 */
static inline int
fib_info_alloc(fib_info_t *fi, void *obj)
{
    uint32_t idx, prev_idx;

    cne_rwlock_write_lock(&fi->lock);
    idx = prev_idx = fi->index;

    prev_idx--;
    prev_idx = (prev_idx & fi->mask);
    while (fi->idx2obj[idx] && (idx != prev_idx)) {
        idx++;
        idx = (idx & fi->mask);
    }

    if (idx == prev_idx) {
        cne_rwlock_write_unlock(&fi->lock);
        return -1;
    }

    fi->idx2obj[idx] = obj;
    fi->index        = idx;
    cne_rwlock_write_unlock(&fi->lock);

    return idx;
}

/**
 * Remove the object from the FIB information structure and release the entry.
 *
 * @param fi
 *   The FIB information structure pointer.
 * @param idx
 *   The index location on the FIB table to release.
 * @return
 *   The object pointer is returned and value could be NULL if an error.
 */
static inline void *
fib_info_free(fib_info_t *fi, uint32_t idx)
{
    void *obj = NULL;

    cne_rwlock_write_lock(&fi->lock);

    idx = fi_obj_index(fi, idx);

    if (idx < fi->objcnt) {
        obj = fi->idx2obj[idx];

        fi->idx2obj[idx] = NULL;
    }
    cne_rwlock_write_unlock(&fi->lock);
    return obj;
}

/**
 * Destroy and free resources in the FIB information structure.
 *
 * @param fi
 *   The FIB information structure pointer.
 */
static inline void
fib_info_destroy(fib_info_t *fi)
{
    if (fi) {
        if (fi->idx2obj)
            free(fi->idx2obj);
        if (fi->fib)
            cne_fib_free(fi->fib);
        free(fi);
    }
}

/**
 * Create the FIB information structure.
 *
 * @param fib
 *   The FIB table to add to the FIB information structure
 * @param objcnt
 *   The number of objects to support in the idx2obj table. The value will be aligned
 *   to the power of 2 value.
 * @param index_shift
 *   The index value used to shift the value to the index value in the object being stored.
 *   This allows for the object pointer, which could be a real pointer or a uint64_t value
 *   with a upper value and lower value encoded into the object pointer.
 * @return
 *   NULL on error or pointer to the FIB information structure
 */
static inline fib_info_t *
fib_info_create(struct cne_fib *fib, uint32_t objcnt, uint32_t index_shift)
{
    fib_info_t *fi;

    if (!fib || objcnt == 0 || index_shift == 0)
        return NULL;

    fi = calloc(1, sizeof(fib_info_t));
    if (fi) {
        fi->fib         = fib;
        fi->objcnt      = cne_align32pow2(objcnt);
        fi->mask        = fi->objcnt - 1;
        fi->index_shift = index_shift;
        cne_rwlock_init(&fi->lock);

        fi->idx2obj = calloc(fi->objcnt, sizeof(void *));
        if (!fi->idx2obj) {
            fib_info_destroy(fi);
            return NULL;
        }
    }

    return fi;
}

/**
 * Get the object pointed to by the index value in the FIB info structure
 *
 * @param fi
 *   The FIB information structure pointer.
 * @param idx
 *   The value to be used to index into the idx2obj table.
 * @return
 *   The object value or pointer is return or NULL if an error occurred.
 */
static inline void *
fib_info_object_get(fib_info_t *fi, uint32_t idx)
{
    if (!fi)
        return NULL;

    idx = fi_obj_index(fi, idx);

    if (idx >= fi->objcnt)
        return NULL;

    return fi->idx2obj[idx];
}

/**
 * Is the index value a valid value.
 *
 * @param fi
 *   The FIB information structure pointer.
 * @param idx
 *   The index value to validate.
 * @return
 *   1 on valid value or 0 if not a valid value.
 */
static inline int
fib_info_index_valid(fib_info_t *fi, uint32_t idx)
{
    idx = fi_obj_index(fi, idx);

    if (fi && (idx < fi->objcnt))
        return 1;

    return 0;
}

/**
 * Return the FIB pointer from a valid FIB info structure.
 *
 * @param fi
 *   The FIB information structure pointer.
 * @return
 *   NULL on error or pointer to the FIB structure.
 */
static inline struct cne_fib *
fib_info_get_fib(fib_info_t *fi)
{
    return (fi) ? fi->fib : NULL;
}

typedef int (*fib_func_t)(void *obj, void *arg);

/**
 * Iterate over the idx2obj values and call a function from caller.
 *
 * @param fi
 *   The FIB information structure pointer.
 * @param func
 *   The function to call in the form of 'int (*fn)(void *obj, void *arg)'
 * @param arg
 *   A void pointer supplied to the function being called.
 * @return
 *   -1 on error or 0 on success.
 */
static inline int
fib_info_foreach(fib_info_t *fi, fib_func_t func, void *arg)
{
    if (fi) {
        for (uint32_t i = 0; i < fi->objcnt; i++) {
            void *obj = fib_info_object_get(fi, i);

            if (obj && (func(obj, arg) < 0))
                return -1;
        }
    }
    return 0;
}

/**
 * Get the FIB information objects into objects for given count 'n'
 *
 * @param fi
 *   The FIB information structure pointer.
 * @param idxs
 *   An array of index values to use in returning the object values.
 * @param objs
 *   An array to return the objects for the given index values.
 * @param n
 *   The number of indexes in the idxs array and must match the size for the objs array.
 * @return
 *   -1 on error or the number of objects found and returned in objs array
 */
static inline int
fib_info_get(fib_info_t *fi, uint64_t *idxs, void **objs, int n)
{
    void *objects[n];
    int i, k;

    if (!fi || !idxs)
        return -1;

    if (!objs)
        objs = objects;

    memset(objs, 0, sizeof(void *) * n);

    for (i = 0, k = 0; i < n; i++) {
        objs[i] = fib_info_object_get(fi, (uint32_t)idxs[i]);

        if (objs[i])
            k++;
    }
    return k;
}

/**
 * Do a build lookup in the FIB table and return the objects
 *
 * @param fi
 *   The FIB information structure pointer.
 * @param ip
 *   The array of IPv4 addresses to lookup in the FIB table.
 * @param objs
 *   The array of returning objects.
 * @param n
 *   The number of IPv4 addresses and the size of the object array
 * @return
 *   -1 on error or number of objects returned
 */
static inline int
fib_info_lookup(fib_info_t *fi, uint32_t *ip, void **objs, int n)
{
    if (fi && ip) {
        uint64_t nh[n];

        if (cne_fib_lookup_bulk(fi->fib, ip, nh, n) == 0)
            return fib_info_get(fi, nh, objs, n);
    }
    return 0;
}

/**
 * Bulk lookup of IPv4 addresses and return the index values of the objects
 *
 * @param fi
 *   The FIB information structure pointer.
 * @param ip
 *   The array of IPv4 addresses to lookup in the FIB table.
 * @param idxs
 *   The array of index values to return
 * @param n
 *   The number of IPv4 addresses and the size of the object array
 * @return
 *   -1 on error or number of objects returned
 */
static inline int
fib_info_lookup_index(fib_info_t *fi, uint32_t *ip, uint64_t *idxs, int n)
{
    if (!fi || !ip || !idxs)
        return -1;
    return cne_fib_lookup_bulk(fi->fib, ip, idxs, n) == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* __CNET_FIB_INFO_H */
