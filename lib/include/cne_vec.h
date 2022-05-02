/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

/* Created by Keith Wiles @ intel.com */

#ifndef __CNE_VEC_H
#define __CNE_VEC_H

#include <string.h>        // for memcpy
#include <sys/queue.h>
#include <pthread.h>           // for pthread_cond_t, pthread_mutex_t
#include <cne_common.h>        // for __cne_always_inline, CNDP_API
#include <cne_prefetch.h>
#include <mempool.h>        // for mempool_t, mempool_get, mempool_g...
#include <pktmbuf.h>        // for pktmbuf_free, pktmbuf_t
#include <stdint.h>         // for uint16_t, uint32_t, uint64_t
#include <stdio.h>          // for NULL, FILE
#include <stdlib.h>         // for free

#include "cne_branch_prediction.h"        // for unlikely

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VEC_FREE_FLAG      = 0x0001, /**< Vector is free */
    VEC_DONT_FREE_FLAG = 0x0002  /**< Do not free this vector maybe static */
} vec_flag_t;

typedef struct vec_hdr {
    uint16_t flags; /**< Flags for Vec structure */
    uint16_t len;   /**< Number of pointers in vector list */
    uint16_t tlen;  /**< Total number of entries possible */
    uint16_t rsvd;  /** Reserved */
    void *pool;     /**< pool from were the vector was allocated */
} vec_hdr_t;

/**
 * Macro to create local variable for the vec_* macros
 */
#define _V(_x) _v_##_x

/**
 * Return the vector header from the vector list pointer
 * @param v
 *   The vector pointer
 * @return
 *   Pointer to the vector header
 */
static inline vec_hdr_t *
vec_header(void *vec)
{
    return (vec_hdr_t *)CNE_PTR_SUB(vec, sizeof(vec_hdr_t));
}

/**
 * Return the vector data pointer from the vector header pointer
 * @param h
 *   The vector header pointer
 * @return
 *   Pointer to the vector address
 */
static inline void *
vec_data(void *h)
{
    return (void *)CNE_PTR_ADD(h, sizeof(vec_hdr_t));
}

/**
 * return the end vector address of the vector list
 *
 * @param vec
 *   The vector list structure pointer
 * @return
 *   The address of the vector location or NULL on error.
 */
#define vec_end(vec) ((vec) + vec_header(vec)->len)

/**
 * return the end vector address of the vector list
 *
 * @param vec
 *   The vector list structure pointer
 * @return
 *   The address of the vector location or NULL on error.
 */
#define vec_end(vec) ((vec) + vec_header(vec)->len)

#define vec_find_index(vec, v) -1

/**
 * Initialize a vector with the given flags
 *
 * @param hv
 *   The vector structure header address
 * @param n
 *   The number of entries in the vector
 * @param flags
 *   The flags to be set in the vector structure
 */
#define vec_init(hv, n, p, f)                  \
    ({                                         \
        vec_hdr_t *_V(hx) = (vec_hdr_t *)(hv); \
        _V(hx)->len       = 0;                 \
        _V(hx)->tlen      = (n);               \
        _V(hx)->flags     = (f);               \
        _V(hx)->pool      = (p);               \
        vec_data(_V(hx));                      \
    })

/**
 * Allocate a vector list
 *
 * @param v
 *   The vector pointer to store the vector list
 * @param n
 *   The number of entries in the list
 * @param v
 *   The v pointer is the address of the allocated data.
 * @return
 *   The pointer to the vector
 */
#define _vec_alloc(v, n, _t)                                       \
    ({                                                             \
        size_t _V(s)     = ((n) * sizeof(_t)) + sizeof(vec_hdr_t); \
        vec_hdr_t *_V(h) = calloc(1, _V(s));                       \
        (_V(h) == NULL) ? NULL : vec_init(_V(h), n, NULL, 0);      \
    })

#define vec_alloc(_v, _n)     _vec_alloc(_v, _n, typeof(_v))
#define vec_alloc_ptr(_v, _n) _vec_alloc(_v, _n, void *)
#define vec_free(v)              \
    do {                         \
        if (v)                   \
            free(vec_header(v)); \
    } while (0)

/**
 * Iterate over the entries in the vector list
 *
 * @param var
 *    The variable pointer to use for each value, needs to be declared
 * @param vec
 *    The vector list pointer to index over.
 */
#define vec_foreach(var, vec) for (var = (vec); var < vec_end(vec); var++)

#define vec_foreach_ptr(var, vec) \
    for (uint16_t _V(_i) = 0; (var = (vec)[_V(_i)], _V(_i) < vec_len(vec)); _V(_i)++)

#define vec_index _V(_i)

#define vec_find_delete(vec, d) \
    do {                        \
        (void)vec;              \
        (void)d;                \
    } while (0)

/**
 * Calculate the size of a vector structure for the given number of entries
 *
 * @param cnt
 *   The number of entries in the vector
 * @param _t
 *   The typeof the vector list
 * @return
 *   Number of bytes for the vector size.
 */
#define vec_calc_size(n, _t) \
    CNE_ALIGN_CEIL((n * sizeof(_t)) + sizeof(vec_hdr_t), CNE_CACHE_LINE_SIZE)

/**
 * Set the vector to be free used for mempool or free list designs
 *
 * @param v
 *   The vector pointer
 */
static inline void
vec_set_free(vec_hdr_t *v)
{
    v->flags |= VEC_FREE_FLAG;
}

/**
 * Test if the vector is free
 *
 * @param v
 *   The vector pointer
 * @return
 *   True if the vector is free or 0 if not.
 */
static inline int
vec_is_free(vec_hdr_t *v)
{
    return v->flags & VEC_FREE_FLAG;
}

/**
 * Test the dont free flag and return value
 *
 * @param v
 *   The vector pointer
 * @return
 *   True if the vector is free or 0 if not.
 */
static inline int
vec_is_dont_free(vec_hdr_t *v)
{
    return v->flags & VEC_DONT_FREE_FLAG;
}

/**
 * Set the dont free flag
 *
 * @param v
 *   The vector pointer
 */
static inline void
vec_set_dont_free(vec_hdr_t *v)
{
    if (v)
        v->flags |= VEC_DONT_FREE_FLAG;
}

/**
 * Clear the dont free flag
 *
 * @param v
 *   The vector pointer
 */
static inline void
vec_clr_dont_free(vec_hdr_t *v)
{
    if (v)
        v->flags &= ~VEC_DONT_FREE_FLAG;
}

/**
 * Return the number entries in the vector
 *
 * @param v
 *   The vector pointer
 * @return
 *   The vector size or number of entries in vector
 */
#define vec_len(v) vec_header(v)->len

/**
 * Return the total number entries in the vector
 *
 * @param v
 *   The vector pointer
 * @return
 *   The vector size or number of entries in vector
 */
#define vec_tlen(v) vec_header(v)->tlen

/**
 * Set the vector length
 *
 * @param v
 *   The vector pointer
 * @param n
 *   The length of the vector list
 */
#define vec_set_len(v, n) vec_len(v) = (n)

/**
 * Return the max number of entries in the list.
 *
 * @param v
 *   The vector pointer
 * @return
 *   The max number of entries allowed in the list.
 */
#define vec_max_len(v) vec_header(v)->tlen

/**
 * Set the max number of vectors allowed in the vector
 *
 * @param v
 *   The vector pointer
 * @param n
 *   The max number of vectors
 */
#define vec_set_max_len(v, n) vec_tlen(v) = (n)

/**
 * Decrease the number of vectors in the list
 *
 * @param v
 *   The vector pointer
 */
#define vec_dec_len(v) vec_header(v)->len--

/**
 * Increment the number of entries in the vector list.
 *
 * @param v
 *   The vector pointer
 */
#define vec_inc_len(v) vec_header(v)->len++

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"

/**
 * Add one vector to the list and return new size.
 *
 * @param v
 *   The vector pointer
 * @param val
 *   The vector entry to add
 * @return
 *   The length of the list before adding the pointer
 */
#define vec_add_ptr(vec, v)                 \
    ({                                      \
        vec_hdr_t *_V(h) = vec_header(vec); \
        uint16_t _V(l)   = _V(h)->len;      \
        if (_V(h)->len < _V(h)->tlen)       \
            (vec)[_V(h)->len++] = (v);      \
        else                                \
            _V(l) = -1;                     \
        _V(l);                              \
    })

#define vec_full(vec)                               \
    ({                                              \
        vec_hdr_t *_V(h) = vec_header(vec);         \
        (_V(h)->len >= _V(h)->tlen) ? true : false; \
    })

/**
 * Return entry value at the given index offset.
 *
 * @param v
 *   The vector pointer
 * @param n
 *   The vector index location
 * @return
 *   The value at the given index location, could be NULL or empty
 */
#define vec_ptr_at_index(vec, n) (vec)[(n)]

/**
 * Set a vector at a given list location
 *
 * @param v
 *   The vector pointer
 * @param idx
 *   The index value to place the entry
 * @param val
 *   The value to place at index.
 */
#define vec_set_at_index(vec, v, n) (vec)[(n)] = v

/**
 * return the vector address at the given index location
 *
 * @param vec
 *   The vector list structure pointer
 * @param n
 *   The index location in the list.
 * @return
 *   The address of the vector location or NULL on error.
 */
#define vec_addr_at_index(vec, n) &(vec)[(n)]

#pragma GCC diagnostic pop

/**
 * Free a set of mbufs pointers in a vector list
 *
 * @param vec
 *    The vector list pointer
 */
static inline void
vec_free_mbufs(void *vec)
{
    if (vec) {
        vec_hdr_t *h = vec_header(vec);
        int cnt      = vec_len(h);

        h->len = 0;
        if (likely(cnt))
            pktmbuf_free_bulk(vec, cnt);
    }
}

/**
 * Pop a value off the end of the vector list.
 *
 * @param vec
 *    The vector list pointer
 * @param val
 *    A pointer to place the entry from the list that was popped.
 * @return
 *    0 if empty list or 1 if the value is valid.
 */
#define vec_pop(vec) (vec)[--vec_header(vec)->len]

/**
 * Free the mbuf entry at the given index location, if not NULL
 *
 * @param vec
 *   The vector list pointer
 * @param idx
 *   The index into the list of entries
 */
#define vec_free_mbuf_at_index(vec, n) pktmbuf_free((vec)[n])

/**
 * Move an entry from one vector list to another by adding the entry using index value
 *
 * @param to
 *    The vector list pointer to add the entry if valid in the from list
 * @param from
 *    The vector list pointer to remove the entry based on index value
 * @param idx
 *    The index location to extract the entry in the *from* list.
 * @return
 *    index location of entry in the *to* list or -1 on error
 */
#define vec_move_at_index(t, f, n)              \
    do {                                        \
        vec_add_ptr(t, vec_ptr_at_index(f, n)); \
        vec_ptr_at_index(f, n) = 0;             \
    } while (0)

#define vec_add_at_index(vec, d, idx) (vec)[idx] = d

/**
 * Copy an entry from one list to another by adding the entry located at the index
 *
 * @param to
 *   The vector list to add the entry if found in the *from* list
 * @param from
 *   The vector list pointer to copy the entry at the given index from
 * @param idx
 *   The index location in the *from* list to get the entry to copy
 */
#define vec_copy_at_index(t, f, n)            \
    do {                                      \
        typeof(f) v = vec_ptr_at_index(f, n); \
        vec_add_ptr(t, v);                    \
    } while (0)

/**
 * Dump out a vec_hdr_t structure
 *
 * @param msg
 *   A message to be printed before data, can be NULL.
 * @param vec
 *   A vector to printout
 */
static inline void
vec_dump(const char *msg, void *vec)
{
    vec_hdr_t *h;

    cne_printf("  [orange]%-8s[]  ", msg ? msg : "");
    if (!vec) {
        cne_printf(" *** Vector is NULL ***\n");
        return;
    }

    h = vec_header(vec);

    cne_printf("[orange]%-8s[]  ", msg ? msg : "");
    cne_printf("Vec @ %p, ", vec);
    cne_printf("flags 0x%04x, ", h->flags);
    cne_printf("len   %5d, ", h->len);
    cne_printf("tlen  %5d, ", h->tlen);
    cne_printf("pool  %p\n", h->pool);
}

#ifdef __cplusplus
}
#endif

#endif /* __CNE_VEC_H */
