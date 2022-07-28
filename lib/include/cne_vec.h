/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNE_VEC_H
#define __CNE_VEC_H

#include <stdint.h>        // for uint16_t, uint32_t, uint64_t
#include <stdio.h>         // for NULL, FILE
#include <stdlib.h>        // for free

#include <cne_common.h>        // for __cne_always_inline, CNDP_API
#include <cne_prefetch.h>
#include <cne_stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VEC_REALLOC_SIZE 8 /**< Number of objects to allocate per realloc */

typedef struct vec_hdr {
    uint32_t len;     /**< Number of pointers in vector list */
    uint32_t alen;    /**< Allocated length of vector list */
    uint16_t esize;   /**< Element size */
    uint16_t rsvd[3]; /**< Reserved space */
    uint8_t data[0];  /**< Location of vector data */
} vec_hdr_t;

/**
 * Macro to create local variable for the vec_* macros
 */
#define _V(_x) _v_##_x

/**
 * Return the vector header from the vector list pointer
 *
 * @param vec
 *   The vector pointer
 * @return
 *   Pointer to the vector header
 */
static inline vec_hdr_t *
vec_header(void *vec)
{
    return (vec_hdr_t *)((vec) ? CNE_PTR_SUB(vec, sizeof(vec_hdr_t)) : NULL);
}

/**
 * return the end vector address of the vector list
 *
 * @param vec
 *   The vector list structure pointer
 * @return
 *   The address of the vector location or NULL on error.
 */
#define vec_end(vec) &(vec)[vec_header(vec)->len]

/**
 * Initialize a vector header
 *
 * @param hv
 *   The vector structure header address
 * @param al
 *   The allocated size of the vector
 * @param es
 *   The vector element size
 * @return
 *   Pointer to vector data
 */
#define vec_init(hv, al, es)                 \
    ({                                       \
        vec_hdr_t *_V(hx);                   \
        _V(hx)          = (vec_hdr_t *)(hv); \
        _V(hx)->len     = 0;                 \
        _V(hx)->alen    = al;                \
        _V(hx)->esize   = es;                \
        _V(hx)->rsvd[0] = 0;                 \
        _V(hx)->rsvd[1] = 0;                 \
        _V(hx)->rsvd[2] = 0;                 \
        (void *)_V(hx)->data;                \
    })

/**
 * reallocate the vector data structure
 *
 * @param vec
 *   The pointer to hold the vector list
 * @param nelem
 *   The number of elements to reallocate in elements sizes
 * @param esize
 *   The size of the element in bytes
 */
static __cne_always_inline void *
_vec_realloc_data(void *vec, uint32_t nelem, uint32_t esize)
{
    vec_hdr_t *h;
    uint32_t sz = (nelem * esize) + sizeof(vec_hdr_t);

    h = (vec) ? vec_header(vec) : NULL;
    h = realloc(h, sz);
    if (!h)
        return NULL;
    if (!vec)
        memset(h, 0, sz);
    h->alen  = nelem;
    h->esize = esize;
    return (void *)h->data;
}

/**
 * re-allocate a vector of the given length
 *
 * @param vec
 *   The vector pointer
 * @param nelem
 *   The number of elements in the vector to allocate from
 * @param esize
 *   Size in bytes of the elements in the vector
 * @return
 *   The pointer to the vector list or NULL if failed.
 */
#define _vec_realloc(vec, nelem, esize) _vec_realloc_data((vec), nelem, esize)

/**
 * Free the memory attached to the vector.
 *
 * @param v
 *   The vector to free, can be NULL.
 */
#define vec_free(v)              \
    ({                           \
        if (v)                   \
            free(vec_header(v)); \
        NULL;                    \
    })

/**
 * Allocate a vector of the given length
 *
 * @param vec
 *   The vector pointer, must be NULL.
 * @param elem
 *   The number of elements in the vector to allocate from
 * @return
 *   The pointer to the vector list or NULL if failed.
 */
#define vec_alloc(vec, nelem)                                     \
    ({                                                            \
        if ((vec))                                                \
            CNE_ERR("Vector all ready allocated\n");              \
        else                                                      \
            (vec) = _vec_realloc((vec), nelem, sizeof((vec)[0])); \
        (vec);                                                    \
    })

/**
 * Iterate over the entries in the vector list
 *
 * @param var
 *    The variable pointer to use for each value, needs to be declared
 * @param vec
 *    The vector list pointer to index over.
 */
#define vec_foreach(var, vec) for ((var) = (vec); (vec) && (var < vec_end(vec)); var++)

#define vec_foreach_ptr(var, vec) \
    for (uint32_t _V(_i) = 0; (vec) && (var = (vec)[_V(_i)], _V(_i) < vec_len(vec)); _V(_i)++)

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
 * Return the number entries in the vector
 *
 * @param v
 *   The vector pointer
 * @return
 *   The vector size or number of entries in vector or 0 if v is NULL.
 */
#define vec_len(v) ((v) ? vec_header(v)->len : 0)

/**
 * Set vector length to the given number of entries
 *
 * @param v
 *   The vector pointer
 * @param len
 *   The new length value to set
 */
static inline void
vec_set_len(void *v, int len)
{
    vec_hdr_t *hdr = (vec_hdr_t *)vec_header(v);

    if (hdr)
        hdr->len = len;
}

/**
 * Return the allocated number of entries in the list.
 *
 * @param v
 *   The vector pointer
 * @return
 *   The max number of entries allocated in the list.
 */
#define vec_max_len(v) ((v) ? vec_header(v)->alen : 0)

/**
 * Decrease the number of vectors in the list
 *
 * @param v
 *   The vector pointer
 */
#define vec_dec_len(v) ((v) ? vec_header(v)->len-- : 0)

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
#define vec_at_index(vec, n) (vec)[(n)]

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
#define vec_pop(vec) ((vec) ? (vec)[--vec_header(vec)->len] : 0)

/**
 * Increment the number of entries in the vector list.
 *
 * @param v
 *   The vector pointer
 */
#define vec_inc_len(v) ((v) ? vec_header(v)->len++ : 0)

static inline int
_vec_find_index(void **vec, void *v)
{
    for (uint32_t i = 0; i < vec_len(vec); i++) {
        if (v == vec_at_index(vec, i))
            return i;
    }
    return -1;
}

#define vec_find_index(vec, v) _vec_find_index((void **)vec, (void *)v)

/**
 * Add one vector to the list and return new size.
 *
 * @param vec
 *   The vector pointer
 * @param v
 *   The vector entry to add
 * @return
 *   The length of the list before adding the pointer
 */
#define vec_add(vec, v)                                                              \
    ({                                                                               \
        if ((vec) == NULL) {                                                         \
            (vec) = _vec_realloc(NULL, VEC_REALLOC_SIZE, sizeof((vec)[0]));          \
            (vec) = vec_init(vec_header((vec)), VEC_REALLOC_SIZE, sizeof((vec)[0])); \
        }                                                                            \
        vec_hdr_t *_V(h) = vec_header((vec));                                        \
        int _V(l)        = _V(h)->len;                                               \
        if (_V(h)->len >= _V(h)->alen) {                                             \
            _V(h)->alen += VEC_REALLOC_SIZE;                                         \
            (vec) = _vec_realloc((vec), _V(h)->alen, _V(h)->esize);                  \
            _V(h) = vec_header((vec));                                               \
        }                                                                            \
        (vec)[_V(h)->len++] = (v);                                                   \
        _V(l);                                                                       \
    })

#define vec_full(vec)                               \
    ({                                              \
        vec_hdr_t *_V(h) = vec_header(vec);         \
        (_V(h)->len >= _V(h)->alen) ? true : false; \
    })

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
#define vec_move_at_index(t, f, n)      \
    do {                                \
        vec_add(t, vec_at_index(f, n)); \
        vec_at_index(f, n) = 0;         \
    } while (0)

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
#define vec_copy_at_index(to, from, idx)          \
    do {                                          \
        typeof(from) v = vec_at_index(from, idx); \
        vec_add(to, v);                           \
    } while (0)

/**
 * Remove a number of items from the vector.
 *
 * @param _v
 *   The pointer to the vector to remove the entries from
 * @param _nb
 *   The number of items to remove from the vector
 */
#define vec_remove(_v, _nb)                                     \
    do {                                                        \
        vec_hdr_t *h = vec_header(_v);                          \
        int _n       = h->len - _nb;                            \
        if (_n >= 0) {                                          \
            char *src = (char *)&h->data[0] + (_nb * h->esize); \
            memmove(&h->data[0], src, _n * h->esize);           \
            h->len = _n;                                        \
        }                                                       \
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

    cne_printf(" @  %p, ", vec);
    cne_printf("len    %5d, ", h->len);
    cne_printf("alen   %5d, ", h->alen);
    cne_printf("esize  %5d\n", h->esize);
}

#ifdef __cplusplus
}
#endif

#endif /* __CNE_VEC_H */
