/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 * Copyright (c) 2016 6WIND S.A.
 */

#include <stdio.h>        // for FILE, size_t
#include <stdlib.h>
#include <stdint.h>        // for uint32_t, uint16_t
#include <errno.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <sys/types.h>        // for ssize_t

struct mempool_cache;

#ifndef _CNE_MEMPOOL_H_
#define _CNE_MEMPOOL_H_

/**
 * @file
 * CNE Mempool.
 *
 * A memory pool is an allocator of fixed-size object. It is
 * identified by its name, and uses a ring to store free objects.
 *
 * Objects owned by a mempool should never be added in another
 * mempool. When an object is freed using mempool_put() or
 * equivalent, the object data is not modified; the user can save some
 * meta-data in the object data and retrieve them when allocating a
 * new object.
 *
 * Note: the mempool implementation is not preemptible. An thread must not be
 * interrupted by another task that uses the same mempool (because it uses a
 * ring which is not preemptible).
 */

#include <cne.h>               // for cne_id
#include <cne_common.h>        // for CNDP_API
#include <cne_log.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void mempool_t; /**< Opaque pointer for mempool */

/**
 * An object callback function for mempool.
 *
 * Used by mempool_create() and mempool_obj_iter().
 */
typedef void(mempool_obj_cb_t)(mempool_t *mp, void *opaque, void *obj, unsigned obj_idx);
typedef mempool_obj_cb_t mempool_obj_ctor_t; /* compat */

/**
 * A mempool constructor callback function.
 *
 * Arguments are the mempool and the opaque pointer given by the user in
 * mempool_create().
 */
typedef void(mempool_ctor_t)(mempool_t *, void *);

/**
 * @param objcnt
 *   The number of elements in the mempool. The optimum size (in terms of
 *   memory usage) for a mempool is when n is a power of two minus one:
 *   n = (2^q - 1).
 * @param objsz
 *   The size of each element.
 * @param cache_sz
 *   Size of the for the mempool
 * @param addr
 *   The address to the start of the mempool. If the addr is NULL then it will be allocated
 *   from the system memory and freed when the mempool is destroyed.
 * @param mp_init
 *   A function pointer that is called for initialization of the pool,
 *   before object initialization. This parameter can be NULL if
 *   not needed.
 * @param mp_init_arg
 *   An opaque pointer to data that can be used in the mempool
 *   constructor function.
 * @param obj_init
 *   A function pointer that is called for each object at
 *   initialization of the pool. The user can set some meta data in
 *   objects if needed. This parameter can be NULL if not needed.
 *   The obj_init() function takes the mempool pointer, the init_arg,
 *   the object pointer and the object number as parameters.
 * @param obj_init_arg
 *   An opaque pointer to data that can be used as an argument for
 *   each call to the object constructor function.
 */
typedef struct mempool_cfg {
    uint32_t objcnt;   /**< Number of object to create */
    uint32_t objsz;    /**< Size of each object */
    uint16_t cache_sz; /**< Size of the cache mempool */
    char *addr;        /**< Address for user supplied memory */

    mempool_ctor_t *mp_init;    /**< Function to call for initing mempool */
    mempool_obj_cb_t *obj_init; /**< Object function to call for each object */
    void *mp_init_arg;          /**< Argument for mp_init function */
    void *obj_init_arg;         /**< Argument to pass to obj_init function */
} mempool_cfg_t;

/**
 * Create a new mempool in memory.
 *
 * This function uses ``mmap_alloc()`` to allocate memory. The
 * pool contains n elements of elt_size. Its size is set to n.
 *
 * @param cinfo
 *   Pointer to the mempool_cfg structure
 * @return
 *   The pointer to the new allocated mempool, on success. NULL on error
 *   with errno set appropriately. Possible errno values include:
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
CNDP_API mempool_t *mempool_create(struct mempool_cfg *cinfo);

/**
 * Create an empty mempool
 *
 * The mempool is allocated and initialized, but it is not populated: no
 * memory is allocated for the mempool elements. The user has to call
 * mempool_populate_*() to add memory chunks to the pool. Once
 * populated, the user may also want to initialize each object with
 * mempool_obj_iter().
 *
 * @param cinfo
 *   Pointer to the mempool_cfg structure
 * @return
 *   The pointer to the new allocated mempool, on success. NULL on error
 *   with errno set appropriately. See mempool_create() for details.
 */
CNDP_API mempool_t *mempool_create_empty(struct mempool_cfg *cinfo);

/**
 * Free a mempool
 *
 * Unlink the mempool from global list, free the memory chunks, and all
 * memory referenced by the mempool. The objects must not be used by
 * other cores as they will be freed.
 *
 * @param mp
 *   A pointer to the mempool structure.
 */
CNDP_API void mempool_destroy(mempool_t *mp);

/**
 * Initialize a mempool buffer area with given address and size
 *
 * @param mp
 *   The mempool pointer
 * @param vaddr
 *   The start of the virtual address to use for buffers
 * @param len
 *   The length of the buffer space
 * @return
 *   0 on success and -1 on error
 */
CNDP_API int mempool_populate(mempool_t *mp, char *vaddr, size_t len);

/**
 * Call a function for each mempool element
 *
 * Iterate across all objects attached to a cne_mempool and call the
 * callback function on it.
 *
 * @param mp
 *   A pointer to an initialized mempool.
 * @param obj_cb
 *   A function pointer that is called for each object.
 * @param obj_cb_arg
 *   An opaque pointer passed to the callback function.
 * @return
 *   Number of objects iterated.
 */
CNDP_API uint32_t mempool_obj_iter(mempool_t *mp, mempool_obj_cb_t *obj_cb, void *obj_cb_arg);

/**
 * Dump the status of the mempool to a file.
 *
 * @param mp
 *   A pointer to the mempool structure.
 */
CNDP_API void mempool_dump(mempool_t *mp);

/**
 * Get a pointer to the per-thread default mempool cache.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   A pointer to the mempool cache or NULL if disabled or non-CNE thread.
 */
CNDP_API struct mempool_cache *mempool_default_cache(mempool_t *mp);

/**
 * Put several objects back in the mempool.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the mempool from the obj_table.
 * @param cache
 *   A pointer to a mempool cache structure. May be NULL if not needed.
 */
CNDP_API void mempool_generic_put(mempool_t *mp, void *const *obj_table, unsigned int n,
                                  struct mempool_cache *cache);

/**
 * Put several objects back in the mempool.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * mempool creation time (see flags).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param n
 *   The number of objects to add in the mempool from obj_table.
 */
CNDP_API void mempool_put_bulk(mempool_t *mp, void *const *obj_table, unsigned int n);

/**
 * Put one object back in the mempool.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * mempool creation time (see flags).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj
 *   A pointer to the object to be added.
 */
CNDP_API void mempool_put(mempool_t *mp, void *obj);

/**
 * Get several objects from the mempool.
 *
 * If cache is enabled, objects will be retrieved first from cache,
 * subsequently from the common pool. Note that it can return -ENOENT when
 * the local cache and common pool are empty, even if cache from other
 * threads are full.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to get from mempool to obj_table.
 * @param cache
 *   A pointer to a mempool cache structure. May be NULL if not needed.
 * @return
 *   - 0: Success; objects taken.
 *   - -ENOENT: Not enough entries in the mempool; no object is retrieved.
 */
CNDP_API int mempool_generic_get(mempool_t *mp, void **obj_table, unsigned int n,
                                 struct mempool_cache *cache);

/**
 * Get several objects from the mempool.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behaviour that was specified at
 * mempool creation time (see flags).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param n
 *   The number of objects to get from the mempool to obj_table.
 * @return
 *   - 0: Success; objects taken
 *   - -ENOENT: Not enough entries in the mempool; no object is retrieved.
 */
CNDP_API int mempool_get_bulk(mempool_t *mp, void **obj_table, unsigned int n);

/**
 * Get one object from the mempool.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behavior that was specified at
 * mempool creation (see flags).
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @return
 *   - 0: Success; objects taken.
 *   - -ENOENT: Not enough entries in the mempool; no object is retrieved.
 */
CNDP_API int mempool_get(mempool_t *mp, void **obj_p);

/**
 * Return the number of entries in the mempool.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   The number of entries in the mempool.
 */
CNDP_API unsigned int mempool_avail_count(const mempool_t *mp);

/**
 * Return the number of elements which have been allocated from the mempool
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   The number of free entries in the mempool.
 */
CNDP_API unsigned int mempool_in_use_count(const mempool_t *mp);

/**
 * Test if the mempool is full.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   - 1: The mempool is full.
 *   - 0: The mempool is not full.
 */
CNDP_API int mempool_full(const mempool_t *mp);

/**
 * Test if the mempool is empty.
 *
 * @param mp
 *   A pointer to the mempool structure.
 * @return
 *   - 1: The mempool is empty.
 *   - 0: The mempool is not empty.
 */
CNDP_API int mempool_empty(const mempool_t *mp);

/**
 * Return the mempool ring pointer.
 *
 * @param mp
 *   The ring pointer for the mempool.
 * @return
 *   The ring pointer or NULL on error
 */
CNDP_API void *mempool_ring_addr(mempool_t *mp);

/**
 * Return the mempool buffer pointer.
 *
 * @param mp
 *   The object memory pointer for the mempool.
 * @return
 *   The object memory pointer or NULL on error
 */
CNDP_API void *mempool_buff_addr(mempool_t *mp);

/**
 * Return number of objects in mempool.
 *
 * @param mp
 *   Mempool pointer
 * @return
 *   The number of objects in the mempool or -1 on error
 */
CNDP_API int mempool_objcnt(mempool_t *mp);

/**
 * Return size of objects in mempool.
 *
 * @param mp
 *   Mempool pointer
 * @return
 *   The size of objects in the mempool or -1 on error
 */
CNDP_API int mempool_objsz(mempool_t *mp);

/**
 * Return the cache size of the mempool.
 *
 * @param mp
 *   The mempool pointer
 * @return
 *   The mempool cache size or -1 on error
 */
CNDP_API int mempool_cache_sz(mempool_t *mp);

/**
 * Return the length of the cache entry noted by idx
 *
 * @param mp
 *   The mempool pointer
 * @param idx
 *   The index value into the cache list
 * @return
 *   The number of entries in the cache or -1 on error
 */
CNDP_API int mempool_cache_len(mempool_t *mp, int idx);

/**
 * Determine the object index value in the mempool.
 *
 * @param mp
 *   The mempool_t pointer to use to calculate the object index.
 * @param obj
 *   The object pointer to use in calculation
 * @return
 *   -1 on error or object index value.
 */
CNDP_API int mempool_obj_index(mempool_t *mp, void *obj);

/**
 * Return the object pointer for the given mempool_t and index value
 *
 * @param mp
 *   The mempool_t pointer to use to calculate the object address.
 * @param idx
 *   The index value into the mempool buffer array.
 * @return
 *   NULL on error or pointer to object.
 */
CNDP_API void *mempool_obj_at_index(mempool_t *mp, int idx);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_MEMPOOL_H_ */
