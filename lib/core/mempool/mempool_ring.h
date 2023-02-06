/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#ifndef _MEMPOOL_RING_H_
#define _MEMPOOL_RING_H_

/**
 * @file
 *
 * Private APIs for a mempool to use Ring to store memory pointers.
 */

#include <stddef.h>           // for size_t
#include <stdint.h>           // for uint32_t
#include <sys/types.h>        // for ssize_t

#include "mempool.h"                // for cne_mempool
#include "mempool_private.h"        // for cne_mempool

// IWYU pragma: no_forward_declare cne_mempool

/**
 * Function to be called for each populated object.
 *
 * @param[in] mp
 *   A pointer to the mempool structure.
 * @param[in] opaque
 *   An opaque pointer passed to iterator.
 * @param[in] vaddr
 *   Object virtual address.
 */
typedef void(mempool_populate_obj_cb_t)(struct cne_mempool *mp, void *opaque, void *vaddr);

int mempool_ring_enqueue(struct cne_mempool *mp, void *const *obj_table, unsigned n);

int mempool_ring_dequeue(struct cne_mempool *mp, void **obj_table, unsigned n);

unsigned mempool_ring_get_count(const struct cne_mempool *mp);

int mempool_ring_alloc(struct cne_mempool *mp);

void mempool_ring_free(struct cne_mempool *mp);

ssize_t mempool_ring_calc_mem_size(const struct cne_mempool *mp, uint32_t obj_num,
                                   uint32_t pg_shift, size_t *min_chunk_size, size_t *align);
int mempool_ring_populate(struct cne_mempool *mp, void *vaddr, mempool_populate_obj_cb_t *obj_cb,
                          void *obj_cb_arg);

#endif /* _MEMPOOL_RING_H_ */
