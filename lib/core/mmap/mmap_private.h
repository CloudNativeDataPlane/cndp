/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Intel Corporation
 */

#ifndef _MMAP_PRIVATE_H_
#define _MMAP_PRIVATE_H_

#include <stddef.h>        // for size_t
#include <stdint.h>        // for uint64_t, uint8_t

#include <cne_mmap.h>

/**
 * @file
 * CNE allocator for huge pages
 *
 * Allocate memory using MMAP anonyuous memory using hugepages.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct mmap_data {
    uint32_t bufcnt; /**< Number of buffers in the pool */
    uint32_t bufsz;  /**< Size of each buffer in the pool */
    size_t sz;       /**< Real size of the memory region  (bufcnt * bufsz) */
    void *addr;      /**< Address of the memory region */
    mmap_type_t typ; /**< Type of memory allocated */
    unsigned align;  /**< Alignment value */
};

#ifdef __cplusplus
}
#endif

#endif /* _MMAP_PRIVATE_H_ */
