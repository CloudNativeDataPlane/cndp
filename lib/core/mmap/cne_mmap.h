/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation
 */

#ifndef _MMAP_H_
#define _MMAP_H_

/**
 * @file
 * CNE allocator for huge pages
 *
 * Allocate memory using MMAP anonyuous memory using hugepages.
 */

#include <stddef.h>        // for size_t
#include <stdint.h>        // for uint64_t, uint8_t

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set of enums to help define HUGEPAGE sizes
 */
typedef enum {
    MMAP_HUGEPAGE_4KB, /**< 4KB pages or default system page size */
    MMAP_HUGEPAGE_2MB, /**< 2MB page size */
    MMAP_HUGEPAGE_1GB, /**< 1GB page size if supported */
    MMAP_HUGEPAGE_CNT  /**< Number of different page sizes supported */
} mmap_type_t;

#define MMAP_HUGEPAGE_DEFAULT MMAP_HUGEPAGE_4KB

/**
 * A set of stats for mmap allocation/free and other stats
 */
typedef struct {
    uint64_t page_sz;       /**< Page size to allocate in bytes */
    uint64_t num_allocated; /**< Number of allocated memory */
    uint64_t num_freed;     /**< Number of freed memory */
    uint64_t allocated;     /**< Number of times memory has been allocated */
    uint64_t freed;         /**< Number of times memory has been freed */
} mmap_sizes_t;

/**
 * Stats per HUGEPAGE type
 */
typedef struct {
    uint8_t inited;                        /**< Value to detect if stats have been allocated */
    mmap_sizes_t sizes[MMAP_HUGEPAGE_CNT]; /**< Stats for each page size */
} mmap_stats_t;

typedef void mmap_t; /**< Opaque pointer to internal mmap data */

/**
 * Allocate memory on the correct socket and use hugepages if set.
 *
 * @param bufcnt
 *   Number of buffers in the memory pool
 * @param bufsz
 *   The size of the buffers in the memory pool
 * @param hugepage
 *   Type of hugepage memory to allocate or non-hugepage memory.
 * @return
 *   The mmap_t structure pointer of the memory allocated or NULL on error
 */
CNDP_API mmap_t *mmap_alloc(uint32_t bufcnt, uint32_t bufsz, mmap_type_t hugepage);

/**
 * Free the memory allocated
 *
 * @param mmap
 *    structure holding the mmap region information
 * @return
 *    0 if freed OK, else -1
 */
CNDP_API int mmap_free(mmap_t *mmap);

/**
 * Return the address in the memory region for the buffer index and size of buffer.
 *
 * Return the address based on the offset into the memory region.
 *
 * @param mm
 *   The mmap_t pointer
 * @param offset
 *   The offset value
 * @return
 *   The address at offset in mmap memory
 */
CNDP_API void *mmap_addr_at_offset(mmap_t *mm, size_t offset);

/**
 * Returns the memory region for a given mmap_t pointer
 *
 * @param mm
 *   The mmap_t pointer
 * @return
 *   The virtual address of the memory region or NULL on error
 */
CNDP_API void *mmap_addr(mmap_t *mm);

/**
 * Return the true size of the memory mapped region
 *
 * @param mm
 *   The mmap_t pointer
 * @param bufcnt
 *   A uint32_t location to place the buffer count value, can be NULL.
 * @param bufsz
 *   A uint32_t location to place the buffer size value, can be NULL.
 * @return
 *   The real size in bytes of the memory region or 0 on error
 */
CNDP_API size_t mmap_size(mmap_t *mm, uint32_t *bufcnt, uint32_t *bufsz);

/**
 * Find a memory hugepage type value by hugepage name
 *
 * @param htype
 *   The hugepage memory type string "4KB", "2MB" or "1GB" memory type
 * @return
 *   The integer value for the  htype passed into the function. If the size string is
 *   not found then the default type is returned.
 */
CNDP_API mmap_type_t mmap_type_by_name(const char *htype);

/**
 * Find the hugepage memory string from a given type
 *
 * @param typ
 *   The integer value for a given type
 * @return
 *   The string pointer to a given mmap type or NULL if not found.
 */
CNDP_API const char *mmap_name_by_type(mmap_type_t typ);

/**
 * Set the default memory type for allocations
 *
 * @param htype
 *   The integer hugepage memory type
 */
CNDP_API void mmap_set_default(mmap_type_t htype);

/**
 * Set the default memory type by hugepage memory string
 *
 * @param name
 *   The number for a memory type "4KB", "2MB", ...
 */
CNDP_API void mmap_set_default_by_name(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _MMAP_H_ */
