/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _UID_PRIVATE_H_
#define _UID_PRIVATE_H_

/**
 * @file
 *
 * API for atomic ID allocation
 *
 */
#include <sys/queue.h>
#include <bsd/sys/bitstring.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UID_MAGIC_ID 0x20180403 /**< Magic ID value for a valid UID structure */

typedef struct uid_entry {
    STAILQ_ENTRY(uid_entry) next; /**< Next UID structure */
    char name[CNE_NAME_LEN];      /**< Name of the UID */
    uint16_t allocated;           /**< Number currently allocated */
    uint16_t max_ids;             /**< Max number of IDs */
    int32_t bitmap_sz;            /**< Size of bitmap array in bits */
    bitstr_t *bitmap;             /**< Pointer to the bitmap array */
    pthread_mutex_t mutex;        /**< Mutex for alloc/free operations */
} uid_entry_t;

typedef struct uid_s {
    uint32_t magic_id;             /**< Magic ID value */
    uint32_t list_cnt;             /**< Number of UID entries */
    STAILQ_HEAD(, uid_entry) list; /**< List of UID entries */
} uid_private_t;

#ifdef __cplusplus
}
#endif

#endif /* _UID_PRIVATE_H_ */
