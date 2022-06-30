/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _UID_H_
#define _UID_H_

/**
 * @file
 *
 * API for User Index allocation
 *
 */
#include <stdio.h>         // for FILE
#include <stdint.h>        // for uint16_t

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UID_INITIAL_NAME    "Initial-UID"
#define DEFAULT_MAX_THREADS 512 /**< Max Number of threads to support */

typedef void *u_id_t; /**< User opaque value handler */

/**
 * Find a UID entry given the name of the UID
 *
 * @param name
 *   String used to locate the UID structure
 * @return
 *   NULL if not found or the u_id_t opaque pointer
 */
CNDP_API u_id_t uid_find_by_name(const char *name);

/**
 * Return the max size of the UID pool.
 *
 * @param _e
 *   The pointer to the uid_entry structure
 * @return
 *   Max number of UID entries in the UID pool.
 */
CNDP_API uint16_t uid_max_ids(u_id_t _e);

/**
 * Return the current number of allocated UIDs
 *
 * @param _e
 *    The pointer to the uid_entry structure
 * @return
 *    The number of allocated entries in the UID structure
 */
CNDP_API uint16_t uid_allocated(u_id_t _e);

/**
 * Add a new UID set of IDs based on the total count
 *
 * @param name
 *   The name of the UID entry
 * @param cnt
 *   The max number of IDs from 0 - cnt possible.
 * @return
 *   The opaque pointer value or NULL if error
 */
CNDP_API u_id_t uid_register(const char *name, uint16_t cnt);

/**
 * Delete a UID entry created by uid_register()
 *
 * @param _e
 *   The opaque pointer value to delete
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int uid_unregister(u_id_t _e);

/**
 * Allocate a unique ID value from a UID entry
 *
 * @param _e
 *   The opaque pointer value to allocate from
 * @return
 *   -1 on error or 0 >= cnt value index
 */
CNDP_API int uid_alloc(u_id_t _e);

/**
 * Release a index value back to the UID entry (free)
 *
 * @param _e
 *   The UID to free the index value to
 * @param idx
 *   The index value to free or release
 */
CNDP_API void uid_free(u_id_t _e, int idx);

/**
 * Test to see if a bit is set in the bitmap (or cleared in this case)
 *
 * @param e
 *   The u_id_t structure pointer to be tested using the uid bit index.
 * @param uid
 *   The uid bit to test, if the bit is cleared then it is allocated.
 * @return
 *   0 on not set and 1 on set.
 */
CNDP_API int uid_test(u_id_t *e, int uid);

/**
 * Dump out all of the UID structures.
 *
 * @param f
 *   File descriptor pointer to write the output, if NULL use stdout
 */
CNDP_API void uid_dump(FILE *f);

#ifdef __cplusplus
}
#endif

#endif /* _UID_H_ */
