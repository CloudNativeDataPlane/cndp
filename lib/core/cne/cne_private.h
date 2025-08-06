/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _CNE_PRIVATE_H_
#define _CNE_PRIVATE_H_

/**
 * @file
 *
 * API for CNE private routines.
 *
 */

#include <stdint.h>
#include <sys/queue.h>

#include <cne_common.h>
#include <uid.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNE_MAGIC_ID 0x20180403 /**< CNE structure valid magic cookie value */

/**
 * The typedef for the on exit function pointer.
 *
 * @param sig
 *   The signal number supplied in the signal handler function.
 * @param arg
 *   The user supplied argument used as an argument to the exit_fn function.
 * @param exit_type
 *   The type of exit signal or exit() was called, CNE_CAUGHT_SIGNAL or CNE_CALLED_EXIT
 */
typedef void (*on_exit_fn_t)(int sig, void *arg, int exit_type);

struct cne_entry {
    STAILQ_ENTRY(cne_entry) next; /**< Next CNE structure */
    char name[CNE_NAME_LEN];      /**< Name of this instance for debug */
    uint32_t magic_id;            /**< Must be set to be valid entry */
    int uid;                      /**< UID value for this instance */
    void *priv_;                  /**< Private value, used by thread API or by something else */
} __cne_cache_aligned;

typedef struct cne_s {
    uint32_t magic_id;             /**< Magic ID value to determine if inited */
    int initial_uid;               /**< Main thread UID value */
    atomic_int active;             /**< Number of active CNE entries */
    u_id_t pool;                   /**< Thread Index pool ID */
    on_exit_fn_t on_exit_fn;       /**< on_exit or signal function */
    void *on_exit_arg;             /**< argument for on_exit function */
    STAILQ_HEAD(, cne_entry) list; /**< List of CNE entries */
    struct cne_entry *entries;     /**< Extend the struct to include all of the entries */
} cne_private_t;

#ifdef __cplusplus
}
#endif

#endif /* _CNE_PRIVATE_H_ */
