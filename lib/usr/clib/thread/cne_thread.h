/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2025 Intel Corporation
 */

#ifndef _CNE_THREAD_H_
#define _CNE_THREAD_H_

/**
 * @file
 * CNE Thread
 *
 * This library provides the thread management service.
 *
 * This library provides an interface to create, register, set affinity and
 * schedule a thread. Also support the thread id query ops and debug ops.
 *
 * See the CNE architecture documentation for more information about the
 * design of this library.
 */
// IWYU pragma: no_include "thread_private.h"
#include <stdio.h>        // for FILE
#include <pthread.h>
#include <cne_common.h>        // for CNDP_API, CNE_STD_C11
#include <stdint.h>            // for uint16_t, uint64_t, uint8_t
#include <uid.h>

#ifdef __cplusplus
extern "C" {
#endif

#define THREAD_WAIT_FOREVER    0
#define THREAD_DEFAULT_TIMEOUT 1000        // 1ms timeout
#define THREAD_DEFAULT_NAME    "Initial-thread"

typedef void *thd_t; /**< Thread data handle, opaque value */

#ifndef _THREAD_PRIVATE_H_
/* Define the function prototype if pubicly included */
typedef void (*thd_func_t)(void *);
#endif

/**< Flags used to determine what type of thread Rx/Tx or Rx or Tx only */
#define DISPLAY_FLAG 0x00
#define RX_ONLY_FLAG 0x01
#define TX_ONLY_FLAG 0x02
#define RXTX_FLAG    (RX_ONLY_FLAG | TX_ONLY_FLAG)

typedef union thread_cfg {
    uint64_t data; /**< 8 byte word to the union */
    void *arg;     /**< A void point for the union of data */

    CNE_STD_C11
    struct {
        uint16_t core; /**< core id if pinning a thread or -1/0xFFFF if not set */
        uint16_t pid;  /**< Port id for the thread use */
        uint16_t qid;  /**< Queue ID for the thread to use */
        uint8_t flags; /**< Flags for configuration */
        uint8_t pad0;
    };
} thread_cfg_t;

/**
 * Return the thread ID or index value .
 */
CNDP_API int thread_id(void);

/**
 * Returns the thd_t pointer give the thread IDX value.
 *
 * @param tidx
 *   The thread index value
 * @return
 *   NULL if tidx is invalid or the thd_t pointer
 */
CNDP_API thd_t thread_get(int tidx);

/**
 * Wrapper routine around pthread_create call to help setup CNDP state
 *
 * @param name
 *   The name of the thread that will be created.
 * @param func
 *   The function pointer to call when thread is started.
 * @param arg
 *   The argument passed to the function
 * @return
 *   -1 on error or 0 - N index value
 */
CNDP_API int thread_create(const char *name, thd_func_t func, void *arg);

/**
 * Register a thread name and pid value, returning a thread index.
 * Obtains a thread index value unique to this thread.
 *
 * @param name
 *   The name of the thread
 * @param pid
 *    The thread identifier value, can be 0 if not required.
 * @return
 *    -1 on error or the thread index value
 */
CNDP_API int thread_register(const char *name, uint64_t pid);

/**
 * Release a thread index value.
 *
 * @param tidx
 *   The thread index value to release.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int thread_unregister(int tidx);

/**
 * Wait for all threads to stop running
 *
 * @param tid
 *    The thread id to wait on to complete
 * @param checks
 *    Number of check to attempt, if zero wait forever.
 * @param usec
 *    Number of micro-seconds to wait between checks.
 * @return
 *    Return when all are stopped or when the check rate is done.
 *    0 on all stopped non-zero when checks are done.
 */
CNDP_API int thread_wait(int tid, unsigned int checks, unsigned int usec);

/**
 * Wait for all threads to stop running
 *
 * @param checks
 *    Number of check to attempt, if zero wait forever.
 * @param usec
 *    Number of micro-seconds to wait between checks.
 * @param skip
 *    Skip the first initial thread.
 * @return
 *    Return when all are stopped or when the check rate is done.
 *    0 on all stopped non-zero when checks are done.
 */
CNDP_API int thread_wait_all(unsigned int checks, unsigned int usec, int skip);

/**
 * Stop a thread running by clearing the running flag
 *
 * @param tidx
 *    Clear the running flag for the thread index value, if -1 then stop self
 * @return
 *    0 on successfully clearing the running flag
 */
CNDP_API int thread_stop_running(int tidx);

/**
 * Return the state of the thread.
 *
 * @param tidx
 *    return the running flag for the thread index value, if -1 then self
 * @return
 *    -1 on error or the state of running flag
 */
CNDP_API int thread_running(int tidx);

/**
 * Set a user specific private value or pointer.
 *
 * @param tidx
 *   The thread index to store the private value.
 * @param priv_
 *   The void pointer value to store in the thread state struct.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int thread_set_private(int tidx, void *priv_);

/**
 * Returns the thread private data stored with thread_set_private()
 *
 * @param tidx
 *   The thread index value to return the private value
 * @return
 *   NULL or the thread private data pointer
 */
CNDP_API void *thread_get_private(int tidx);

/**
 * Set the CPU affinity for the current thread.
 */
CNDP_API int thread_set_affinity(int cpu);

/**
 * Return thread name.
 *
 * @param tidx
 *   If tidx is -1 then return current thread name, otherwise tidx name.
 * @return
 *   NULL on error or the thread name
 */
CNDP_API const char *thread_name(int tidx);

/**
 * Dump out all threads currently active/allocated
 *
 * @param f
 *   The file pointer to write the text output or NULL if stdout
 */
CNDP_API void thread_dump(FILE *f);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_THREAD_H_ */
