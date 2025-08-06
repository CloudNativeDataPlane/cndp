/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _THREAD_PRIVATE_H_
#define _THREAD_PRIVATE_H_

#include <pthread.h>
#include <uid.h>
/**
 * @file
 *
 * The Thread Local Storage (TLS) for each thread in the application.
 *
 */
#ifdef __cplusplus
extern "C" {
#endif

#define THREAD_MAGIC_ID 0x20180403

typedef void (*thd_func_t)(void *); /**< Thread function prototype */

struct thd_state {
    char name[CNE_NAME_LEN]; /**< Thread Name */
    uint32_t magic_id;       /**< Magic value to determine if inited */
    uint32_t running;        /**< Thread is running */
    uintptr_t pid;           /**< Thread ID from pthread */
    void *priv_;             /**< User supplied value */
} __cne_cache_aligned;

struct thd_params {
    char name[CNE_NAME_LEN];   /**< Name of thread */
    thd_func_t start_routine;  /**< Function pointer to call */
    void *arg;                 /**< User supplied argument pointer */
    pthread_barrier_t barrier; /**< Barrier for thread_create startup */
    int tidx;                  /**< Thread Index value (return value) */
};

typedef struct thd_state thd_state_t;

#ifdef __cplusplus
}
#endif

#endif /* _THREAD_PRIVATE_H_ */
