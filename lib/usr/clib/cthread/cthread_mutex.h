/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#ifndef _CTHREAD_MUTEX_H_
#define _CTHREAD_MUTEX_H_

#include "cthread_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MUTEX_NAME_SIZE 32

struct cthread_mutex {
    struct cthread *owner;                             /**< Owner of the mutex */
    CNE_ATOMIC(uint_least16_t) waiters;                /**< Number of waiter on the mutex */
    struct cthread_queue *blocked __cne_cache_aligned; /**< blocked thread list */
    struct cthread_sched *sched;                       /**< Scheduler pointer */
    uint32_t flags;                                    /**< flags for the mutex */
    char name[MAX_MUTEX_NAME_SIZE];                    /**< Name of mutex */
} __cne_cache_aligned;

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_MUTEX_H_ */
