/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _CTHREAD_ONCE_H_
#define _CTHREAD_ONCE_H_

#include "cthread_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cthread_once {
    struct cthread_sched *sched; /**< Scheduler pointer */
    atomic_uint_least32_t count; /**< if none zero already called */
    struct cthread_mutex *mutex; /**< Mutex to restrict access */
} __cne_cache_aligned;

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_ONCE_H_ */
