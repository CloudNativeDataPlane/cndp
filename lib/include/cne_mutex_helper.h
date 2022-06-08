/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef __CNE_MUTEX_HELPER_H
#define __CNE_MUTEX_HELPER_H

/**
 * @file
 * Routines to help create a mutex.
 */

#include <pthread.h>
#include <cne_log.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Helper routine to create a mutex with a specific type.
 *
 * @param mutex
 *   The pointer to the mutex to create.
 * @param flags
 *   The attribute flags used to create the mutex i.e. recursive attribute
 * @return
 *   0 on success or -1 on failure errno is set
 */
static inline int
cne_mutex_create(pthread_mutex_t *mutex, int flags)
{
    int ret = EFAULT;

    if (mutex) {
        pthread_mutexattr_t attr;

        ret = pthread_mutexattr_init(&attr);
        if (ret == 0) {
            ret = pthread_mutexattr_settype(&attr, flags);
            if (ret == 0) {
                ret = pthread_mutex_init(mutex, &attr);
                if (ret == 0 && pthread_mutexattr_destroy(&attr) == 0)
                    return 0;
            }
        }
    }

    errno = ret;
    return -1;
}

/**
 * Destroy a mutex
 *
 * @param mutex
 *   Pointer to mutex to destroy.
 * @return
 *   0 on success and -1 on error with errno set.
 */
static inline int
cne_mutex_destroy(pthread_mutex_t *mutex)
{
    int ret = 0;

    if (mutex)
        ret = pthread_mutex_destroy(mutex);

    errno = ret;
    return (ret != 0) ? -1 : 0;
}

#ifdef __cplusplus
}
#endif

#endif /* __CNE_MUTEX_HELPER_H */
