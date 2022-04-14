/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <errno.h>

#include <cne_log.h>
#include <cne_common.h>
#include <cne_per_thread.h>

#include "ctx.h"
#include "cthread.h"
#include "cthread_api.h"
#include "cthread_int.h"
#include <cthread_queue.h>
#include "cthread_sched.h"
#include "cthread_objcache.h"
#include "cthread_timer.h"
#include "cthread_mutex.h"
#include "cthread_cond.h"
#include "cthread_once.h"

/*
 * Initialize a once variable
 */
int
cthread_once_init(struct cthread_once **once)
{
    struct cthread_once *o;

    if (once == NULL)
        return POSIX_ERRNO(EINVAL);

    /* allocate a condition variable from cache */
    o = _cthread_objcache_alloc((THIS_SCHED)->once_cache);

    if (!o)
        return POSIX_ERRNO(EAGAIN);

    cne_atomic32_set(&o->count, 0);

    cthread_mutex_init("once", &o->mutex, NULL);

    o->sched = THIS_SCHED;

    (*once) = o;

    return 0;
}

/*
 * Destroy a once variable
 */
int
cthread_once_destroy(struct cthread_once *o)
{
    if (!o)
        return POSIX_ERRNO(EINVAL);

    cthread_mutex_destroy(o->mutex);

    /* okay free it */
    _cthread_objcache_free(o->sched->once_cache, o);

    return 0;
}

/*
 * Reset a once variable to initilazed state.
 */
int
cthread_once_reset(struct cthread_once *o)
{
    if (!o)
        return POSIX_ERRNO(EINVAL);

    cthread_mutex_lock(o->mutex);

    cne_atomic32_set(&o->count, 0);
    o->sched = THIS_SCHED;

    cthread_mutex_unlock(o->mutex);

    return 0;
}
int
cthread_once(struct cthread_once *once, int (*func)(void *), void *arg)
{
    int ret = 0;

    cthread_mutex_lock(once->mutex);

    if (cne_atomic32_add_return(&once->count, 1) == 1)
        ret = func(arg);

    cthread_mutex_unlock(once->mutex);

    /* the once happened */
    return ret;
}
