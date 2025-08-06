/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stddef.h>
#include <limits.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/mman.h>

#include <cne_per_thread.h>
#include <cne_log.h>
#include <cne_common.h>

#include "ctx.h"
#include "cthread.h"
#include "cthread_api.h"
#include "cthread_int.h"
#include "cthread_mutex.h"
#include "cthread_sched.h"
#include "cthread_queue.h"
#include "cthread_objcache.h"

/*
 * Create a mutex
 */
int
cthread_mutex_init(const char *name, struct cthread_mutex **mutex,
                   const struct cthread_mutexattr *attr)
{
    struct cthread_mutex *m;

    if (mutex == NULL)
        return POSIX_ERRNO(EINVAL);

    m = _cthread_objcache_alloc((THIS_SCHED)->mutex_cache);
    if (m == NULL)
        return POSIX_ERRNO(EAGAIN);

    m->blocked = _cthread_queue_create("blocked queue");
    if (m->blocked == NULL) {
        _cthread_objcache_free((THIS_SCHED)->mutex_cache, m);
        return POSIX_ERRNO(EAGAIN);
    }

    if (name == NULL)
        strlcpy(m->name, "no name", sizeof(m->name));
    else
        strlcpy(m->name, name, sizeof(m->name));
    m->name[sizeof(m->name) - 1] = 0;

    m->sched = THIS_SCHED;
    m->owner = NULL;
    m->flags = (attr) ? attr->flags : 0;

    atomic_store(&m->waiters, 0);

    /* success */
    (*mutex) = m;
    return 0;
}

/*
 * Destroy a mutex
 */
int
cthread_mutex_destroy(struct cthread_mutex *m)
{
    if ((m == NULL) || (m->blocked == NULL))
        return POSIX_ERRNO(EINVAL);

    if (m->owner == NULL) {
        /* try to delete the blocked queue */
        if (_cthread_queue_destroy(m->blocked) < 0)
            return POSIX_ERRNO(EBUSY);

        /* free the mutex to cache */
        _cthread_objcache_free(m->sched->mutex_cache, m);
        return 0;
    }
    /* can't do its still in use */
    return POSIX_ERRNO(EBUSY);
}

/*
 * Try to obtain a mutex
 */
int
cthread_mutex_lock(struct cthread_mutex *m)
{
    struct cthread *ct = THIS_CTHREAD;

    if ((m == NULL) || (m->blocked == NULL))
        return POSIX_ERRNO(EINVAL);

    if (m->owner == ct) {
        if (m->flags & MUTEX_RECURSIVE_ATTR)
            return 0;
        /* allow no recursion */
        return POSIX_ERRNO(EDEADLK);
    }

    for (;;) {
        uint64_t c = 0;

        atomic_fetch_add(&m->waiters, 1);
        do {
            if (atomic_compare_exchange_strong((atomic_uint_least64_t *)&m->owner, &c,
                                               (uint64_t)ct))
                return 0;
            /* spin due to race with unlock when
             * nothing was blocked
             */
        } while ((atomic_load(&m->waiters) == 1) && (m->owner == NULL));

        /* queue the current thread in the blocked queue
         * we defer this to after we return to the scheduler
         * to ensure that the current thread context is saved
         * before unlock could result in it being dequeued and
         * resumed
         */
        ct->pending_wr_queue = m->blocked;
        /* now relinquish cpu */
        _cthread_mutex_wait();
        /* resumed, must loop and compete for the lock again */
    }
    return 0;
}

/* try to lock a mutex but dont block */
int
cthread_mutex_trylock(struct cthread_mutex *m)
{
    struct cthread *ct = THIS_CTHREAD;

    if ((m == NULL) || (m->blocked == NULL))
        return POSIX_ERRNO(EINVAL);

    if (m->owner == ct) {
        if (m->flags & MUTEX_RECURSIVE_ATTR)
            return 0;
        /* no recursion */
        return POSIX_ERRNO(EDEADLK);
    }

    atomic_fetch_add(&m->waiters, 1);
    uint64_t c = 0;
    if (atomic_compare_exchange_strong((atomic_uint_least64_t *)&m->owner, &c, (uint64_t)ct))
        return 0;

    /* failed so return busy */
    atomic_fetch_sub(&m->waiters, 1);
    return POSIX_ERRNO(EBUSY);
}

int
cthread_mutex_state(struct cthread_mutex *m)
{
    struct cthread *ct = THIS_CTHREAD;

    if ((m == NULL) || (m->blocked == NULL))
        return POSIX_ERRNO(EINVAL);

    if (m->owner == ct)
        return POSIX_ERRNO(EDEADLK); /* no recursion */

    return m->owner ? 1 : 0;
}

/*
 * Unlock a mutex
 */
int
cthread_mutex_unlock(struct cthread_mutex *m)
{
    struct cthread *ct = THIS_CTHREAD;
    struct cthread *unblocked;

    if ((m == NULL) || (m->blocked == NULL))
        return POSIX_ERRNO(EINVAL);

    /* fail if its owned by someone else or it is NULL */
    if (m->owner != ct || m->owner == NULL)
        return POSIX_ERRNO(EPERM);

    atomic_fetch_sub(&m->waiters, 1);

    /* if there are blocked threads then make one ready */
    while (atomic_load(&m->waiters) > 0) {
        unblocked = _cthread_queue_remove(m->blocked);

        if (unblocked != NULL) {
            atomic_fetch_sub(&m->waiters, 1);
            CNE_ASSERT(unblocked->sched != NULL);
            _ready_queue_insert((struct cthread_sched *)unblocked->sched, unblocked);
            break;
        }
    }
    /* release the lock */
    m->owner = NULL;
    return 0;
}
