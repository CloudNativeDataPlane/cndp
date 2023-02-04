/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

/*
 * Some portions of this software may have been derived from the
 * https://github.com/halayli/lthread which carrys the following license.
 *
 * Copyright (c) 2012, Hasan Alayli <halayli@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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
#include <errno.h>

#include <cne_log.h>
#include <cne_common.h>
#include <cne_per_thread.h>
#include <cne_strings.h>

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

/*
 * Create a condition variable
 */
int
cthread_cond_init(const char *name, struct cthread_cond **cond,
                  const struct cthread_condattr *attr __cne_unused)
{
    struct cthread_cond *c;

    if (!cond)
        return POSIX_ERRNO(EINVAL);

    /* allocate a condition variable from cache */
    c = _cthread_objcache_alloc((THIS_SCHED)->cond_cache);

    if (!c)
        return POSIX_ERRNO(EAGAIN);

    c->blocked = _cthread_queue_create("blocked");
    if (!c->blocked) {
        _cthread_objcache_free((THIS_SCHED)->cond_cache, (void *)c);
        return POSIX_ERRNO(EAGAIN);
    }

    if (!name || !*name)
        strlcpy(c->name, "no name", sizeof(c->name));
    else
        strlcpy(c->name, name, sizeof(c->name));
    c->name[sizeof(c->name) - 1] = 0;

    c->sched = THIS_SCHED;

    (*cond) = c;
    return 0;
}

/*
 * Destroy a condition variable
 */
int
cthread_cond_destroy(struct cthread_cond *c)
{
    if (!c)
        return POSIX_ERRNO(EINVAL);

    /* try to free it */
    if (_cthread_queue_destroy(c->blocked) < 0)
        return POSIX_ERRNO(EBUSY);

    /* okay free it */
    _cthread_objcache_free(c->sched->cond_cache, c);
    return 0;
}

/*
 * Reset a condition variable to initialized state.
 */
int
cthread_cond_reset(struct cthread_cond *c)
{
    if (!c)
        return POSIX_ERRNO(EINVAL);

    do {
        struct cthread *ct;

        /* drain the queue waking everybody */
        ct = _cthread_queue_remove(c->blocked);

        if (!ct)
            break;

        ct->state &= ~CLEAR_STATE_BITS;

        /* wake up */
        _ready_queue_insert((struct cthread_sched *)ct->sched, ct);
    } while (!_cthread_queue_empty(c->blocked));

    c->sched = THIS_SCHED;

    return 0;
}

/*
 * Wait on a condition variable
 */
int
cthread_cond_wait(struct cthread_cond *c, struct cthread_mutex *m)
{
    struct cthread *ct = THIS_CTHREAD;

    if (!c)
        return POSIX_ERRNO(EINVAL);

    /*
     * queue the current thread in the blocked queue
     * this will be written when we return to the scheduler
     * to ensure that the current thread context is saved
     * before any signal could result in it being dequeued and
     * resumed
     */
    ct->pending_wr_queue = c->blocked;

    if (m) {
        cthread_mutex_unlock(m);
        _cthread_wait();
        cthread_mutex_lock(m);
    } else
        _cthread_wait();

    /* the condition happened */
    return 0;
}

/*
 * Wait on a condition variable with timeout
 */
int
cthread_cond_timedwait(struct cthread_cond *c, struct cthread_mutex *m,
                       const struct timespec *timeout)
{
    struct cthread *ct = THIS_CTHREAD;
    uint64_t nsecs;

    if (!c || !timeout)
        return POSIX_ERRNO(EINVAL);

    /*
     * queue the current thread in the blocked queue
     * this will be written when we return to the scheduler
     * to ensure that the current thread context is saved
     * before any signal could result in it being dequeued and
     * resumed
     */
    ct->pending_wr_queue = c->blocked;

    nsecs    = (timeout->tv_sec * 1000000) + timeout->tv_nsec;
    ct->cond = c;

    if (m) {
        cthread_mutex_unlock(m);
        cthread_sleep(nsecs);
        cthread_mutex_lock(m);
    } else
        cthread_sleep(nsecs);

    /* the condition happened or timeout */
    return (ct->state & CT_STATE_EXPIRED);
}

/*
 * Signal a condition variable
 * attempt to resume any blocked thread
 */
int
cthread_cond_signal(struct cthread_cond *c)
{
    struct cthread *ct;

    if (!c)
        return POSIX_ERRNO(EINVAL);

    ct = _cthread_queue_remove(c->blocked);

    if (ct) {
        uint64_t state = ct->state;

        ct->state &= ~CLEAR_STATE_BITS;

        /* Cancel the timer and clear Sleeping bit if found */
        if (state & BIT(CT_STATE_SLEEPING))
            _timer_stop(ct);

        /* okay wake up this thread */
        _ready_queue_insert(ct->sched, ct);
    }

    return 0;
}

/*
 * Broadcast a condition variable
 */
static int
_cond_broadcast(struct cthread_cond *c, int resched)
{
    if (!c)
        return POSIX_ERRNO(EINVAL);

    do {
        /* drain the queue waking everybody */
        struct cthread *ct = _cthread_queue_remove(c->blocked);

        if (ct) {
            uint64_t state = ct->state;

            ct->state &= ~CLEAR_STATE_BITS;

            /* Cancel the timer if thread was sleeping */
            if (state & BIT(CT_STATE_SLEEPING))
                _timer_stop(ct);

            /* wake up */
            _ready_queue_insert(ct->sched, ct);
        }
    } while (!_cthread_queue_empty(c->blocked));

    if (resched)
        _reschedule();

    return 0;
}

int
cthread_cond_broadcast(struct cthread_cond *c)
{
    return _cond_broadcast(c, 1);
}

int
cthread_cond_broadcast_no_sched(struct cthread_cond *c)
{
    return _cond_broadcast(c, 0);
}
