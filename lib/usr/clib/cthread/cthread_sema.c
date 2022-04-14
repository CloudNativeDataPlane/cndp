/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
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

#include "ctx.h"
#include "cthread.h"
#include "cthread_api.h"
#include "cthread_int.h"
#include <cthread_queue.h>
#include "cthread_sched.h"
#include "cthread_objcache.h"
#include "cthread_timer.h"
#include "cthread_mutex.h"
#include "cthread_sema.h"

/*
 * Create a semaphore
 */
int
cthread_sema_init(const char *name, struct cthread_sema **sema, const struct cthread_semaattr *attr)
{
    struct cthread_sema *s;

    if (!sema)
        return POSIX_ERRNO(EINVAL);

    /* allocate a semaphore from cache */
    s = _cthread_objcache_alloc((THIS_SCHED)->sema_cache);

    if (!s)
        return POSIX_ERRNO(EAGAIN);

    s->blocked = _cthread_queue_create("blocked");
    if (!s->blocked) {
        _cthread_objcache_free((THIS_SCHED)->sema_cache, (void *)s);
        return POSIX_ERRNO(EAGAIN);
    }

    if (!name || !*name)
        strlcpy(s->name, "no name", sizeof(s->name));
    else
        strlcpy(s->name, name, sizeof(s->name));
    s->name[sizeof(s->name) - 1] = 0;

    s->sched      = THIS_SCHED;
    s->orig_count = (attr) ? attr->cnt : 0;

    atomic_store(&s->count, s->orig_count);

    (*sema) = s;
    return 0;
}

/*
 * Destroy a semaphore
 */
int
cthread_sema_destroy(struct cthread_sema *s)
{
    if (!s)
        return POSIX_ERRNO(EINVAL);

    /* try to free it */
    if (_cthread_queue_destroy(s->blocked) < 0)
        return POSIX_ERRNO(EBUSY); /* queue in use */

    /* okay free it */
    _cthread_objcache_free(s->sched->sema_cache, s);
    return 0;
}

/*
 * Reset a semaphore to initialized state.
 */
int
cthread_sema_reset(struct cthread_sema *s)
{
    if (!s)
        return POSIX_ERRNO(EINVAL);

    do {
        struct cthread *ct;

        /* drain the queue waking everybody */
        ct = _cthread_queue_remove(s->blocked);

        if (!ct)
            break;

        ct->state &= ~CLEAR_STATE_BITS;

        /* wake up */
        _ready_queue_insert((struct cthread_sched *)ct->sched, ct);
    } while (!_cthread_queue_empty(s->blocked));

    s->sched = THIS_SCHED;
    atomic_store(&s->count, s->orig_count);

    return 0;
}

static inline void
_atomic32_cmp_and_add(atomic_int_least32_t *v, int inc)
{
    int32_t cnt;

    do {
        cnt = atomic_load(v);
    } while (!atomic_compare_exchange_strong(v, &cnt, cnt + inc));
}

/*
 * Wait on a semaphore
 */
int
cthread_sema_wait(struct cthread_sema *s, struct cthread_mutex *m)
{
    struct cthread *ct = THIS_CTHREAD;

    if (!s)
        return POSIX_ERRNO(EINVAL);

    _atomic32_cmp_and_add(&s->count, -1);

    if (atomic_load(&s->count) >= 0)
        return 0;

    /*
     * queue the current thread in the blocked queue
     * this will be written when we return to the scheduler
     * to ensure that the current thread context is saved
     * before any signal could result in it being dequeued and
     * resumed
     */
    ct->pending_wr_queue = s->blocked;

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
 * Wait on a semaphore with timeout
 */
int
cthread_sema_timedwait(struct cthread_sema *s, struct cthread_mutex *m,
                       const struct timespec *timeout)
{
    struct cthread *ct = THIS_CTHREAD;
    uint64_t nsecs;

    if (!s)
        return POSIX_ERRNO(EINVAL);

    _atomic32_cmp_and_add(&s->count, -1);

    if (atomic_load(&s->count) >= 0)
        return 0;

    /*
     * queue the current thread in the blocked queue
     * this will be written when we return to the scheduler
     * to ensure that the current thread context is saved
     * before any signal could result in it being dequeued and
     * resumed
     */
    ct->pending_wr_queue = s->blocked;

    nsecs    = (timeout->tv_sec * 1000000) + timeout->tv_nsec;
    ct->sema = s;

    if (m) {
        cthread_mutex_unlock(m);
        cthread_sleep(nsecs);
        cthread_mutex_lock(m);
    } else
        cthread_sleep(nsecs);

    if (ct->state & CT_STATE_EXPIRED)
        _atomic32_cmp_and_add(&s->count, 1);

    /* the condition happened or timeout */
    return (ct->state & CT_STATE_EXPIRED);
}

/*
 * Signal a semaphore and attempt to resume any blocked thread
 */
int
cthread_sema_signal(struct cthread_sema *s)
{
    struct cthread *ct;

    if (!s)
        return POSIX_ERRNO(EINVAL);

    _atomic32_cmp_and_add(&s->count, 1);

    if (atomic_load(&s->count) > 0)
        return 0;

    ct = _cthread_queue_remove(s->blocked);

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
 * Flush a semaphore
 */
static int
_sema_flush(struct cthread_sema *s, int resched)
{

    if (!s)
        return POSIX_ERRNO(EINVAL);

    atomic_store(&s->count, 0);

    do {
        /* drain the queue waking everybody */
        struct cthread *ct = _cthread_queue_remove(s->blocked);

        if (ct) {
            uint64_t state = ct->state;

            ct->state &= ~CLEAR_STATE_BITS;

            /* Cancel the timer if thread was sleeping */
            if (state & BIT(CT_STATE_SLEEPING))
                _timer_stop(ct);
            /* wake up */
            _ready_queue_insert(ct->sched, ct);
        }
    } while (!_cthread_queue_empty(s->blocked));

    if (resched)
        _reschedule();

    return 0;
}

int
cthread_sema_flush(struct cthread_sema *s)
{
    return _sema_flush(s, 1);
}

int
cthread_sema_flush_no_sched(struct cthread_sema *s)
{
    return _sema_flush(s, 0);
}
