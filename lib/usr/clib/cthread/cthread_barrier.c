/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
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
#include <bsd/string.h>

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
#include "cthread_barrier.h"

/*
 * Create a barrier
 */
int
cthread_barrier_init(const char *name, struct cthread_barrier **barr, unsigned count)
{
    struct cthread_barrier *b;

    if (!barr || count == 0)
        return POSIX_ERRNO(EINVAL);

    /* allocate a barrier from cache */
    b = _cthread_objcache_alloc((THIS_SCHED)->barr_cache);
    if (!b)
        return POSIX_ERRNO(EAGAIN);

    cthread_mutex_init("barrier", &b->mutex, NULL);
    cthread_cond_init("b_cond", &b->cv, NULL);

    b->count = count;
    b->sched = THIS_SCHED;
    strlcpy(b->name, name, MAX_BARRIER_NAME_SIZE);

    (*barr) = b;
    return 0;
}

/*
 * Destroy a semaphore
 */
int
cthread_barrier_destroy(struct cthread_barrier *b)
{
    if (!b)
        return POSIX_ERRNO(EINVAL);

    cthread_mutex_lock(b->mutex);
    if (b->destroying) {
        cthread_mutex_unlock(b->mutex);
        return EBUSY;
    }
    b->destroying = 1;

    do {
        if (b->waiters > 0) {
            b->destroying = 0;
            cthread_mutex_unlock(b->mutex);
            return EBUSY;
        }
        if (b->refcount != 0) {
            cthread_cond_wait(b->cv, b->mutex);
            cthread_mutex_lock(b->mutex);
        } else
            break;
    } while (1);
    b->destroying = 0;
    cthread_mutex_unlock(b->mutex);

    cthread_cond_destroy(b->cv);
    cthread_mutex_destroy(b->mutex);

    /* okay free it */
    _cthread_objcache_free(b->sched->barr_cache, b);

    return 0;
}

/*
 * Wait on a barrier for all threads to join
 */
int
cthread_barrier_wait(struct cthread_barrier *b)
{
    int64_t cycle;

    if (!b)
        return POSIX_ERRNO(EINVAL);

    cthread_mutex_lock(b->mutex);
    if (++b->waiters == b->count) {
        b->waiters = 0;
        b->cycle++;

        cthread_cond_broadcast(b->cv);
        cthread_mutex_unlock(b->mutex);
    } else {
        cycle = b->cycle;
        b->refcount++;
        do {
            cthread_cond_wait(b->cv, b->mutex);
        } while (cycle == b->cycle);

        if (--b->refcount == 0 && b->destroying)
            cthread_cond_broadcast(b->cv);

        cthread_mutex_unlock(b->mutex);
    }

    /* the condition happened */
    return 0;
}
