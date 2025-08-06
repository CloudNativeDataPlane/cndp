/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

/*
 * Some portions of this software is derived from the
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
#include <sched.h>

#include <cne.h>
#include <cne_prefetch.h>
#include <cne_per_thread.h>
#include <cne_log.h>
#include <cne_common.h>
#include <cne_branch_prediction.h>
#include <cne_spinlock.h>
#include <uid.h>

#include "ctx.h"
#include "cthread.h"
#include "cthread_api.h"
#include "cthread_int.h"
#include "cthread_queue.h"
#include "cthread_sched.h"
#include "cthread_objcache.h"
#include "cthread_timer.h"
#include "cthread_mutex.h"
#include "cthread_cond.h"
#include "cthread_once.h"
#include "cthread_sema.h"
#include "cthread_tls.h"
#include "cthread_barrier.h"

/*
 * This file implements the cthread scheduler
 * The scheduler is the function cthread_run()
 * This must be run as the main loop of an EAL thread.
 *
 * Currently once a scheduler is created it cannot be destroyed
 * When a scheduler shuts down it is assumed that the application is terminating
 */

static STAILQ_HEAD(sched_list, cthread_sched) sched_head;
static cne_spinlock_recursive_t sched_lock;
static atomic_uint_least16_t num_schedulers;
static atomic_uint_least16_t active_schedulers;
static size_t sched_stack_size = CTHREAD_DEFAULT_STACK_SIZE;

/* one scheduler per thread */
CNE_DEFINE_PER_THREAD(struct cthread_sched *, this_sched) = NULL;

enum sched_alloc_phase {
    SCHED_ALLOC_OK,
    SCHED_ALLOC_QNODE_POOL,
    SCHED_ALLOC_READY_QUEUE,
    SCHED_ALLOC_PREADY_QUEUE,
    SCHED_ALLOC_CTHREAD_CACHE,
    SCHED_ALLOC_STACK_CACHE,
    SCHED_ALLOC_PERCT_CACHE,
    SCHED_ALLOC_TLS_CACHE,
    SCHED_ALLOC_COND_CACHE,
    SCHED_ALLOC_SEMA_CACHE,
    SCHED_ALLOC_MUTEX_CACHE,
    SCHED_ALLOC_ONCE_CACHE,
    SCHED_ALLOC_BARRIER_CACHE,
};

void
cthread_sched_stack_size_set(size_t stack_size)
{
    if (stack_size == 0)
        stack_size = CTHREAD_DEFAULT_STACK_SIZE;
    sched_stack_size = stack_size;
}

size_t
cthread_sched_stack_size(void)
{
    return sched_stack_size;
}

struct cthread_sched *
cthread_sched_find(int schedid)
{
    struct cthread_sched *sched = NULL;

    cne_spinlock_recursive_lock(&sched_lock);
    STAILQ_FOREACH (sched, &sched_head, next) {
        if (sched->sched_id == schedid)
            break;
    }
    cne_spinlock_recursive_unlock(&sched_lock);

    return sched;
}

int
cthread_sched_foreach(sched_cb_t func, void *arg)
{
    struct cthread_sched *sched = NULL;
    int ret                     = 0;

    cne_spinlock_recursive_lock(&sched_lock);
    STAILQ_FOREACH (sched, &sched_head, next) {
        ret = func(sched, arg, sched->sched_id);
        if (ret < 0)
            break;
    }
    cne_spinlock_recursive_unlock(&sched_lock);

    return ret;
}

int
cthread_sched_id(struct cthread_sched *s)
{
    if (!s)
        s = THIS_SCHED;
    return (s) ? s->sched_id : -1;
}

/*
 * Execute a ctx by invoking the start function
 * On return call an exit handler if the user has provided one
 */
static void
_cthread_exec(void *arg)
{
    struct cthread *ct = (struct cthread *)arg;

    /* invoke the contexts function */
    ct->fun(ct->arg);

    /* do exit handling */
    if (ct->exit_handler != NULL)
        ct->exit_handler(ct);
}

/*
 *	set the cthread stack
 */
static void
_cthread_set_stack(struct cthread *ct, void *stack, size_t stack_size)
{
    char *stack_top = (char *)stack + stack_size;
    void **s        = (void **)stack_top;

    /* set stack */
    ct->stack      = stack;
    ct->stack_size = stack_size;

    /* set initial context */
    s[-3]       = NULL;
    s[-2]       = (void *)ct;
    ct->ctx.rsp = (void *)(stack_top - (4 * sizeof(void *)));
    ct->ctx.rbp = (void *)(stack_top - (3 * sizeof(void *)));
    ct->ctx.rip = (void *)_cthread_exec;
}

static int
__sched_alloc_resources(struct cthread_sched *new_sched)
{
    int alloc_status;

    do {
        /* Initialize per scheduler queue node pool */
        alloc_status          = SCHED_ALLOC_QNODE_POOL;
        new_sched->qnode_pool = _qnode_pool_create("qnode pool", CTHREAD_PREALLOC);
        if (new_sched->qnode_pool == NULL)
            break;

        /* Initialize per scheduler local ready queue */
        alloc_status     = SCHED_ALLOC_READY_QUEUE;
        new_sched->ready = _cthread_queue_create("ready queue");
        if (new_sched->ready == NULL)
            break;

        /* Initialize per scheduler local peer ready queue */
        alloc_status      = SCHED_ALLOC_PREADY_QUEUE;
        new_sched->pready = _cthread_queue_create("pready queue");
        if (new_sched->pready == NULL)
            break;

        /* Initialize per scheduler local free cthread cache */
        alloc_status = SCHED_ALLOC_CTHREAD_CACHE;
        new_sched->cthread_cache =
            _cthread_objcache_create("cthread cache", sizeof(struct cthread), CTHREAD_PREALLOC);
        if (new_sched->cthread_cache == NULL)
            break;

        /* Initialize per scheduler local free stack cache */
        alloc_status = SCHED_ALLOC_STACK_CACHE;
        new_sched->stack_cache =
            _cthread_objcache_create("stack_cache", sched_stack_size, CTHREAD_PREALLOC);
        if (new_sched->stack_cache == NULL)
            break;

        if (CNE_PER_CTHREAD_SECTION_SIZE) {
            /* Initialize per scheduler local free per cthread data cache */
            alloc_status                 = SCHED_ALLOC_PERCT_CACHE;
            new_sched->per_cthread_cache = _cthread_objcache_create(
                "per_dt cache", CNE_PER_CTHREAD_SECTION_SIZE, CTHREAD_PREALLOC);
            if (new_sched->per_cthread_cache == NULL)
                break;
        } else
            new_sched->per_cthread_cache = NULL;

        /* Initialize per scheduler local free tls cache */
        alloc_status = SCHED_ALLOC_TLS_CACHE;
        new_sched->tls_cache =
            _cthread_objcache_create("TLS cache", sizeof(struct cthread_tls), CTHREAD_PREALLOC);
        if (new_sched->tls_cache == NULL)
            break;

        /* Initialize per scheduler local free cond var cache */
        alloc_status = SCHED_ALLOC_COND_CACHE;
        new_sched->cond_cache =
            _cthread_objcache_create("cond cache", sizeof(struct cthread_cond), CTHREAD_PREALLOC);
        if (new_sched->cond_cache == NULL)
            break;

        /* Initialize per scheduler local free cond var cache */
        alloc_status = SCHED_ALLOC_SEMA_CACHE;
        new_sched->sema_cache =
            _cthread_objcache_create("sema cache", sizeof(struct cthread_sema), CTHREAD_PREALLOC);
        if (new_sched->sema_cache == NULL)
            break;

        /* Initialize per scheduler local free cond var cache */
        alloc_status          = SCHED_ALLOC_BARRIER_CACHE;
        new_sched->barr_cache = _cthread_objcache_create(
            "barrier cache", sizeof(struct cthread_barrier), CTHREAD_PREALLOC);
        if (new_sched->barr_cache == NULL)
            break;

        /* Initialize per scheduler local free mutex cache */
        alloc_status = SCHED_ALLOC_MUTEX_CACHE;
        new_sched->mutex_cache =
            _cthread_objcache_create("mutex cache", sizeof(struct cthread_mutex), CTHREAD_PREALLOC);
        if (new_sched->mutex_cache == NULL)
            break;

        /* Initialize per scheduler local free once cache */
        alloc_status = SCHED_ALLOC_ONCE_CACHE;
        new_sched->once_cache =
            _cthread_objcache_create("once cache", sizeof(struct cthread_once), CTHREAD_PREALLOC);
        if (new_sched->once_cache == NULL)
            break;

        alloc_status = SCHED_ALLOC_OK;
    } while (0);

    /* roll back on any failure */
    switch (alloc_status) {
    case SCHED_ALLOC_ONCE_CACHE:
        _cthread_objcache_destroy(new_sched->mutex_cache);
    /* fall through */
    case SCHED_ALLOC_MUTEX_CACHE:
        _cthread_objcache_destroy(new_sched->barr_cache);
    /* fall through */
    case SCHED_ALLOC_BARRIER_CACHE:
        _cthread_objcache_destroy(new_sched->sema_cache);
    /* fall through */
    case SCHED_ALLOC_SEMA_CACHE:
        _cthread_objcache_destroy(new_sched->cond_cache);
    /* fall through */
    case SCHED_ALLOC_COND_CACHE:
        _cthread_objcache_destroy(new_sched->tls_cache);
    /* fall through */
    case SCHED_ALLOC_TLS_CACHE:
        _cthread_objcache_destroy(new_sched->per_cthread_cache);
    /* fall through */
    case SCHED_ALLOC_PERCT_CACHE:
        _cthread_objcache_destroy(new_sched->stack_cache);
    /* fall through */
    case SCHED_ALLOC_STACK_CACHE:
        _cthread_objcache_destroy(new_sched->cthread_cache);
    /* fall through */
    case SCHED_ALLOC_CTHREAD_CACHE:
        _cthread_queue_destroy(new_sched->pready);
    /* fall through */
    case SCHED_ALLOC_PREADY_QUEUE:
        _cthread_queue_destroy(new_sched->ready);
    /* fall through */
    case SCHED_ALLOC_READY_QUEUE:
        _qnode_pool_destroy(new_sched->qnode_pool);
    /* fall through */
    case SCHED_ALLOC_QNODE_POOL:
    /* fall through */
    case SCHED_ALLOC_OK:
        break;
    }
    return alloc_status;
}

/*
 * Create a scheduler on the current thread
 */
int
cthread_sched_create(size_t stack_size)
{
    int status;
    struct cthread_sched *new_sched;
    int schedid = cne_id();
    char uid_name[32];

    if (stack_size == 0)
        stack_size = sched_stack_size;

    if (THIS_SCHED)
        return 0;

    cne_timer_subsystem_init();

    new_sched = calloc(1, sizeof(struct cthread_sched));
    if (new_sched == NULL)
        CNE_ERR_RET("Failed to allocate memory for scheduler\n");
    STAILQ_INIT(&new_sched->threads);

    _cthread_key_pool_init();

    new_sched->stack_size = stack_size;
    new_sched->birth      = cne_rdtsc();
    snprintf(uid_name, sizeof(uid_name), "cthread-%d", schedid);
    new_sched->uid_pool = uid_register(uid_name, DEFAULT_MAX_THREADS);
    THIS_SCHED          = new_sched;

    status = __sched_alloc_resources(new_sched);
    if (status != SCHED_ALLOC_OK) {
        free(new_sched);
        CNE_ERR_RET("Failed to allocate resources for scheduler code = %d\n", status);
    }

    bzero(&new_sched->ctx, sizeof(struct ctx));

    new_sched->sched_id = schedid;

    cne_spinlock_recursive_init(&new_sched->lock);

    cne_spinlock_recursive_lock(&sched_lock);

    STAILQ_INSERT_TAIL(&sched_head, new_sched, next);

    new_sched->run_flag = 1;

    cne_spinlock_recursive_unlock(&sched_lock);

    cne_compiler_barrier();

    return schedid;
}

/*
 * Set the number of schedulers in the system
 */
int
cthread_num_schedulers_set(int num)
{
    atomic_store(&num_schedulers, num);
    return (int)atomic_load(&num_schedulers);
}

/*
 * Return the number of schedulers active
 */
int
cthread_active_schedulers(void)
{
    return (int)atomic_load(&active_schedulers);
}

/**
 * shutdown the scheduler running on the specified thread
 */
void
cthread_scheduler_shutdown(int threadid)
{
    struct cthread_sched *sched = cthread_sched_find(threadid);

    if (sched)
        sched->run_flag = 0;
}

/**
 * shutdown all schedulers
 */
void
cthread_scheduler_shutdown_all(void)
{
    struct cthread_sched *sched;

    /*
     * give time for all schedulers to have started
     * Note we use sched_yield() rather than pthread_yield() to allow
     * for the possibility of a pthread wrapper on cthread_yield(),
     * something that is not possible unless the scheduler is running.
     */
    while (atomic_load(&active_schedulers) < atomic_load(&num_schedulers))
        sched_yield();

    cne_spinlock_recursive_lock(&sched_lock);
    STAILQ_FOREACH (sched, &sched_head, next) {
        sched->run_flag = 0;
    }
    cne_spinlock_recursive_unlock(&sched_lock);
}

/*
 * Resume a suspended cthread
 */
static __attribute__((always_inline)) inline void
_cthread_resume(struct cthread *ct)
{
    struct cthread_sched *sched = THIS_SCHED;
    struct cthread_stack *s;
    uint64_t state;

    if (!ct)
        return;

    state                  = ct->state;
    sched->current_cthread = ct;

    if (state & (BIT(CT_STATE_CANCELLED) | BIT(CT_STATE_EXITED))) {
        /* if detached we can free the thread now */
        if (state & BIT(CT_STATE_DETACH)) {
            _cthread_free(ct);
            sched->current_cthread = NULL;
            return;
        }
    }

    if (state & BIT(CT_STATE_INIT)) {
        s = _stack_alloc(); /* allocate stack */
        if (!s)
            return;

        /* allocate memory for TLS used by this thread */
        if (_cthread_tls_alloc(ct) < 0) {
            _stack_free(s);
            return;
        }

        ct->stack_container = s;
        _cthread_set_stack(ct, &s->stack_start[0], s->stack_size);

        ct->state = BIT(CT_STATE_READY);
    }

    /* switch to the new thread */
    cthread_switch(&ct->ctx, &sched->ctx);

    /* If posting to a queue that could be read by another thread
     * we defer the queue write till now to ensure the context has been
     * saved before the other core tries to resume it
     * This applies to blocking on mutex, cond, and to set_affinity
     */
    if (ct->pending_wr_queue) {
        struct cthread_queue *dest = ct->pending_wr_queue;

        ct->pending_wr_queue = NULL;

        /* queue the current thread to the specified queue */
        _cthread_queue_insert_mp(dest, ct);
    }

    sched->current_cthread = NULL;
}

/*
 * Handle sleep timer expiry
 */
void
_sched_timer_cb(struct cne_timer *tim, void *arg)
{
    struct cthread *ct = (struct cthread *)arg;
    uint64_t state     = ct->state;

    cne_timer_stop_sync(tim);

    if (ct->state & BIT(CT_STATE_CANCELLED))
        (THIS_SCHED)->nb_blocked_threads--;

    ct->state = state | BIT(CT_STATE_EXPIRED);
    if (ct->cond) {
        _cthread_queue_remove_given(ct->cond->blocked, ct);
        ct->cond = NULL;
    }
    _cthread_resume(ct);
    ct->state = state & ~BIT(CT_STATE_EXPIRED);
}

/*
 * Returns 0 if there is a pending job in scheduler or 1 if done and can exit.
 */
static inline int
_cthread_sched_isdone(struct cthread_sched *sched)
{
    if (sched->run_flag == 0)
        return 1;
    return (_cthread_queue_empty(sched->ready) && _cthread_queue_empty(sched->pready) &&
            (sched->nb_blocked_threads == 0));
}

/*
 * Wait for all schedulers to start
 */
static inline void
_cthread_schedulers_sync_start(void)
{
    atomic_fetch_add(&active_schedulers, 1);

    /* wait for cthread schedulers
     * Note we use sched_yield() rather than pthread_yield() to allow
     * for the possibility of a pthread wrapper on cthread_yield(),
     * something that is not possible unless the scheduler is running.
     */
    while (atomic_load(&active_schedulers) < atomic_load(&num_schedulers))
        sched_yield();
}

/*
 * Wait for all schedulers to stop
 */
static inline void
_cthread_schedulers_sync_stop(void)
{
    atomic_fetch_sub(&active_schedulers, 1);
    atomic_fetch_sub(&num_schedulers, 1);

    /* wait for schedulers
     * Note we use sched_yield() rather than pthread_yield() to allow
     * for the possibility of a pthread wrapper on cthread_yield(),
     * something that is not possible unless the scheduler is running.
     */
    while (atomic_load(&active_schedulers) > 0)
        sched_yield();
}

#define POLL_TIMER_VALUE 512
/*
 * Run the cthread scheduler
 * This loop is the heart of the system
 */
void
cthread_run(void)
{
    struct cthread_sched *sched = THIS_SCHED;
    uint32_t cnt;

    if (!sched)
        return;

    /* if more than one, wait for all schedulers to start */
    _cthread_schedulers_sync_start();

    /*
     * This is the main scheduling loop
     * So long as there are tasks in existence we run this loop.
     * We check for:-
     *   expired timers,
     *   the local ready queue,
     *   and the peer ready queue,
     *
     * and resume cthreads ad infinitum.
     */
    cnt = POLL_TIMER_VALUE;
    while (!_cthread_sched_isdone(sched)) {
        if (--cnt == 0) {
            cne_timer_manage();
            cnt = POLL_TIMER_VALUE;
        }

        _cthread_resume(_cthread_queue_poll(sched->ready));

        _cthread_resume(_cthread_queue_poll(sched->pready));
    }

    /* if more than one wait for all schedulers to stop */
    _cthread_schedulers_sync_stop();

    fflush(stdout);
}

/*
 * migrate the current thread to another scheduler running
 * on the specified thread.
 */
int
cthread_set_affinity(int threadid)
{
    struct cthread *ct               = THIS_CTHREAD;
    struct cthread_sched *dest_sched = cthread_sched_find(threadid);

    if (unlikely(dest_sched == NULL))
        return POSIX_ERRNO(EINVAL);

    if (likely(dest_sched != THIS_SCHED)) {
        ct->sched            = dest_sched;
        ct->pending_wr_queue = dest_sched->pready;
        _affinitize();
        return 0;
    }
    return 0;
}

/* constructor */
CNE_INIT_PRIO(_sched_ctor, THREAD)
{
    STAILQ_INIT(&sched_head);

    cne_spinlock_recursive_init(&sched_lock);

    atomic_store(&num_schedulers, 1);
    atomic_store(&active_schedulers, 0);
}
