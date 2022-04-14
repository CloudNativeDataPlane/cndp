/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
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

#include <cne.h>
#include <cne_prefetch.h>
#include <cne_log.h>
#include <cne_tailq.h>
#include <cne_spinlock.h>

#include "ctx.h"

#include "cthread_api.h"
#include "cthread.h"
#include "cthread_queue.h"
#include "cthread_timer.h"
#include "cthread_tls.h"
#include "cthread_objcache.h"
#include "cthread_cond.h"

struct cthread_sched *
cthread_get_sched(struct cthread *c)
{
    if (!c)
        c = THIS_CTHREAD;
    return (c) ? c->sched : NULL;
}

struct cthread *
cthread_find(struct cthread_sched *sched, int threadid)
{
    struct cthread *c = NULL;

    if (!sched)
        sched = THIS_SCHED;

    if (sched) {
        cne_spinlock_recursive_lock(&sched->lock);
        STAILQ_FOREACH (c, &sched->threads, next) {
            if (c->cthread_id == threadid || threadid == -1)
                break;
        }
        cne_spinlock_recursive_unlock(&sched->lock);
    }
    return c;
}

int
cthread_foreach(struct cthread_sched *sched, cthread_cb_t func, void *arg)
{
    struct cthread *c = NULL;
    int ret           = 0;

    cne_spinlock_recursive_lock(&sched->lock);
    STAILQ_FOREACH (c, &sched->threads, next) {
        ret = func(c, arg, c->cthread_id);
        if (ret < 0)
            break;
    }
    cne_spinlock_recursive_unlock(&sched->lock);

    return ret;
}

void *
cthread_thread_private(struct cthread *c)
{
    return (!c) ? NULL : c->private_data;
}

int
cthread_set_thread_private(struct cthread *c, void *arg)
{
    if (!c)
        c = THIS_CTHREAD;
    if (!c)
        return -1;
    c->private_data = arg;
    return 0;
}

/*
 * This function gets called after an cthread function has returned.
 */
void
_cthread_exit_handler(struct cthread *ct)
{
    ct->state |= BIT(CT_STATE_EXITED);

    if (!(ct->state & BIT(CT_STATE_DETACH))) {
        /* thread is this not explicitly detached
         * it must be joinable, so we call cthread_exit().
         */
        cthread_exit(NULL);
    }

    /* if we get here the thread is detached so we can reschedule it,
     * allowing the scheduler to free it
     */
    _reschedule();
}

/*
 * Free resources allocated to an cthread
 */
void
_cthread_free(struct cthread *ct)
{
    struct cthread *d;

    if (!ct)
        return;

    /* invoke any user TLS destructor functions */
    _cthread_tls_destroy(ct);

    /* free memory allocated for TLS defined using CNE_PER_CTHREAD macros */
    if (sizeof(void *) < (uint64_t)CNE_PER_CTHREAD_SECTION_SIZE)
        _cthread_objcache_free(ct->tls->sched->per_cthread_cache, ct->per_cthread_data);

    /* free pthread style TLS memory */
    _cthread_objcache_free(ct->tls->sched->tls_cache, ct->tls);

    /* free the stack */
    _cthread_objcache_free(ct->stack_container->sched->stack_cache, ct->stack_container);

    cne_spinlock_recursive_lock(&THIS_SCHED->lock);

    /* find out tailq entry */
    STAILQ_FOREACH (d, &THIS_SCHED->threads, next) {
        if (d == (void *)ct) {
            STAILQ_REMOVE(&THIS_SCHED->threads, d, cthread, next);
            break;
        }
    }

    uid_free(THIS_SCHED->uid_pool, ct->cthread_id);

    cne_spinlock_recursive_unlock(&THIS_SCHED->lock);

    /* now free the thread */
    _cthread_objcache_free(ct->sched->cthread_cache, ct);
}

/*
 * Allocate a stack and maintain a cache of stacks
 */
struct cthread_stack *
_stack_alloc(void)
{
    struct cthread_stack *s;

    s = _cthread_objcache_alloc((THIS_SCHED)->stack_cache);
    if (!s)
        CNE_NULL_RET("objcache stack_cache is empty\n");

    s->sched      = THIS_SCHED;
    s->stack_size = cthread_sched_stack_size() - sizeof(struct cthread_stack);

    return s;
}

void
_stack_free(struct cthread_stack *s)
{
    _cthread_objcache_free((THIS_SCHED)->stack_cache, s);
}

/*
 *	Initialize an cthread
 *	Set its function, args, and exit handler
 */
static void
_cthread_init(struct cthread *ct, const char *name, cthread_func_t fun, void *arg,
              cthread_exit_func exit_handler)
{
    /* set ctx func and args */
    ct->fun          = fun;
    ct->arg          = arg;
    ct->exit_handler = exit_handler;
    ct->cthread_id   = uid_alloc(THIS_SCHED->uid_pool);

    /* set initial state */
    ct->birth = _sched_now();
    ct->state = BIT(CT_STATE_INIT);
    ct->join  = CT_JOIN_INITIAL;

    strlcpy(ct->name, name, sizeof(ct->name));
}

/*
 * Create a cthread on the current scheduler
 * If there is no current scheduler on this pthread then first create one
 */
struct cthread *
cthread_create(const char *name, cthread_func_t fun, void *arg)
{
    if (!fun)
        CNE_NULL_RET("Invalid arguments\n");

    if (!name)
        name = "Not Set";

    if (!THIS_SCHED && cthread_sched_create(0) < 0)
        CNE_NULL_RET("Unable to create scheduler\n");

    cne_spinlock_recursive_lock(&THIS_SCHED->lock);

    /* allocate a thread structure */
    struct cthread *ct = _cthread_objcache_alloc((THIS_SCHED)->cthread_cache);
    if (!ct) {
        cne_spinlock_recursive_unlock(&THIS_SCHED->lock);
        CNE_NULL_RET("Unable to allocate struct cthread\n");
    }

    bzero(ct, sizeof(struct cthread));
    ct->sched = THIS_SCHED;

    /* set the function args and exit handlder */
    _cthread_init(ct, name, fun, arg, _cthread_exit_handler);

    STAILQ_INSERT_TAIL(&THIS_SCHED->threads, ct, next);
    THIS_SCHED->thread_count++;

    cne_spinlock_recursive_unlock(&THIS_SCHED->lock);

    cne_compiler_barrier();
    _ready_queue_insert(THIS_SCHED, ct);

    return ct;
}

static void
_cthread_dump(FILE *f, const struct cthread *ct)
{
    const char *states[] = CTHREAD_STATES;
    int i;

    fprintf(f, "  %p:  %-16s < ", ct, ct->name);
    for (i = 0; i < NUM_STATES; i++)
        if (ct->state & BIT(i))
            fprintf(f, "%s ", states[i]);
    fprintf(f, ">\n");
}

void
cthread_list(FILE *f, int tid)
{
    struct cthread *ct;
    struct cthread_sched *sched = cthread_sched_find(tid);

    if (sched == NULL)
        return;

    if (!f)
        f = stdout;

    fprintf(f, "== cthread list on thread %d ==\n", tid);

    cne_spinlock_recursive_lock(&sched->lock);

    fprintf(f, "Scheduler thread list is %sempty\n", STAILQ_EMPTY(&sched->threads) ? "" : "Not ");

    STAILQ_FOREACH (ct, &sched->threads, next) {
        _cthread_dump(f, ct);
    }
    ct = sched->current_cthread;
    fprintf(f, "    Current Running thread: %s\n", cthread_get_name(ct));

    cne_spinlock_recursive_unlock(&sched->lock);
}

/*
 * Schedules cthread to sleep for `nsecs`
 * setting the cthread state to CT_STATE_SLEEPING.
 * cthread state is cleared upon resumption or expiry.
 */
static inline void
_cthread_sched_sleep(struct cthread *ct, uint64_t nsecs)
{
    uint64_t clks = _ns_to_clks(nsecs);

    if (clks) {
        _timer_start(ct, clks);

        ct->state |= BIT(CT_STATE_SLEEPING);
        _suspend();

        /* Remove ct from condition variable blocked queue */
        if (ct->cond) {
            struct cthread *_dt;
            _dt = _cthread_queue_remove_given(ct->cond->blocked, ct);
            if (_dt && (ct != _dt)) {
                if (_dt)
                    fprintf(stderr, "%s: thread %s\n", __func__, cthread_get_name(_dt));
                cne_panic("wrong thread dequeued %p\n", _dt);
            }
            ct->cond = NULL;
        }
        ct->state &= ~BIT(CT_STATE_SLEEPING);
    } else
        _reschedule();
}

/*
 * Cancels any running timer.
 * This can be called multiple times on the same cthread regardless if it was
 * sleeping or not.
 */
int
_cthread_desched_sleep(struct cthread *ct)
{
    uint64_t state = ct->state;

    if (state & BIT(CT_STATE_SLEEPING)) {
        _timer_stop(ct);
        state &= ~(BIT(CT_STATE_SLEEPING) | BIT(CT_STATE_EXPIRED));
        ct->state = state | BIT(CT_STATE_READY);
        return 1;
    }
    return 0;
}

/*
 * set user data pointer in an cthread
 */
void
cthread_set_data(void *data)
{
    if (sizeof(void *) == CNE_PER_CTHREAD_SECTION_SIZE)
        THIS_CTHREAD->per_cthread_data = data;
}

/*
 * Retrieve user data pointer from an cthread
 */
void *
cthread_get_data(void)
{
    return THIS_CTHREAD->per_cthread_data;
}

/*
 * Return the current cthread handle
 */
struct cthread *
cthread_current(void)
{
    struct cthread_sched *sched = THIS_SCHED;

    if (sched)
        return sched->current_cthread;
    return NULL;
}

int
cthread_id_get(struct cthread *c)
{
    return (c) ? c->cthread_id : -1;
}

int
cthread_timer_expired(struct cthread *ct)
{
    if (!ct)
        ct = THIS_CTHREAD;
    return (ct->state & CT_STATE_EXPIRED);
}

/*
 * Tasklet to cancel a thread
 */
static void
_cancel(void *arg)
{
    struct cthread *ct = (struct cthread *)arg;

    ct->state |= BIT(CT_STATE_CANCELLED);
    cthread_detach();
}

/*
 * Mark the specified thread as canceled
 */
int
cthread_cancel(struct cthread *ct)
{
    if ((ct == NULL) || (ct == THIS_CTHREAD))
        return POSIX_ERRNO(EINVAL);

    if (ct->sched != THIS_SCHED)
        cthread_create("Cancel", _cancel, ct); /* spawn task-let to cancel the thread */
    else
        ct->state |= BIT(CT_STATE_CANCELLED);
    return 0;
}

void
_cthread_wait(void)
{
    struct cthread *ct = THIS_CTHREAD;

    ct->state |= BIT(CT_STATE_COND_WAITING);
    _suspend();
    ct->state &= ~BIT(CT_STATE_COND_WAITING);
}

void
_cthread_mutex_wait(void)
{
    struct cthread *ct = THIS_CTHREAD;

    ct->state |= BIT(CT_STATE_MUTEX_WAITING);
    _suspend();
    ct->state &= ~BIT(CT_STATE_MUTEX_WAITING);
}

/*
 * Suspend the current cthread for specified time
 */
void
cthread_sleep(uint64_t nsecs)
{
    struct cthread *ct = THIS_CTHREAD;

    _cthread_sched_sleep(ct, nsecs);
}

/*
 * Suspend the current cthread for specified time
 */
void
cthread_sleep_clks(uint64_t clks)
{
    struct cthread *ct = THIS_CTHREAD;

    _cthread_sched_sleep(ct, _clks_to_ns(clks));
}

void
cthread_sleep_nsecs(uint64_t nsecs)
{
    struct cthread *ct = THIS_CTHREAD;

    _cthread_sched_sleep(ct, nsecs);
}

void
cthread_sleep_msec(uint64_t ms)
{
    struct cthread *ct = THIS_CTHREAD;

    _cthread_sched_sleep(ct, ms * 1000000UL);
}

/*
 * Requeue the current thread to the back of the ready queue
 */
void
cthread_yield(void)
{
    struct cthread *ct = THIS_CTHREAD;

    _ready_queue_insert(THIS_SCHED, ct);

    cthread_switch(&(THIS_SCHED)->ctx, &ct->ctx);
}

/*
 * Exit the current cthread
 * If a thread is joining pass the user pointer to it
 */
void
cthread_exit(void *ptr)
{
    struct cthread *c = THIS_CTHREAD;

    if (THIS_SCHED == NULL)
        return;

    /* if thread is detached (this is not valid) just exit */
    if (!c || (c->state & BIT(CT_STATE_DETACH)))
        return;

    /* There is a race between cthread_join() and cthread_exit()
     *  - if exit before join then we suspend and resume on join
     *  - if join before exit then we resume the joining thread
     */
    uint64_t v = atomic_load(&c->join);
    if ((c->join == CT_JOIN_INITIAL) &&
        atomic_compare_exchange_strong(&c->join, &v, CT_JOIN_EXITING)) {

        _suspend();

        /* set the exit value */
        if ((ptr != NULL) && (c->dt_join->dt_exit_ptr != NULL))
            *(c->dt_join->dt_exit_ptr) = ptr;

        /* let the joining thread know we have set the exit value */
        c->join = CT_JOIN_EXIT_VAL_SET;
    } else {
        /* set the exit value */
        if ((ptr != NULL) && (c->dt_join->dt_exit_ptr != NULL))
            *(c->dt_join->dt_exit_ptr) = ptr;

        /* let the joining thread know we have set the exit value */
        c->join = CT_JOIN_EXIT_VAL_SET;
        _ready_queue_insert(c->dt_join->sched, (struct cthread *)c->dt_join);
    }

    /* wait until the joining thread has collected the exit value */
    while (c->join != CT_JOIN_EXIT_VAL_READ)
        _reschedule();

    /* reset join state */
    c->join = CT_JOIN_INITIAL;

    /* detach it so its resources can be released */
    c->state |= (BIT(CT_STATE_DETACH) | BIT(CT_STATE_EXITED));

    atomic_fetch_sub(&THIS_SCHED->thread_count, 1);
}

/*
 * Join an cthread
 * Suspend until the joined thread returns
 */
int
cthread_join(struct cthread *ct, void **ptr)
{
    if (ct == NULL)
        return POSIX_ERRNO(EINVAL);

    struct cthread *current = THIS_CTHREAD;
    uint64_t dt_state       = ct->state;

    /* invalid to join a detached thread, or a thread that is joined */
    if ((dt_state & BIT(CT_STATE_DETACH)) || (ct->join == CT_JOIN_THREAD_SET))
        return POSIX_ERRNO(EINVAL);

    /* pointer to the joining thread and a poingter to return a value */
    ct->dt_join          = current;
    current->dt_exit_ptr = ptr;

    /* There is a race between cthread_join() and cthread_exit()
     *  - if join before exit we suspend and will resume when exit is called
     *  - if exit before join we resume the exiting thread
     */
    uint64_t c = atomic_load(&ct->join);
    if ((ct->join == CT_JOIN_INITIAL) &&
        atomic_compare_exchange_strong(&ct->join, &c, CT_JOIN_THREAD_SET))
        _suspend();
    else
        _ready_queue_insert(ct->sched, ct);

    /* wait for exiting thread to set return value */
    while (ct->join != CT_JOIN_EXIT_VAL_SET)
        _reschedule();

    /* collect the return value */
    if (ptr != NULL)
        *ptr = *current->dt_exit_ptr;

    /* let the exiting thread proceed to exit */
    ct->join = CT_JOIN_EXIT_VAL_READ;
    return 0;
}

/**
 * Detach current cthread
 * A detached thread cannot be joined
 */
void
cthread_detach(void)
{
    struct cthread *ct = THIS_CTHREAD;

    ct->state |= BIT(CT_STATE_DETACH);
}

/**
 * Set thread name of a cthread
 */
void
cthread_set_name(const char *f)
{
    struct cthread *ct = THIS_CTHREAD;

    strlcpy(ct->name, f, sizeof(ct->name));
}

const char *
cthread_get_name(struct cthread *ct)
{
    if (!ct)
        ct = THIS_CTHREAD;

    return (ct) ? ct->name : "No-Thread";
}
