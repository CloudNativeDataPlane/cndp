/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2023 Intel Corporation
 */

#include <string.h>                       // for memset
#include <stdio.h>                        // for fprintf, FILE, stdout
#include <stdint.h>                       // for uint64_t, uint32_t, int16_t, UINT...
#include <stdlib.h>                       // for calloc, rand
#include <inttypes.h>                     // for PRIu64
#include <stdatomic.h>                    // for memory_order_relaxed, atomic_comp...
#include <cne_common.h>                   // for cne_compiler_barrier, cne_bsf32
#include <cne.h>                          // for cne_id, cne_max_threads
#include <cne_cycles.h>                   // for cne_rdtsc
#include <cne_branch_prediction.h>        // for likely
#include <cne_spinlock.h>                 // for cne_spinlock_unlock, cne_spinlock...
#include <cne_pause.h>                    // for cne_pause
#include <stddef.h>                       // for NULL

#include "cne_timer.h"

struct priv_timer {
    struct cne_timer pending_head; /**< dummy timer instance to head up list */
    cne_spinlock_t list_lock;      /**< lock to protect list access */

    /** per-core variable that true if a timer was updated on this
     *  core since last reset of the variable */
    int updated;

    /** track the current depth of the skiplist */
    unsigned curr_skiplist_depth;

    unsigned prev_thread; /**< used for thread round robin */

    /** running timer on this thread now */
    struct cne_timer *running_tim;

    /** per-thread statistics */
    struct cne_timer_debug_stats stats;
} __cne_cache_aligned;

/** per-thread private info for timers */
static struct priv_timer *priv_timer;

/* when debug is enabled, store some statistics */
#define __TIMER_STAT_ADD(name, n)                \
    do {                                         \
        unsigned __tid = cne_id();               \
        if (__tid < (unsigned)cne_max_threads()) \
            priv_timer[__tid].stats.name += (n); \
    } while (0)

/* Init the timer library. */
void
cne_timer_subsystem_init(void)
{
    if (priv_timer)
        return;

    priv_timer = calloc(cne_max_threads(), sizeof(struct priv_timer));
    if (!priv_timer)
        return;

    /* since priv_timer is static, it's zeroed by default, so only init some fields. */
    for (int tid = 0; tid < cne_max_threads(); tid++) {
        cne_spinlock_init(&priv_timer[tid].list_lock);
        priv_timer[tid].prev_thread = tid;
    }
}

/* Initialize the timer handle tim for use */
void
cne_timer_init(struct cne_timer *tim)
{
    union cne_timer_status status;

    status.state    = CNE_TIMER_STOP;
    status.owner    = CNE_TIMER_NO_OWNER;
    tim->status.u32 = status.u32;
}

/*
 * if timer is pending or stopped (or running on the same core than
 * us), mark timer as configuring, and on success return the previous
 * status of the timer
 */
static int
timer_set_config_state(struct cne_timer *tim, union cne_timer_status *ret_prev_status)
{
    union cne_timer_status prev_status, status;
    uint32_t prev_status_non_atomic;
    int success = 0;
    unsigned tid;

    tid = cne_id();

    /* wait that the timer is in correct status before update,
     * and mark it as being configured */
    while (success == 0) {
        prev_status.u32        = tim->status.u32;
        prev_status_non_atomic = prev_status.u32;

        /* timer is running on another core
         * or ready to run on local core, exit
         */
        if (prev_status.state == CNE_TIMER_RUNNING &&
            (prev_status.owner != (uint16_t)tid || tim != priv_timer[tid].running_tim))
            return -1;

        /* timer is being configured on another core */
        if (prev_status.state == CNE_TIMER_CONFIG)
            return -1;

        /* here, we know that timer is stopped or pending,
         * mark it atomically as being configured */
        status.state = CNE_TIMER_CONFIG;
        status.owner = (int16_t)tid;
        success = atomic_compare_exchange_strong_explicit(&tim->status.u32, &prev_status_non_atomic,
                                                          status.u32, memory_order_relaxed,
                                                          memory_order_relaxed);
    }

    ret_prev_status->u32 = prev_status.u32;
    return 0;
}

/*
 * if timer is pending, mark timer as running
 */
static int
timer_set_running_state(struct cne_timer *tim)
{
    union cne_timer_status prev_status, status;
    uint32_t prev_status_non_atomic;
    unsigned tid = cne_id();
    int success  = 0;

    /* wait that the timer is in correct status before update,
     * and mark it as running */
    while (success == 0) {
        prev_status.u32        = tim->status.u32;
        prev_status_non_atomic = prev_status.u32;

        /* timer is not pending anymore */
        if (prev_status.state != CNE_TIMER_PENDING)
            return -1;

        /* here, we know that timer is stopped or pending,
         * mark it atomically as being configured */
        status.state = CNE_TIMER_RUNNING;
        status.owner = (int16_t)tid;
        success = atomic_compare_exchange_strong_explicit(&tim->status.u32, &prev_status_non_atomic,
                                                          status.u32, memory_order_relaxed,
                                                          memory_order_relaxed);
    }

    return 0;
}

/*
 * Return a skiplist level for a new entry.
 * This probabilistically gives a level with p=1/4 that an entry at level n
 * will also appear at level n+1.
 */
static uint32_t
timer_get_skiplist_level(unsigned curr_depth)
{
    /* probability value is 1/4, i.e. all at level 0, 1 in 4 is at level 1,
     * 1 in 16 at level 2, 1 in 64 at level 3, etc. Calculated using lowest
     * bit position of a (pseudo)random number.
     */
    uint32_t rnd   = rand() & (UINT32_MAX - 1);
    uint32_t level = rnd == 0 ? MAX_SKIPLIST_DEPTH : (cne_bsf32(rnd) - 1) / 2;

    /* limit the levels used to one above our current level, so we don't,
     * for instance, have a level 0 and a level 7 without anything between
     */
    if (level > curr_depth)
        level = curr_depth;
    if (level >= MAX_SKIPLIST_DEPTH)
        level = MAX_SKIPLIST_DEPTH - 1;

    return level;
}

/*
 * For a given time value, get the entries at each level which
 * are <= that time value.
 */
static void
timer_get_prev_entries(uint64_t time_val, unsigned tim_thread, struct cne_timer **prev)
{
    unsigned lvl = priv_timer[tim_thread].curr_skiplist_depth;
    prev[lvl]    = &priv_timer[tim_thread].pending_head;
    while (lvl != 0) {
        lvl--;
        prev[lvl] = prev[lvl + 1];
        while (prev[lvl]->sl_next[lvl] && prev[lvl]->sl_next[lvl]->expire <= time_val)
            prev[lvl] = prev[lvl]->sl_next[lvl];
    }
}

/*
 * Given a timer node in the skiplist, find the previous entries for it at
 * all skiplist levels.
 */
static void
timer_get_prev_entries_for_node(struct cne_timer *tim, unsigned tim_thread, struct cne_timer **prev)
{
    int i;
    /* to get a specific entry in the list, look for just lower than the time
     * values, and then increment on each level individually if necessary
     */
    timer_get_prev_entries(tim->expire - 1, tim_thread, prev);
    for (i = priv_timer[tim_thread].curr_skiplist_depth - 1; i >= 0; i--) {
        while (prev[i]->sl_next[i] != NULL && prev[i]->sl_next[i] != tim &&
               prev[i]->sl_next[i]->expire <= tim->expire)
            prev[i] = prev[i]->sl_next[i];
    }
}

/* call with lock held as necessary
 * add in list
 * timer must be in config state
 * timer must not be in a list
 */
static void
timer_add(struct cne_timer *tim, unsigned int tim_thread)
{
    unsigned lvl;
    struct cne_timer *prev[MAX_SKIPLIST_DEPTH + 1] = {0};

    /* find where exactly this element goes in the list of elements
     * for each depth. */
    timer_get_prev_entries(tim->expire, tim_thread, prev);

    /* now assign it a new level and add at that level */
    const unsigned tim_level = timer_get_skiplist_level(priv_timer[tim_thread].curr_skiplist_depth);
    if (tim_level == priv_timer[tim_thread].curr_skiplist_depth)
        priv_timer[tim_thread].curr_skiplist_depth++;

    lvl = tim_level;
    while (lvl > 0) {
        tim->sl_next[lvl]       = prev[lvl]->sl_next[lvl];
        prev[lvl]->sl_next[lvl] = tim;
        lvl--;
    }
    tim->sl_next[0]     = prev[0]->sl_next[0];
    prev[0]->sl_next[0] = tim;

    /* save the lowest list entry into the expire field of the dummy hdr
     * NOTE: this is not atomic on 32-bit*/
    priv_timer[tim_thread].pending_head.expire =
        priv_timer[tim_thread].pending_head.sl_next[0]->expire;
}

/*
 * del from list, lock if needed
 * timer must be in config state
 * timer must be in a list
 */
static void
timer_del(struct cne_timer *tim, union cne_timer_status prev_status, int local_is_locked)
{
    unsigned tid        = cne_id();
    unsigned prev_owner = prev_status.owner;
    int i;
    struct cne_timer *prev[MAX_SKIPLIST_DEPTH + 1] = {0};

    /* if timer needs is pending another core, we need to lock the
     * list; if it is on local core, we need to lock if we are not
     * called from cne_timer_manage() */
    if (prev_owner != tid || !local_is_locked)
        cne_spinlock_lock(&priv_timer[prev_owner].list_lock);

    /* save the lowest list entry into the expire field of the dummy hdr.
     * NOTE: this is not atomic on 32-bit */
    if (tim == priv_timer[prev_owner].pending_head.sl_next[0])
        priv_timer[prev_owner].pending_head.expire =
            ((tim->sl_next[0] == NULL) ? 0 : tim->sl_next[0]->expire);

    /* adjust pointers from previous entries to point past this */
    timer_get_prev_entries_for_node(tim, prev_owner, prev);
    for (i = priv_timer[prev_owner].curr_skiplist_depth - 1; i >= 0; i--) {
        if (prev[i]->sl_next[i] == tim)
            prev[i]->sl_next[i] = tim->sl_next[i];
    }

    /* in case we deleted last entry at a level, adjust down max level */
    for (i = priv_timer[prev_owner].curr_skiplist_depth - 1; i >= 0; i--)
        if (priv_timer[prev_owner].pending_head.sl_next[i] == NULL)
            priv_timer[prev_owner].curr_skiplist_depth--;
        else
            break;

    if (prev_owner != tid || !local_is_locked)
        cne_spinlock_unlock(&priv_timer[prev_owner].list_lock);
}

/* Reset and start the timer associated with the timer handle (private func) */
static int
__cne_timer_reset(struct cne_timer *tim, uint64_t expire, uint64_t period, unsigned tim_thread,
                  cne_timer_cb_t fct, void *arg, int local_is_locked)
{
    union cne_timer_status prev_status, status;
    int ret;
    unsigned tid = cne_id();

    /* round robin for tim_thread */
    if (tim_thread > (unsigned)cne_max_threads()) {
        tim_thread                  = cne_id();
        priv_timer[tid].prev_thread = tim_thread;
    }

    /* wait that the timer is in correct status before update,
     * and mark it as being configured */
    ret = timer_set_config_state(tim, &prev_status);
    if (ret < 0)
        return -1;

    __TIMER_STAT_ADD(reset, 1);
    if (prev_status.state == CNE_TIMER_RUNNING)
        priv_timer[tid].updated = 1;

    /* remove it from list */
    if (prev_status.state == CNE_TIMER_PENDING) {
        timer_del(tim, prev_status, local_is_locked);
        __TIMER_STAT_ADD(pending, -1);
    }

    tim->period = period;
    tim->expire = expire;
    tim->f      = fct;
    tim->arg    = arg;

    /* if timer needs to be scheduled on another core, we need to
     * lock the destination list; if it is on local core, we need to lock if
     * we are not called from cne_timer_manage()
     */
    if (tim_thread != tid || !local_is_locked)
        cne_spinlock_lock(&priv_timer[tim_thread].list_lock);

    __TIMER_STAT_ADD(pending, 1);
    timer_add(tim, tim_thread);

    /* update state: as we are in CONFIG state, only us can modify
     * the state so we don't need to use cmpset() here */
    cne_compiler_barrier();
    status.state    = CNE_TIMER_PENDING;
    status.owner    = (int16_t)tim_thread;
    tim->status.u32 = status.u32;

    if (tim_thread != tid || !local_is_locked)
        cne_spinlock_unlock(&priv_timer[tim_thread].list_lock);

    return 0;
}

/* Reset and start the timer associated with the timer handle tim */
int
cne_timer_reset(struct cne_timer *tim, uint64_t ticks, enum cne_timer_type type,
                unsigned tim_thread, cne_timer_cb_t fct, void *arg)
{
    uint64_t cur_time;
    uint64_t period;

    cur_time = cne_rdtsc();
    period   = (type == PERIODICAL) ? ticks : 0;

    return __cne_timer_reset(tim, cur_time + ticks, period, tim_thread, fct, arg, 0);
}

/* loop until cne_timer_reset() succeed */
void
cne_timer_reset_sync(struct cne_timer *tim, uint64_t ticks, enum cne_timer_type type,
                     unsigned tim_thread, cne_timer_cb_t fct, void *arg)
{
    while (cne_timer_reset(tim, ticks, type, tim_thread, fct, arg) != 0)
        cne_pause();
}

/* Stop the timer associated with the timer handle tim */
int
cne_timer_stop(struct cne_timer *tim)
{
    union cne_timer_status prev_status, status;
    unsigned tid = cne_id();
    int ret;

    if (!tim)
        return -1;

    /* wait that the timer is in correct status before update,
     * and mark it as being configured */
    ret = timer_set_config_state(tim, &prev_status);
    if (ret < 0)
        return -1;

    __TIMER_STAT_ADD(stop, 1);
    if (prev_status.state == CNE_TIMER_RUNNING)
        priv_timer[tid].updated = 1;

    /* remove it from list */
    if (prev_status.state == CNE_TIMER_PENDING) {
        timer_del(tim, prev_status, 0);
        __TIMER_STAT_ADD(pending, -1);
    }

    /* mark timer as stopped */
    cne_compiler_barrier();
    status.state    = CNE_TIMER_STOP;
    status.owner    = CNE_TIMER_NO_OWNER;
    tim->status.u32 = status.u32;

    return 0;
}

/* loop until cne_timer_stop() succeed */
void
cne_timer_stop_sync(struct cne_timer *tim)
{
    while (cne_timer_stop(tim) != 0)
        cne_pause();
}

/* Test the PENDING status of the timer handle tim */
int
cne_timer_pending(struct cne_timer *tim)
{
    return tim->status.state == CNE_TIMER_PENDING;
}

/* must be called periodically, run all timer that expired */
void
cne_timer_manage(void)
{
    union cne_timer_status status;
    struct cne_timer *tim, *next_tim;
    struct cne_timer *run_first_tim, **pprev;
    unsigned tid                                   = cne_id();
    struct cne_timer *prev[MAX_SKIPLIST_DEPTH + 1] = {0};
    uint64_t cur_time;
    int i, ret;

    __TIMER_STAT_ADD(manage, 1);
    /* optimize for the case where per-thread list is empty */
    if (priv_timer[tid].pending_head.sl_next[0] == NULL)
        return;
    cur_time = cne_rdtsc();

    /* on 64-bit the value cached in the pending_head.expired will be
     * updated atomically, so we can consult that for a quick check here
     * outside the lock */
    if (likely(priv_timer[tid].pending_head.expire > cur_time))
        return;

    /* browse ordered list, add expired timers in 'expired' list */
    cne_spinlock_lock(&priv_timer[tid].list_lock);

    /* if nothing to do just unlock and return */
    if (priv_timer[tid].pending_head.sl_next[0] == NULL ||
        priv_timer[tid].pending_head.sl_next[0]->expire > cur_time) {
        cne_spinlock_unlock(&priv_timer[tid].list_lock);
        return;
    }

    /* save start of list of expired timers */
    tim = priv_timer[tid].pending_head.sl_next[0];

    /* break the existing list at current time point */
    timer_get_prev_entries(cur_time, tid, prev);
    for (i = priv_timer[tid].curr_skiplist_depth - 1; i >= 0; i--) {
        if (prev[i] == &priv_timer[tid].pending_head)
            continue;
        priv_timer[tid].pending_head.sl_next[i] = prev[i]->sl_next[i];
        if (prev[i]->sl_next[i] == NULL)
            priv_timer[tid].curr_skiplist_depth--;
        prev[i]->sl_next[i] = NULL;
    }

    /* transition run-list from PENDING to RUNNING */
    run_first_tim = tim;
    pprev         = &run_first_tim;

    for (; tim != NULL; tim = next_tim) {
        next_tim = tim->sl_next[0];

        ret = timer_set_running_state(tim);
        if (likely(ret == 0)) {
            pprev = &tim->sl_next[0];
        } else {
            /* another core is trying to re-config this one,
             * remove it from local expired list
             */
            *pprev = next_tim;
        }
    }

    /* update the next to expire timer value */
    priv_timer[tid].pending_head.expire = (priv_timer[tid].pending_head.sl_next[0] == NULL)
                                              ? 0
                                              : priv_timer[tid].pending_head.sl_next[0]->expire;

    cne_spinlock_unlock(&priv_timer[tid].list_lock);

    /* now scan expired list and call callbacks */
    for (tim = run_first_tim; tim != NULL; tim = next_tim) {
        next_tim                    = tim->sl_next[0];
        priv_timer[tid].updated     = 0;
        priv_timer[tid].running_tim = tim;

        /* execute callback function with list unlocked */
        tim->f(tim, tim->arg);

        __TIMER_STAT_ADD(pending, -1);
        /* the timer was stopped or reloaded by the callback
         * function, we have nothing to do here */
        if (priv_timer[tid].updated == 1)
            continue;

        if (tim->period == 0) {
            /* remove from done list and mark timer as stopped */
            status.state = CNE_TIMER_STOP;
            status.owner = CNE_TIMER_NO_OWNER;
            cne_compiler_barrier();
            tim->status.u32 = status.u32;
        } else {
            /* keep it in list and mark timer as pending */
            cne_spinlock_lock(&priv_timer[tid].list_lock);
            status.state = CNE_TIMER_PENDING;
            __TIMER_STAT_ADD(pending, 1);
            status.owner = (int16_t)tid;
            cne_compiler_barrier();
            tim->status.u32 = status.u32;
            __cne_timer_reset(tim, tim->expire + tim->period, tim->period, tid, tim->f, tim->arg,
                              1);
            cne_spinlock_unlock(&priv_timer[tid].list_lock);
        }
    }
    priv_timer[tid].running_tim = NULL;
}

/* dump statistics about timers */
void
cne_timer_dump_stats(FILE *f)
{
    struct cne_timer_debug_stats sum;
    int max_threads = cne_max_threads();

    if (!f)
        f = stdout;

    memset(&sum, 0, sizeof(sum));
    for (int tid = 0; tid < max_threads; tid++) {
        sum.reset += priv_timer[tid].stats.reset;
        sum.stop += priv_timer[tid].stats.stop;
        sum.manage += priv_timer[tid].stats.manage;
        sum.pending += priv_timer[tid].stats.pending;
    }
    fprintf(f, "Timer statistics:\n");
    fprintf(f, "  reset = %" PRIu64 "\n", sum.reset);
    fprintf(f, "  stop = %" PRIu64 "\n", sum.stop);
    fprintf(f, "  manage = %" PRIu64 "\n", sum.manage);
    fprintf(f, "  pending = %" PRIu64 "\n", sum.pending);
}
