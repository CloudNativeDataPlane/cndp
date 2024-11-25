/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
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

#ifndef _CTHREAD_SCHED_H_
#define _CTHREAD_SCHED_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * insert an cthread into a queue
 *
 * @param sched
 *   The scheduler pointer
 * @param ct
 *   The cthread pointer to insert
 */
static inline void
_ready_queue_insert(struct cthread_sched *sched, struct cthread *ct)
{
    if (sched == THIS_SCHED)
        _cthread_queue_insert_sp((THIS_SCHED)->ready, ct);
    else
        _cthread_queue_insert_mp(sched->pready, ct);
}

/**
 * remove an cthread from a queue
 *
 * @param q
 *   The cthread queue pointer
 * @return
 *   The cthread pointer or NULL on error
 */
static inline struct cthread *
_ready_queue_remove(struct cthread_queue *q)
{
    return _cthread_queue_remove(q);
}

/**
 * Return true if the ready queue is empty
 *
 * @param q
 *   The cthread queue pointer
 * @return
 *   true if empty or false if not empty
 */
static inline int
_ready_queue_empty(struct cthread_queue *q)
{
    return _cthread_queue_empty(q);
}

/**
 * Return the current ticks of a scheduler
 *
 */
static inline uint64_t
_sched_now(void)
{
    uint64_t now = cne_rdtsc();

    if (now > (THIS_SCHED)->birth)
        return now - (THIS_SCHED)->birth;

    if (now < (THIS_SCHED)->birth)
        return (THIS_SCHED)->birth - now;

    /* never return 0 because this means sleep forever */
    return 1;
}

static inline void __attribute__((always_inline))
_affinitize(void)
{
    struct cthread *ct = THIS_CTHREAD;

    cthread_switch(&(THIS_SCHED)->ctx, &ct->ctx);
}

static inline void __attribute__((always_inline))
_suspend(void)
{
    struct cthread *ct = THIS_CTHREAD;

    (THIS_SCHED)->nb_blocked_threads++;
    cthread_switch(&(THIS_SCHED)->ctx, &ct->ctx);
    (THIS_SCHED)->nb_blocked_threads--;
}

static inline void __attribute__((always_inline))
_reschedule(void)
{
    struct cthread *ct = THIS_CTHREAD;

    _ready_queue_insert(THIS_SCHED, ct);
    cthread_switch(&(THIS_SCHED)->ctx, &ct->ctx);
}

static inline int
is_sched_running(void)
{
    struct cthread_sched *sched = THIS_SCHED;

    return sched->run_flag;
}

void _sched_timer_cb(struct cne_timer *tim, void *arg);
void _sched_shutdown(void *arg);

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_SCHED_H_ */
