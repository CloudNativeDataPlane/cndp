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

#ifndef _CTHREAD_BARRIER_H_
#define _CTHREAD_BARRIER_H_

#include "cthread_mutex.h"
#include "cthread_cond.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BARRIER_NAME_SIZE 32

struct cthread_barrier {
    struct cthread_sched *sched;          /**< this scheduler pointer */
    struct cthread_mutex *mutex;          /**< Mutex to use for locking the barrier */
    struct cthread_cond *cv;              /**< The condition variable */
    int64_t cycle;                        /**< Current cycle counter */
    CNE_ATOMIC(uint_fast32_t) count;      /**< Number of times to wait on barrier */
    CNE_ATOMIC(uint_fast32_t) waiters;    /**< Number of current waiters on barrier */
    CNE_ATOMIC(uint_fast32_t) refcount;   /**< Reference counter for the barrier */
    CNE_ATOMIC(uint_fast32_t) destroying; /**< The barrier is being destroyed */
    char name[MAX_BARRIER_NAME_SIZE];     /**< Name of the barrier */
} __cne_cache_aligned;

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_BARRIERS_H_ */
