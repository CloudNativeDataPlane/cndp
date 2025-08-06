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

#ifndef _CTHREAD_H_
#define _CTHREAD_H_

#include <cne_atomic.h>
#include <bsd/string.h>

#include <cne_per_thread.h>
#include <cne_system.h>
#include <cne_timer.h>

#include <cthread_api.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cthread;
struct cthread_sched;

/* function to be called when a context function returns */
typedef void (*cthread_exit_func)(struct cthread *);

void _cthread_exit_handler(struct cthread *ct);

void _cthread_sched_busy_sleep(struct cthread *ct, uint64_t nsecs);

int _cthread_desched_sleep(struct cthread *ct);

void _cthread_free(struct cthread *ct);

struct cthread_stack *_stack_alloc(void);

void _stack_free(struct cthread_stack *s);

void cthread_list(FILE *f, int tid);

int cthread_id_get(struct cthread *c);

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_H_ */
