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
#ifndef _CTHREAD_INT_H
#define _CTHREAD_INT_H

#include <sys/queue.h>
#include <cne_per_thread.h>
#include <cne_spinlock.h>
#include <cne_timer.h>
#include <uid.h>
#include "cthread.h"
#include "ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cthread;
struct cthread_sched;
struct cthread_cond;
struct cthread_mutex;
struct cthread_key;

struct key_pool;
struct qnode;
struct qnode_pool;
struct cthread_sched;
struct cthread_tls;

#define BIT(x) (1ULL << (x))

#define POSIX_ERRNO(x) (x)

#define CTHREAD_NAME_SIZE 64

/* define some shorthand for current scheduler and current thread */
#define THIS_SCHED   CNE_PER_THREAD(this_sched)
#define THIS_CTHREAD CNE_PER_THREAD(this_sched)->current_cthread

/**
 * Definition of an scheduler struct
 */
struct cthread_sched {
    STAILQ_ENTRY(cthread_sched) next;           /**< Next pointer to next thread */
    struct cthread *current_cthread;            /**< running thread */
    cne_spinlock_recursive_t lock;              /**< Lock for scheduler access */
    int sched_id;                               /**< this sched ID */
    int run_flag;                               /**< sched shutdown */
    struct ctx ctx;                             /**< cpu context */
    uint64_t birth;                             /**< time created */
    u_id_t *uid_pool;                           /**< Unique ID pool for a scheduler */
    uint64_t nb_blocked_threads;                /**< blocked threads */
    STAILQ_HEAD(, cthread) threads;             /**< List of threads for this scheduler */
    CNE_ATOMIC(uint_least32_t) thread_count;    /**< Number of current active threads */
    struct cthread_queue *ready;                /**< local ready queue */
    struct cthread_queue *pready;               /**< peer ready queue */
    struct cthread_objcache *cthread_cache;     /**< free cthreads */
    struct cthread_objcache *stack_cache;       /**< free stacks */
    struct cthread_objcache *per_cthread_cache; /**< free per cthread */
    struct cthread_objcache *tls_cache;         /**< free TLS */
    struct cthread_objcache *cond_cache;        /**< free cond vars */
    struct cthread_objcache *sema_cache;        /**< free semaphores */
    struct cthread_objcache *barr_cache;        /**< free barriers */
    struct cthread_objcache *mutex_cache;       /**< free mutexes */
    struct cthread_objcache *once_cache;        /**< free once structures */
    struct qnode_pool *qnode_pool;              /**< pool of queue nodes */
    struct key_pool *key_pool;                  /**< pool of free TLS keys */
    size_t stack_size;                          /**< Size of the stack per thread */
} __cne_cache_aligned;

CNE_DECLARE_PER_THREAD(struct cthread_sched *, this_sched);

/**
 * State for a cthread
 */
enum cthread_st {
    CT_STATE_INIT,          /* initial state */
    CT_STATE_READY,         /* cthread is ready to run */
    CT_STATE_EXITED,        /* cthread has exited and needs cleanup */
    CT_STATE_DETACH,        /* cthread frees on exit*/
    CT_STATE_CANCELLED,     /* cthread has been cancelled */
    CT_STATE_COND_WAITING,  /* cthread is blocked on condition var */
    CT_STATE_MUTEX_WAITING, /* cthread is blocked on mutex */
    CT_STATE_EXPIRED,       /* cthread timeout has expired  */
    CT_STATE_SLEEPING,      /* cthread is sleeping */
    NUM_STATES
};

#define CLEAR_STATE_BITS \
    (BIT(CT_STATE_COND_WAITING) | BIT(CT_STATE_MUTEX_WAITING) | BIT(CT_STATE_SLEEPING))

// clang-format off
#define CTHREAD_STATES  {   \
    "INIT",                 \
    "READY",                \
    "EXITED",               \
    "DETACH",               \
    "CANCELLED",            \
    "COND-WAITING",         \
    "MUTEX-WAITING",        \
    "EXPIRED",              \
    "SLEEPING",             \
    NULL                    \
    }
// clang-format on

/**
 * cthread sub states for exit/join
 */
enum join_st {
    CT_JOIN_INITIAL,      /* initial state */
    CT_JOIN_EXITING,      /* thread is exiting */
    CT_JOIN_THREAD_SET,   /* joining thread has been set */
    CT_JOIN_EXIT_VAL_SET, /* exiting thread has set ret val */
    CT_JOIN_EXIT_VAL_READ /* joining thread has collected ret val */
};

/**
 * defnition of an cthread stack object
 */
struct cthread_stack {
    struct cthread_sched *sched;
    size_t stack_size;
    uint8_t stack_start[0];
} __cne_cache_aligned;

/**
 * Definition of an cthread
 */
struct cthread {
    struct ctx ctx;                         /**< cpu context */
    int cthread_id;                         /**< thread id value */
    uint64_t state;                         /**< current cthread state */
    void *private_data;                     /**< Thread private data set by thread */
    void *stack;                            /**< ptr to actual stack */
    size_t stack_size;                      /**< current stack_size */
    size_t last_stack_size;                 /**< last yield stack_size */
    cthread_func_t fun;                     /**< func ctx is running */
    void *arg;                              /**< func args passed to func */
    void *per_cthread_data;                 /**< per cthread user data */
    cthread_exit_func exit_handler;         /**< called when thread exits */
    uint64_t birth;                         /**< time cthread was born */
    struct cthread_queue *pending_wr_queue; /**< deferred  queue to write */
    struct cthread *dt_join;                /**< cthread to join on */
    CNE_ATOMIC(uint_least64_t) join;        /**< state for joining */
    void **dt_exit_ptr;                     /**< exit ptr for cthread_join */
    struct cthread_sched *sched;            /**< thread was created here*/
    struct queue_node *qnode;               /**< node when in a queue */
    struct cne_timer tim;                   /**< sleep timer */
    struct cthread_tls *tls;                /**< keys in use by the thread */
    struct cthread_stack *stack_container;  /**< stack container pointer */
    struct cthread_cond *cond;              /**< Condition variable ct is waiting on */
    struct cthread_sema *sema;              /**< Semaphore ct is waiting on */
    char name[CTHREAD_NAME_SIZE];           /**< thread name */
    STAILQ_ENTRY(cthread) next;             /**< Next thread in list */
} __cne_cache_aligned;

/* Internal functions */
/**
 * Cause the current cthread to be suspended.
 *
 * @return
 *    None.
 */
void _cthread_wait(void);

/**
 * Cause the current cthread to be suspended waiting on mutex.
 *
 * @return
 *    None.
 */
void _cthread_mutex_wait(void);

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_INT_H */
