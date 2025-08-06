/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

/*
 * Some portions of this software is derived from the producer
 * consumer queues described by Dmitry Vyukov and published  here
 * http://www.1024cores.net
 *
 * Copyright (c) 2010-2011 Dmitry Vyukov. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY DMITRY VYUKOV "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DMITRY VYUKOV OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of Dmitry Vyukov.
 */

#ifndef _CTHREAD_POOL_H_
#define _CTHREAD_POOL_H_

#include <cne_per_thread.h>
#include <cne_log.h>

#include "cthread_int.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file implements pool of queue nodes used by the queue implemented
 * in cthread_queue.h.
 *
 * The pool is an intrusive lock free MPSC queue.
 *
 * The pool is created empty and populated lazily, i.e. on first attempt to
 * allocate a the pool.
 *
 * Whenever the pool is empty more nodes are added to the pool
 * The number of nodes preallocated in this way is a parameter of
 * _qnode_pool_create. Freeing an object returns it to the pool.
 *
 * Each cthread scheduler maintains its own pool of nodes. D-threads must always
 * allocate from this local pool ( because it is a single consumer queue ).
 * D-threads can free nodes to any pool (because it is a multi producer queue)
 * This enables threads that have affined to a different scheduler to free
 * nodes safely.
 */

struct qnode;
struct qnode_cache;

/*
 * define intermediate node
 */
struct qnode {
    struct qnode *next;      /**< Next pointer for the pool */
    void *data;              /**< data pointer for the pool */
    struct qnode_pool *pool; /**< pool structure pointer */
} __cne_cache_aligned;

/*
 * a pool structure
 */
struct qnode_pool {
    struct qnode *head;                     /**< Head of pool list */
    struct qnode *stub;                     /**< Stub pointer for the list */
    struct qnode *fast_alloc;               /**< Fast allocation pointer */
    struct qnode *tail __cne_cache_aligned; /**< Tail pointer in the pool */
    int pre_alloc;                          /**< The pre-allocation count */
    char name[CTHREAD_NAME_SIZE];           /**< Name of the pool */
} __cne_cache_aligned;

/**
 * Create a pool of qnodes
 *
 * @param name
 *   The name of the pool of nodes.
 * @param prealloc_size
 *   Number to preallocate
 * @return
 *   NULL on error or pointer to qnode_pool
 */
static inline struct qnode_pool *
_qnode_pool_create(const char *name, int prealloc_size)
{
    struct qnode_pool *p = calloc(1, sizeof(struct qnode_pool));

    CNE_ASSERT(p);
    if (p == NULL)
        return NULL;

    p->stub = calloc(1, sizeof(struct qnode));

    CNE_ASSERT(p->stub);
    if (p->stub == NULL) {
        free(p);
        return NULL;
    }

    if (name != NULL)
        strlcpy(p->name, name, sizeof(p->name));
    p->name[sizeof(p->name) - 1] = 0;

    p->stub->pool = p;
    p->stub->next = NULL;
    p->tail       = p->stub;
    p->head       = p->stub;
    p->pre_alloc  = prealloc_size;

    return p;
}

/**
 * Insert a node into the pool
 *
 * @param p
 *   The qnode_pool pointer
 * @param n
 *   The qnode to insert in to pool
 */
static inline void __attribute__((always_inline))
_qnode_pool_insert(struct qnode_pool *p, struct qnode *n)
{
    n->next            = NULL;
    struct qnode *prev = n;
    /* We insert at the head */
    prev = (struct qnode *)__sync_lock_test_and_set((uint64_t *)&p->head, (uint64_t)prev);
    /* there is a window of inconsistency until prev next is set */
    /* which is why remove must retry */
    prev->next = (n);
}

/**
 * Remove a node from the pool
 *
 * There is a race with _qnode_pool_insert() whereby the queue could appear
 * empty during a concurrent insert, this is handled by retrying
 *
 * The queue uses a stub node, which must be swung as the queue becomes
 * empty, this requires an insert of the stub, which means that removing the
 * last item from the queue incurs the penalty of an atomic exchange. Since the
 * pool is maintained with a bulk pre-allocation the cost of this is amortised.
 *
 * @param p
 *   The qnode_pool pointer
 * @return
 *   NULL on error or qnode pointer
 */
static inline struct qnode *__attribute__((always_inline))
_pool_remove(struct qnode_pool *p)
{
    struct qnode *head;
    struct qnode *tail = p->tail;
    struct qnode *next = tail->next;

    /* we remove from the tail */
    if (tail == p->stub) {
        if (next == NULL)
            return NULL;
        /* advance the tail */
        p->tail = next;
        tail    = next;
        next    = next->next;
    }
    if (likely(next != NULL)) {
        p->tail = next;
        return tail;
    }

    head = p->head;
    if (tail == head)
        return NULL;

    /* swing stub node */
    _qnode_pool_insert(p, p->stub);

    next = tail->next;
    if (next) {
        p->tail = next;
        return tail;
    }
    return NULL;
}

/**
 * This adds a retry to the _pool_remove function
 * defined above
 *
 * @param p
 *   The qnode_pool pointer
 * @return
 *   The qnode removed from queue or NULL on error
 */
static inline struct qnode *__attribute__((always_inline))
_qnode_pool_remove(struct qnode_pool *p)
{
    struct qnode *n;

    do {
        n = _pool_remove(p);
        if (likely(n != NULL))
            return n;

        cne_compiler_barrier();
    } while ((p->head != p->tail) && (p->tail != p->stub));
    return NULL;
}

/*
 * Allocate a node from the pool
 * If the pool is empty add mode nodes
 */
static inline struct qnode *__attribute__((always_inline))
_qnode_alloc(void)
{
    struct qnode_pool *p = (THIS_SCHED)->qnode_pool;
    int prealloc_size    = p->pre_alloc;
    struct qnode *n;
    int i;

    if (likely(p->fast_alloc != NULL)) {
        n             = p->fast_alloc;
        p->fast_alloc = NULL;
        return n;
    }

    n = _qnode_pool_remove(p);

    if (unlikely(n == NULL)) {
        for (i = 0; i < prealloc_size; i++) {
            n = calloc(1, sizeof(struct qnode));
            if (n == NULL)
                return NULL;

            n->pool = p;
            _qnode_pool_insert(p, n);
        }
        n = _qnode_pool_remove(p);
    }

    return n;
}

/*
 * free a queue node to the per scheduler pool from which it came
 */
static inline void __attribute__((always_inline))
_qnode_free(struct qnode *n)
{
    struct qnode_pool *p = n->pool;

    if (unlikely(p->fast_alloc != NULL) || unlikely(n->pool != (THIS_SCHED)->qnode_pool)) {
        _qnode_pool_insert(p, n);
        return;
    }
    p->fast_alloc = n;
}

/*
 * Destroy an qnode pool
 * queue must be empty when this is called
 */
static inline int
_qnode_pool_destroy(struct qnode_pool *p)
{
    free(p->stub);
    free(p);
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_POOL_H_ */
