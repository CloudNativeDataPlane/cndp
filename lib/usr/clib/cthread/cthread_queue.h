/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

/*
 * Some portions of this software is derived from the producer
 * consumer queues described by Dmitry Vyukov and published  here
 * http://www.1024cores.net
 *
 * Copyright (c) 2010-2011 Dmitry Vyukov. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
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

#ifndef _CTHREAD_QUEUE_H_
#define _CTHREAD_QUEUE_H_

#include <string.h>

#include <cne_prefetch.h>
#include <cne_per_thread.h>

#include "cthread_int.h"
#include "cthread.h"
#include "cthread_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file implements an unbounded FIFO queue based on a lock free
 * linked list.
 *
 * The queue is non-intrusive in that it uses intermediate nodes, and does
 * not require these nodes to be inserted into the object being placed
 * in the queue.
 *
 * This is slightly more efficient than the very similar queue in cthread_pool
 * in that it does not have to swing a stub node as the queue becomes empty.
 *
 * The queue access functions allocate and free intermediate node
 * transparently from/to a per scheduler pool ( see cthread_pool.h ).
 *
 * The queue provides both MPSC and SPSC insert methods
 */

/*
 * define a queue of cthread nodes
 */
struct cthread_queue {
    struct qnode *head;                     /**< Head of the queue of threads */
    struct qnode *tail __cne_cache_aligned; /**< Last thread in queue */
    char name[CTHREAD_NAME_SIZE];           /**< Name of queue */
} __cne_cache_aligned;

/**
 * Create a thread queue
 *
 * @param name
 *   The name of the thread queue
 * @return
 *   NULL on error or pointer to the thread queue
 */
static inline struct cthread_queue *
_cthread_queue_create(const char *name)
{
    struct qnode *stub;
    struct cthread_queue *new_queue;

    new_queue = calloc(1, sizeof(struct cthread_queue));
    if (!new_queue)
        return NULL;

    /* allocated stub node */
    stub = _qnode_alloc();
    CNE_ASSERT(stub);
    if (stub == NULL) {
        free(new_queue);
        return NULL;
    }

    strlcpy(new_queue->name, (name) ? name : "Unknown", sizeof(new_queue->name));

    /* initialize queue as empty */
    stub->next      = NULL;
    new_queue->head = stub;
    new_queue->tail = stub;

    return new_queue;
}

/**
 * Return true if the queue is empty
 *
 * @param q
 *   The queue pointer
 * @return
 *   true is empty or false if not empty
 */
static __attribute__((always_inline)) inline int
_cthread_queue_empty(struct cthread_queue *q)
{
    return q->tail == q->head;
}

/**
 * Destroy a queue fail if queue is not empty
 *
 * @param q
 *   The queue pointer
 * @return
 *   0 on success or -1 on error
 */
static inline int
_cthread_queue_destroy(struct cthread_queue *q)
{
    if (!q)
        return 0;

    if (!_cthread_queue_empty(q))
        return -1;

    _qnode_free(q->head);
    free(q);
    return 0;
}

CNE_DECLARE_PER_THREAD(struct cthread_sched *, this_sched);

/**
 * Insert a node into a queue this implementation is multi producer safe
 *
 * @param q
 *   The queue pointer
 * @param data
 *   Pointer to data to insert in queue
 * @return
 *   NULL on error or pointer to qnode
 */
static __attribute__((always_inline)) inline struct qnode *
_cthread_queue_insert_mp(struct cthread_queue *q, void *data)
{
    struct qnode *prev;
    struct qnode *n = _qnode_alloc();

    if (!n)
        return NULL;

    /* set object in node */
    n->data = data;
    n->next = NULL;

    /* this is an MPSC method, perform a locked update */
    prev = n;
    prev = (struct qnode *)__sync_lock_test_and_set((uint64_t *)&(q)->head, (uint64_t)prev);
    /* there is a window of inconsistency until prev next is set,
     * which is why remove must retry
     */
    prev->next = n;

    return n;
}

/**
 * Insert an node into a queue in single producer mode
 * this implementation is NOT mult producer safe
 *
 * @param q
 *   The queue pointer
 * @param data
 *   Pointer to data to insert in queue
 * @return
 *   NULL on error or pointer to qnode
 */
static __attribute__((always_inline)) inline struct qnode *
_cthread_queue_insert_sp(struct cthread_queue *q, void *data)
{
    /* allocate a queue node */
    struct qnode *prev;
    struct qnode *n = _qnode_alloc();

    if (n == NULL)
        return NULL;

    /* set data in node */
    n->data = data;
    n->next = NULL;

    /* this is an SPSC method, no need for locked exchange operation */
    prev       = q->head;
    prev->next = q->head = n;

    return n;
}

/**
 * Remove a node from a queue
 *
 * @param q
 *   The queue pointer
 * @return
 *   NULL on error or pointer to qnode
 */
static __attribute__((always_inline)) inline void *
_cthread_queue_poll(struct cthread_queue *q)
{
    void *data         = NULL;
    struct qnode *tail = q->tail;
    struct qnode *next = (struct qnode *)tail->next;

    /*
     * There is a small window of inconsistency between producer and
     * consumer whereby the queue may appear empty if consumer and
     * producer access it at the same time.
     * The consumer must handle this by retrying
     */

    if (likely(next != NULL)) {
        q->tail    = next;
        tail->data = next->data;
        data       = tail->data;

        /* free the node */
        _qnode_free(tail);

        return data;
    }
    return NULL;
}

/**
 * Remove a node from a queue
 *
 * @param q
 *   The queue pointer
 * @return
 *   NULL on error or pointer to qnode
 */
static __attribute__((always_inline)) inline void *
_cthread_queue_remove(struct cthread_queue *q)
{
    void *data = NULL;

    /*
     * There is a small window of inconsistency between producer and
     * consumer whereby the queue may appear empty if consumer and
     * producer access it at the same time. We handle this by retrying
     */
    do {
        data = _cthread_queue_poll(q);

        if (likely(data != NULL))
            return data;
        cne_compiler_barrier();
    } while (unlikely(!_cthread_queue_empty(q)));
    return NULL;
}

/**
 * Remove a given node from a queue, very slow :-(
 *
 * @param q
 *   The queue pointer
 * @param given
 *   The given pointer to remove
 * @return
 *   NULL on error or pointer to qnode
 */
static __attribute__((always_inline)) inline void *
_cthread_queue_remove_given(struct cthread_queue *q, void *given)
{
    void *data = NULL;
    struct cthread_queue *saved;

    saved = _cthread_queue_create(NULL);
    if (saved == NULL)
        return NULL;

    /*
     * There is a small window of inconsistency between producer and
     * consumer whereby the queue may appear empty if consumer and
     * producer access it at the same time. We handle this by retrying
     */
    do {
        data = _cthread_queue_poll(q);

        if (likely(data != NULL)) {
            if (data == given)
                break;
            _cthread_queue_insert_sp(saved, data);
            data = NULL;
        }
        cne_compiler_barrier();
    } while (unlikely(!_cthread_queue_empty(q)));

    while (!_cthread_queue_empty(saved)) {
        given = _cthread_queue_remove(saved);
        _cthread_queue_insert_mp(q, given);
    }
    _cthread_queue_destroy(saved);

    return data;
}

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_QUEUE_H_ */
