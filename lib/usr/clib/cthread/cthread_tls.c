/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <execinfo.h>
#include <sched.h>

#include <cne_log.h>
#include <cne_ring.h>

#include "ctx.h"
#include <cthread.h>
#include "cthread_tls.h"
#include "cthread_queue.h"
#include "cthread_objcache.h"
#include "cthread_sched.h"

static struct cne_ring *key_pool;
static atomic_uint_least64_t key_pool_init;

/* needed to cause section start and end to be defined */
CNE_DEFINE_PER_CTHREAD(void *, dummy);

static struct cthread_key key_table[CTHREAD_MAX_KEYS];

void cthread_tls_ctor(void) __attribute__((constructor(103)));

void
cthread_tls_ctor(void)
{
    key_pool      = NULL;
    key_pool_init = 0;
}

/*
 * Initialize a pool of keys
 * These are unique tokens that can be obtained by threads
 * calling cthread_key_create()
 */
void
_cthread_key_pool_init(void)
{
    static struct cne_ring *pool;
    struct cthread_key *new_key;
    char name[CTHREAD_NAME_SIZE];
    uint64_t c = 0;

    bzero(key_table, sizeof(key_table));

    /* only one thread should do this */
    if (atomic_compare_exchange_strong(&key_pool_init, &c, 1)) {

        snprintf(name, sizeof(name), "key_pool_%d", getpid());
        pool = cne_ring_create(name, sizeof(struct cthread_key), CTHREAD_MAX_KEYS, 0);
        if (!pool)
            CNE_RET("Unable to allocate ring for key pool\n");

        for (int i = 1; i < CTHREAD_MAX_KEYS; i++) {
            new_key = &key_table[i];
            cne_ring_enqueue((struct cne_ring *)pool, (void *)new_key);
        }
        key_pool = pool;
    }
    /* other threads wait here till done */
    while (key_pool == NULL) {
        cne_compiler_barrier();
        sched_yield();
    }
}

/*
 * Create a key
 * this means getting a key from the the pool
 */
int
cthread_key_create(unsigned int *key, tls_destructor_func destructor)
{
    if (key == NULL)
        return POSIX_ERRNO(EINVAL);

    struct cthread_key *new_key;

    if (cne_ring_dequeue((struct cne_ring *)key_pool, (void **)&new_key) == 0) {
        new_key->destructor = destructor;
        *key                = (new_key - key_table);

        return 0;
    }
    return POSIX_ERRNO(EAGAIN);
}

/*
 * Delete a key
 */
int
cthread_key_delete(unsigned int k)
{
    struct cthread_key *key;

    key = (struct cthread_key *)&key_table[k];

    if (k > CTHREAD_MAX_KEYS)
        return POSIX_ERRNO(EINVAL);

    key->destructor = NULL;
    cne_ring_enqueue((struct cne_ring *)key_pool, (void *)key);
    return 0;
}

/*
 * Break association for all keys in use by this thread
 * invoke the destructor if available.
 * Since a destructor can create keys we could enter an infinite loop
 * therefore we give up after CTHREAD_DESTRUCTOR_ITERATIONS
 * the behavior is modelled on pthread
 */
void
_cthread_tls_destroy(struct cthread *ct)
{
    int i, k;
    int nb_keys;
    void *data;

    for (i = 0; i < CTHREAD_DESTRUCTOR_ITERATIONS; i++) {
        for (k = 1; k < CTHREAD_MAX_KEYS; k++) {
            /* no keys in use ? */
            nb_keys = ct->tls->nb_keys_inuse;
            if (nb_keys == 0)
                return;

            /* this key not in use ? */
            if (ct->tls->data[k] == NULL)
                continue;

            /* remove this key */
            data                   = ct->tls->data[k];
            ct->tls->data[k]       = NULL;
            ct->tls->nb_keys_inuse = nb_keys - 1;

            /* invoke destructor */
            if (key_table[k].destructor != NULL)
                key_table[k].destructor(data);
        }
    }
}

/*
 * Return the pointer associated with a key
 * If the key is no longer valid return NULL
 */
void *
cthread_getspecific(unsigned int k)
{
    if (k >= CTHREAD_MAX_KEYS)
        return NULL;

    return THIS_CTHREAD->tls->data[k];
}

/*
 * Set a value against a key
 * If the key is no longer valid return an error
 * when storing value
 */
int
cthread_setspecific(unsigned int k, const void *data)
{
    if (k >= CTHREAD_MAX_KEYS)
        return POSIX_ERRNO(EINVAL);

    int n = THIS_CTHREAD->tls->nb_keys_inuse;

    /* discard const qualifier */
    char *p = (char *)(uintptr_t)data;

    if (data != NULL) {
        if (THIS_CTHREAD->tls->data[k] == NULL)
            THIS_CTHREAD->tls->nb_keys_inuse = n + 1;
    }

    THIS_CTHREAD->tls->data[k] = (void *)p;
    return 0;
}

/*
 * Allocate data for TLS cache
 */
int
_cthread_tls_alloc(struct cthread *ct)
{
    struct cthread_tls *tls = NULL;
    void *per_cthread_data;
    bool needs_per_thread_data =
        CNE_PER_CTHREAD_SECTION_SIZE && (sizeof(void *) < (uint64_t)CNE_PER_CTHREAD_SECTION_SIZE);

    if (needs_per_thread_data) {
        /* allocate data for TLS variables using CNE_PER_CTHREAD macros */
        per_cthread_data = _cthread_objcache_alloc((THIS_SCHED)->per_cthread_cache);
        if (per_cthread_data == NULL)
            goto err;
    } else
        per_cthread_data = NULL;

    tls = _cthread_objcache_alloc((THIS_SCHED)->tls_cache);
    CNE_ASSERT(tls != NULL);
    if (tls == NULL)
        goto err;

    tls->sched = (THIS_SCHED);

    ct->tls              = tls;
    ct->per_cthread_data = per_cthread_data;

    return 0;
err:
    if (needs_per_thread_data && per_cthread_data != NULL)
        _cthread_objcache_free((THIS_SCHED)->per_cthread_cache, per_cthread_data);
    _cthread_objcache_free((THIS_SCHED)->tls_cache, tls);

    return -1;
}
