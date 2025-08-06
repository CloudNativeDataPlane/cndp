/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2025 Intel Corporation
 */

#include <string.h>              // for memset
#include <cne.h>                 // for cne_max_threads, cne_id, cne_unregister
#include <pthread.h>             // for pthread_self, pthread_barrier_wait, pthr...
#include <sched.h>               // for cpu_set_t, CPU_SET, CPU_ZERO
#include <stdlib.h>              // for calloc, exit, free
#include <unistd.h>              // for usleep, gettid
#include <bsd/string.h>          // for strlcpy
#include <cne_spinlock.h>        // for cne_spinlock_unlock, cne_spinlock_lock
#include <cne_log.h>             // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_NULL_RET

#include "thread_private.h"        // for thd_state_t, thd_params, THREAD_MAGIC_ID
#include "cne_thread.h"
#include "cne_common.h"        // for CNE_INIT_PRIO, CNE_PRIORITY_THREAD
#include "uid.h"               // for UID_INITIAL_NAME
#include "cne_stdio.h"         // for cne_printf

thd_state_t *__thd;
static cne_spinlock_t thd_lock;

/* get the pointer of thread state through thread id. */
thd_t
thread_get(int tidx)
{
    thd_state_t *t;

    if (tidx < 0 || tidx >= cne_max_threads())
        tidx = cne_id();

    t = &__thd[tidx];

    if (t->magic_id != THREAD_MAGIC_ID)
        return NULL;

    return t;
}

const char *
thread_name(int tidx)
{
    thd_state_t *t;

    if (tidx < 0 || tidx >= cne_max_threads()) {
        tidx = cne_id();
        if (tidx < 0)
            return NULL;
    }

    t = &__thd[tidx];

    if (t->magic_id != THREAD_MAGIC_ID)
        return NULL;

    return t->name;
}

/* request specific thread stop running. */
int
thread_stop_running(int tidx)
{
    thd_state_t *t = thread_get(tidx);

    if (!t)
        return -1;

    t->running = 0;

    return 0;
}

/* return specific thread running status. */
int
thread_running(int tidx)
{
    thd_state_t *t = thread_get(tidx);

    if (!t)
        return -1;

    return t->running;
}

/* thread subsystem initialization. */
static void *
__thread_init(void *arg)
{
    struct thd_params *params = arg;
    int tidx;

    pthread_detach(pthread_self());

    thd_func_t start_routine = params->start_routine;
    void *routine_arg        = params->arg;

    cne_spinlock_lock(&thd_lock);
    tidx = cne_register(params->name);
    if (tidx < 0) {
        cne_spinlock_unlock(&thd_lock);
        return NULL;
    }
    cne_spinlock_unlock(&thd_lock);

    if (thread_register(params->name, (uintptr_t)pthread_self()) < 0) {
        cne_spinlock_lock(&thd_lock);
        cne_unregister(tidx);
        cne_spinlock_unlock(&thd_lock);
        return NULL;
    }
    params->tidx = tidx; /* Return the tidx index value */

    if (pthread_setname_np(pthread_self(), params->name))
        CNE_NULL_RET("Failed to set thread name\n");

    if (pthread_barrier_wait(&params->barrier) > 0)
        CNE_NULL_RET("Failed to wait for barrier\n");

    /* Launch the user defined thread if our thread index is valid */
    start_routine(routine_arg);

    thread_stop_running(tidx);
    thread_unregister(tidx);

    return NULL;
}

/* create thread. */
int
thread_create(const char *name, thd_func_t func, void *arg)
{
    struct thd_params *params;
    pthread_t pid = 0;
    int ret       = -1;

    params = calloc(1, sizeof(*params));
    if (!params)
        CNE_ERR_RET("Allocation of struct thd_params failed\n");

    /* Setup the params for the user thread */
    params->start_routine = func;
    params->arg           = arg;

    strlcpy(params->name, (char *)(uintptr_t)name, sizeof(params->name));

    /* Setup a barrier to wait for spawned thread to be initialized. */
    if (pthread_barrier_init(&params->barrier, NULL, 2))
        CNE_ERR_GOTO(leave, "Failed to initialize barrier\n");

    ret = pthread_create(&pid, NULL, __thread_init, (void *)params);
    if (ret == 0) {
        /* Wait for thread to initialize */
        if (pthread_barrier_wait(&params->barrier) > 0)
            CNE_ERR_GOTO(error, "Failed to wait on barrier\n");

        ret = params->tidx;
    }

error:
    if (pthread_barrier_destroy(&params->barrier))
        CNE_ERR("Failed to destroy barrier\n");
leave:
    free(params);

    return ret;
}

int
thread_register(const char *name, uint64_t pid)
{
    thd_state_t *s = NULL;
    int tidx;

    cne_spinlock_lock(&thd_lock);
    tidx = cne_id();

    if (tidx < 0)
        goto leave;

    s = &__thd[tidx];

    if (s->magic_id == THREAD_MAGIC_ID)
        goto leave;

    snprintf(s->name, sizeof(s->name), "%s", name);

    s->magic_id = THREAD_MAGIC_ID;
    s->pid      = (uintptr_t)pid;
    s->running  = 1;

    cne_spinlock_unlock(&thd_lock);
    return 0;

leave:
    cne_spinlock_unlock(&thd_lock);
    return -1;
}

int
thread_unregister(int tidx)
{
    cne_spinlock_lock(&thd_lock);

    if (tidx < 0)
        tidx = cne_id();

    if (tidx >= 0) {
        thd_state_t *s = &__thd[tidx];

        if (s->magic_id != THREAD_MAGIC_ID)
            goto leave;

        cne_unregister(tidx);

        memset(s, 0, sizeof(struct thd_state));

        cne_spinlock_unlock(&thd_lock);
        return 0;
    }

leave:
    cne_spinlock_unlock(&thd_lock);
    return -1;
}

int
thread_wait(int tid, unsigned int checks, unsigned int usec)
{
    if (usec == 0)
        usec = THREAD_DEFAULT_TIMEOUT;

    for (;;) {
        uint16_t running;

        running        = 0;
        thd_state_t *s = &__thd[tid];

        if (s->magic_id == THREAD_MAGIC_ID)
            running += s->running;

        if (running == 0)
            break;

        if (checks && (--checks == 0))
            return -1;

        if (usec)
            usleep(usec);
    }
    return 0;
}

int
thread_wait_all(unsigned int checks, unsigned int usec, int skip)
{
    if (usec == 0)
        usec = THREAD_DEFAULT_TIMEOUT;

    for (;;) {
        uint16_t running;

        running = 0;
        for (int tidx = (skip) ? 1 : 0; tidx < cne_max_threads(); tidx++) {
            thd_state_t *s = &__thd[tidx];

            if (s->magic_id == THREAD_MAGIC_ID)
                running += s->running;
        }
        if (running == 0)
            break;

        if (checks && (--checks == 0))
            return -1;

        if (usec)
            usleep(usec);
    }
    return 0;
}

int
thread_set_private(int tidx, void *priv_)
{
    if (tidx >= 0 && tidx < cne_max_threads()) {
        __thd[tidx].priv_ = priv_;
        return 0;
    }
    return -1;
}

void *
thread_get_private(int tidx)
{
    if (tidx >= 0 && tidx < cne_max_threads())
        return __thd[tidx].priv_;

    return NULL;
}

int
thread_set_affinity(int cpu)
{
    pthread_t tid;
    cpu_set_t cpuset;

    tid = pthread_self();

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    return pthread_setaffinity_np(tid, sizeof(cpu_set_t), &cpuset);
}

void
thread_dump(FILE *f)
{
    struct thd_state *s;
    int i;

    if (!f)
        f = stdout;

    fprintf(f, ">>> Max threads %d, sizeof(thd_t) %ld, ", cne_max_threads(), sizeof(thd_t));

    fprintf(f, "sizeof(thd_state) %ld, total size %ld bytes\n", sizeof(struct thd_state),
            (sizeof(struct thd_state) * cne_max_threads()) + sizeof(struct thd_state));

    for (i = 0; i < cne_max_threads(); i++) {
        s = &__thd[i];
        if (s->magic_id != THREAD_MAGIC_ID)
            continue;
        fprintf(f, " %3d: '%s' %srunning, pid 0x%lx\n", i, s->name, (s->running) ? "" : "Not ",
                (uintptr_t)s->pid);
    }
}

CNE_INIT_PRIO(thread_initialize, THREAD)
{
    thd_state_t *s;
    int max_threads = cne_max_threads();
    int uid;

    cne_spinlock_init(&thd_lock);

    /* thd_state_t should be max_threads + 1 cachelines in size */
    __thd = calloc(max_threads + 1, sizeof(thd_state_t));
    if (!__thd) {
        cne_printf("%s: Failed to initialize thread state\n", __func__);
        exit(-1);
    }

    uid = cne_initial_uid();
    s   = &__thd[uid];

    snprintf(s->name, sizeof(s->name), UID_INITIAL_NAME);

    s->pid     = (uintptr_t)gettid();
    s->running = 1;

    s->magic_id = THREAD_MAGIC_ID;
}
