/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <stdlib.h>             // for exit, calloc, free, on_exit
#include <signal.h>             // for signal, SIG_DFL, SIG_ERR
#include <stdatomic.h>          // for atomic_fetch_add, atomic_fetch_sub, atomic_...
#include <cne_version.h>        // for cne_version
#include <cne_tty.h>            // for tty_is_inited
#include <sys/queue.h>          // for STAILQ_INIT, STAILQ_INSERT_TAIL, STAILQ_REMOVE
#include <locale.h>
#include <cne_tailq.h>
#include <cne_log.h>

#include "cne_private.h"        // for cne_private_t, cne_entry, cne_entry::(anony...
#include "cne.h"                // for cne_id, ...
#include "uid.h"                // for uid_alloc, uid_free, uid_max_ids, uid_register
#include "cne_common.h"         // for CNE_INIT_PRIO, CNE_PRIORITY_STATE

static cne_private_t __cne = {.initial_uid = -1};

__thread __typeof__(struct cne_entry *) per_thread__cne;
#define this_cne per_thread__cne

int
cne_id(void)
{
    if (per_thread__cne)
        return per_thread__cne->uid;
    return -1;
}

static inline struct cne_entry *
__get_entry(int tidx)
{
    struct cne_entry *e = NULL;

    if (tidx < 0) {
        tidx = cne_id();
        if (tidx < 0)
            return NULL;
    }

    e = &__cne.entries[tidx];
    if (e->magic_id != CNE_MAGIC_ID)
        return NULL;

    return e;
}

static inline int
__create_entry(const char *name, int uid)
{
    struct cne_entry *e;

    if (uid < 0 || uid >= cne_max_threads())
        return -1;

    e = &__cne.entries[uid];
    if (e->magic_id == CNE_MAGIC_ID)
        return -1;

    snprintf(e->name, sizeof(e->name), "%s", name);
    e->uid      = uid;
    e->magic_id = CNE_MAGIC_ID;

    STAILQ_INSERT_TAIL(&__cne.list, e, next);
    atomic_fetch_add(&__cne.active, 1);

    this_cne = e;

    return uid;
}

int
cne_initial_uid(void)
{
    return __cne.initial_uid;
}

int
cne_entry_uid(void)
{
    struct cne_entry *e = __get_entry(cne_id());

    if (!e)
        return -1;

    if (e->magic_id != CNE_MAGIC_ID)
        return -1;

    return e->uid;
}

int
cne_max_threads(void)
{
    return uid_max_ids(__cne.pool);
}

int
cne_init(void)
{
    if (cne_tailqs_init() < 0)
        CNE_ERR_RET("unable to complete tailq initialization\n");
    return cne_initial_uid();
}

int
cne_next_id(int uid, int skip, int wrap)
{
    struct cne_entry *e = __get_entry(++uid);
    int initial_uid     = cne_initial_uid();

    if (!e) {
        if (wrap)
            e = __get_entry(__cne.initial_uid);
        else
            return -1;
    }

    if (!e)
        return -1;

    if (skip && (initial_uid == e->uid))
        e = e->next.stqe_next;
    if (!e)
        return -1;

    return e->uid;
}

int
cne_active_threads(void)
{
    return atomic_load(&__cne.active);
}

int
cne_register(const char *name)
{
    int uid;

    uid = uid_alloc(__cne.pool);
    if (uid < 0)
        return -1;

    return __create_entry(name, uid);
}

int
cne_unregister(int tidx)
{
    struct cne_entry *e = __get_entry(tidx);

    if (!e)
        return -1;

    /* Do not release the initial entry */
    if (tidx == __cne.initial_uid)
        return 0; /* This is not an error case */

    if (e->magic_id != CNE_MAGIC_ID || e->uid != tidx)
        return -1;

    uid_free(__cne.pool, e->uid);

    e->uid      = -1;
    e->magic_id = 0;

    STAILQ_REMOVE(&__cne.list, e, cne_entry, next);
    atomic_fetch_sub(&__cne.active, 1);

    return 0;
}

int
cne_set_private(int tidx, void *v)
{
    struct cne_entry *e = __get_entry(tidx);

    if (!e)
        return -1;

    e->priv_ = v;

    return 0;
}

int
cne_get_private(int tidx, void **v)
{
    struct cne_entry *e = __get_entry(tidx);

    if (!e)
        return -1;

    *v = e->priv_;

    return 0;
}

void
cne_dump(FILE *f)
{
    if (!f)
        f = stdout;

    fprintf(f, "Version %s: Magic ID: %x, Max threads %u\n", cne_version(), __cne.magic_id,
            cne_max_threads());

    for (int i = 0; i < cne_max_threads(); i++) {
        struct cne_entry *e = &__cne.entries[i];

        if (e->magic_id == CNE_MAGIC_ID)
            fprintf(f, "  Thread %s has UID %d private pointer is %p\n", e->name, e->uid, e->priv_);
    }
}

static void
__signal_handler(int sig)
{
    if (__cne.on_exit_fn)
        __cne.on_exit_fn(sig, __cne.on_exit_arg, CNE_CAUGHT_SIGNAL);
}

static void
__exit_handler(void)
{
    if (__cne.on_exit_fn)
        __cne.on_exit_fn(0, __cne.on_exit_arg, CNE_CALLED_EXIT);
}

int
cne_on_exit(on_exit_fn_t exit_fn, void *arg, int *signals, int nb_signals)
{
    int i;

    if (!signals && nb_signals)
        goto err_no_signals;

    if (!exit_fn)
        goto err;

    for (i = 0; i < nb_signals; i++)
        if (signal(signals[i], __signal_handler) == SIG_ERR)
            goto err;

    if (atexit(__exit_handler))
        goto err;

    __cne.on_exit_fn  = exit_fn;
    __cne.on_exit_arg = arg;

    return 0;

err:
    /* Reset the signal handler on error */
    for (i = 0; i < nb_signals; i++)
        signal(signals[i], SIG_DFL);

err_no_signals:
    return -1;
}

CNE_INIT_PRIO(cne_initialize, STATE)
{
    if (__cne.magic_id != CNE_MAGIC_ID) {
        /* Setup the thread pool of ID values */
        __cne.pool = uid_register(UID_INITIAL_NAME, DEFAULT_MAX_THREADS);
        if (!__cne.pool) {
            printf("%s: UID register failed\n", __func__);
            exit(-1);
        }

        __cne.entries = calloc(DEFAULT_MAX_THREADS, sizeof(struct cne_entry));
        if (__cne.entries == NULL) {
            printf("%s: Failed to initialize CNE\n", __func__);
            uid_unregister(__cne.pool);
            exit(-1);
        }
        STAILQ_INIT(&__cne.list);

        __cne.initial_uid = cne_register("Initial");
        if (__cne.initial_uid < 0) {
            printf("%s: Failed to register initial thread\n", __func__);
            free(__cne.entries);
            exit(-1);
        }

        setlocale(LC_ALL, "");

        __cne.magic_id = CNE_MAGIC_ID;
    }

    if (!tty_is_inited()) /* Force tty to be loaded and inited */
        printf("%s:%d: Error: TTY was not inited or loaded %d\n", __FILE__, __LINE__,
               tty_is_inited());
}
