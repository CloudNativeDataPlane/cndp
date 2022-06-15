/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <stdint.h>                   // for uint16_t
#include <string.h>                   // for strcmp
#include <bsd/string.h>               // for strlcpy
#include <cne_common.h>               // for CNE_INIT, CNE_PRIORITY_LAST
#include <sys/queue.h>                // for STAILQ_FOREACH, STAILQ_INIT, STAILQ_I...
#include <bsd/sys/bitstring.h>        // for bit_alloc, bit_clear, bit_ffs, bit_nset
#include <limits.h>                   // for CHAR_BIT
#include <stdlib.h>                   // for free, calloc
#include <pthread.h>
#include <cne_log.h>
#include <cne_mutex_helper.h>

#include "uid_private.h"        // for uid_entry, uid_private_t, uid_entry::...
#include "uid.h"

static uid_private_t __uid;
static pthread_mutex_t uid_list_mutex;

static inline int
uid_list_lock(void)
{
    int ret = pthread_mutex_lock(&uid_list_mutex);

    if (ret == 0)
        return 1;
    CNE_WARN("failed: %s\n", strerror(ret));
    return 0;
}

static inline void
uid_list_unlock(void)
{
    int ret = pthread_mutex_unlock(&uid_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static inline int
uid_lock(struct uid_entry *e)
{
    if (e) {
        int ret = pthread_mutex_lock(&e->mutex);

        if (ret == 0)
            return 1;
        CNE_WARN("failed: %s\n", strerror(ret));
    }

    return 0;
}

static inline void
uid_unlock(struct uid_entry *e)
{
    if (e) {
        int ret = pthread_mutex_unlock(&e->mutex);

        if (ret)
            CNE_WARN("failed: (%d) %s\n", ret, strerror(ret));
    }
}

u_id_t
uid_find_by_name(const char *name)
{
    struct uid_entry *e, *ret = NULL;

    if (name && name[0] != '\0') {
        if (uid_list_lock()) {
            STAILQ_FOREACH (e, &__uid.list, next) {
                if (!strncmp(name, e->name, sizeof(e->name))) {
                    ret = e;
                    break;
                }
            }
            uid_list_unlock();
        }
    }

    return ret;
}

int
uid_test(u_id_t *_e, int uid)
{
    struct uid_entry *e = (struct uid_entry *)_e;
    int ret             = 0;

    if (e) {
        if (uid_lock(e)) {
            ret = (bit_test(e->bitmap, uid) == 0);
            uid_unlock(e);
        }
    }
    return ret;
}

uint16_t
uid_max_ids(u_id_t _e)
{
    struct uid_entry *e = _e;

    return (!e) ? 0 : e->max_ids;
}

uint16_t
uid_allocated(u_id_t _e)
{
    struct uid_entry *e = _e;

    return (!e) ? 0 : e->allocated;
}

static inline void
entry_destroy(struct uid_entry *e)
{
    if (e) {
        /* use the max_ids to detect mutex was created */
        if (e->max_ids && cne_mutex_destroy(&e->mutex) < 0)
            CNE_ERR("Unable to destroy mutex\n");
        free(e->bitmap);
        free(e);
    }
}

static inline struct uid_entry *
entry_create(const char *name, int cnt)
{
    struct uid_entry *e;

    e = calloc(1, sizeof(struct uid_entry));
    if (e) {
        strlcpy(e->name, name, sizeof(e->name));

        e->bitmap_sz = bitstr_size(cnt) * CHAR_BIT;
        e->bitmap    = bit_alloc(e->bitmap_sz);
        if (!e->bitmap)
            goto err;

        /* Set all of the bits to one (not allocated) to allow bit_ffs() to work */
        bit_nset(e->bitmap, 0, cnt - 1);

        if (cne_mutex_create(&e->mutex, 0) < 0)
            goto err;

        e->max_ids = cnt;
    }

    return e;
err:
    entry_destroy(e);
    return NULL;
}

u_id_t
uid_register(const char *name, uint16_t cnt)
{
    struct uid_entry *e;

    if (!name || name[0] == '\0')
        return NULL;

    e = uid_find_by_name(name);
    if (e)
        return e;

    e = entry_create(name, cnt);
    if (e) {
        if (!uid_list_lock())
            goto err;
        STAILQ_INSERT_TAIL(&__uid.list, e, next);
        __uid.list_cnt++;
        uid_list_unlock();
    }

    return e;
err:
    entry_destroy(e);
    return NULL;
}

int
uid_unregister(u_id_t _e)
{
    struct uid_entry *e = _e;

    if (e) {
        if (uid_list_lock()) {
            STAILQ_REMOVE(&__uid.list, e, uid_entry, next);

            __uid.list_cnt--;

            entry_destroy(e);

            uid_list_unlock();
            return 0;
        }
    }

    return -1;
}

int
uid_alloc(u_id_t _e)
{
    struct uid_entry *e = _e;
    int uid             = -1;

    if (e && e->allocated < e->max_ids) {
        if (uid_lock(e)) {
            bit_ffs(e->bitmap, e->max_ids, &uid);
            bit_clear(e->bitmap, uid);
            e->allocated++;
            uid_unlock(e);
        }
    }

    return uid;
}

void
uid_free(u_id_t _e, int uid)
{
    struct uid_entry *e = _e;

    if (e) {
        if (uid >= 0 && uid < e->max_ids) {
            if (uid_lock(e)) {
                if (!bit_test(e->bitmap, uid)) {
                    bit_set(e->bitmap, uid);
                    e->allocated--;
                }
                uid_unlock(e);
            }
        }
    }
}

void
uid_dump(FILE *f)
{
    struct uid_entry *e;

    if (!f)
        f = stdout;

    fprintf(f, "\nID Allocator count %d\n", __uid.list_cnt);

    STAILQ_FOREACH (e, &__uid.list, next) {
        fprintf(f, "%-24s max_ids %5d bitmap_sz %5dbits, Allocated %5d\n", e->name, e->max_ids,
                e->bitmap_sz, e->allocated);
    }
}

CNE_INIT_PRIO(uid_initialize, INIT)
{
    if (__uid.magic_id != UID_MAGIC_ID) {
        STAILQ_INIT(&__uid.list);

        if (cne_mutex_create(&uid_list_mutex, PTHREAD_MUTEX_RECURSIVE) < 0)
            CNE_RET("mutex init(uid_list_mutex) failed\n");

        __uid.list_cnt = 0;
        __uid.magic_id = UID_MAGIC_ID;
    }
}
