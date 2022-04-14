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

#include "uid_private.h"        // for uid_entry, uid_private_t, uid_entry::...
#include "uid.h"

static uid_private_t __uid;

u_id_t
uid_find_by_name(const char *name)
{
    struct uid_entry *e, *ret = NULL;

    if (name && name[0] != '\0') {
        STAILQ_FOREACH (e, &__uid.list, next) {
            if (!strcmp(name, e->name)) {
                ret = e;
                break;
            }
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

u_id_t
uid_register(const char *name, uint16_t cnt)
{
    struct uid_entry *e;

    if (!name || name[0] == '\0')
        return NULL;

    e = uid_find_by_name(name);
    if (e)
        return e;

    e = calloc(1, sizeof(struct uid_entry));
    if (!e)
        return NULL;

    strlcpy(e->name, name, sizeof(e->name));

    e->max_ids = cnt;

    e->bitmap_sz = bitstr_size(cnt) * CHAR_BIT;
    e->bitmap    = bit_alloc(e->bitmap_sz);
    if (!e->bitmap) {
        free(e);
        return NULL;
    }
    bit_nset(e->bitmap, 0, e->max_ids - 1);

    STAILQ_INSERT_TAIL(&__uid.list, e, next);
    __uid.list_cnt++;

    return e;
}

int
uid_unregister(u_id_t _e)
{
    struct uid_entry *e = _e;

    if (!e)
        return -1;

    STAILQ_REMOVE(&__uid.list, e, uid_entry, next);
    __uid.list_cnt--;

    free(e->bitmap);
    free(e);

    return 0;
}

int
uid_alloc(u_id_t _e)
{
    struct uid_entry *e = _e;

    if (!e)
        return -1;

    if (e->allocated < e->max_ids) {
        int uid;

        bit_ffs(e->bitmap, (e->max_ids), (&uid));
        bit_clear(e->bitmap, uid);
        e->allocated++;

        return uid;
    }

    return -1;
}

int
uid_free(u_id_t _e, int uid)
{
    struct uid_entry *e = _e;

    if (!e)
        return -1;

    if (uid < 0)
        return -1;

    /* prevent out of range access */
    if (uid >= e->max_ids)
        return -1;

    if (!bit_test(e->bitmap, uid)) {
        bit_set(e->bitmap, uid);
        e->allocated--;
    }

    return 0;
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
        __uid.list_cnt = 0;
        __uid.magic_id = UID_MAGIC_ID;
    }
}
