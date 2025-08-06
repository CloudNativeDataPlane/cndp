/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2025 Intel Corporation
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/queue.h>
#include <stdatomic.h>
#include <bsd/string.h>
#include <pthread.h>
#include <errno.h>

#include "ibroker.h"
#include "ibroker_private.h"
#include "ibroker_uintr.h"

static pthread_spinlock_t ibroker_lock;
static struct ibroker *ibrokers[IBROKER_MAX_COUNT];

__thread struct ibroker *per_thread_ibroker;

/* Must be called with the ibroker_lock held */
static int
_find_ibroker_slot(void)
{
    for (int i = 0; i < IBROKER_MAX_COUNT; i++)
        if (ibrokers[i] == NULL)
            return i;
    return -1;
}

static struct ibroker *
__search_broker(const char *name)
{
    struct ibroker *ibroker = NULL;

    if (pthread_spin_lock(&ibroker_lock) == 0) {
        for (int i = 0; i < IBROKER_MAX_COUNT; i++) {
            if (!ibrokers[i])
                continue;

            if (!strncasecmp(name, ibrokers[i]->name, sizeof(ibroker->name))) {
                ibroker = ibrokers[i];
                break;
            }
        }

        (void)pthread_spin_unlock(&ibroker_lock);
    }

    return ibroker;
}

static struct ibroker *
__create(const char *name)
{
    struct ibroker *ibroker;

    if (this_ibroker)
        return this_ibroker;

    ibroker = calloc(1, sizeof(struct ibroker));
    if (ibroker) {
        if (!name)
            name = "BrokerUnknown";

        strlcpy(ibroker->name, name, sizeof(ibroker->name));

        for (int i = 0; i < IBROKER_MAX_SERVICES; i++) {
            struct ibroker_srv *srv = &ibroker->services[i];

            srv->uintr_fd = -1;
            srv->enabled  = false;
        }

        ibroker->tid = gettid();

        if (uintr_register_handler(uintr_handler, 0) < 0)
            goto err;
    }

    return ibroker;
err:
    free(ibroker);
    return NULL;
}

broker_id_t
ibroker_create(const char *name)
{
    struct ibroker *ibroker;

    /* Look up broker name and see if it exists */
    ibroker = __search_broker(name);
    if (ibroker)
        return ibroker->bid;

    ibroker = __create(name);
    if (ibroker) {
        if (pthread_spin_lock(&ibroker_lock) == 0) {
            broker_id_t bid = _find_ibroker_slot();

            if (bid < 0)
                free(ibroker);
            else {
                ibroker->bid  = bid;
                ibrokers[bid] = ibroker;
                this_ibroker  = ibroker;

                uintr_start();
            }

            (void)pthread_spin_unlock(&ibroker_lock);

            return bid;
        } else
            free(ibroker);
    }
    return -1;
}

static int
__destroy(struct ibroker *ibroker)
{
    for (int i = 0; i < IBROKER_MAX_SERVICES; i++) {
        struct ibroker_srv *srv = &ibroker->services[i];

        if (srv->enabled)
            if (uintr_unregister_sender(srv->uintr_fd, 0) < 0)
                return -1;
    }
    uintr_clear();

    if (uintr_unregister_handler(0) < 0)
        return -1;

    this_ibroker = NULL;
    free(ibroker);

    return 0;
}

void
ibroker_destroy(broker_id_t bid)
{
    if (!BROKER_IS_VALID(bid))
        return;

    if (pthread_spin_lock(&ibroker_lock) == 0) {
        struct ibroker *ibroker = ibrokers[bid];

        if (ibroker) {
            if (__destroy(ibroker) < 0)
                printf("ibroker_destroy(%d) failed\n", bid);
            else
                ibrokers[bid] = NULL;
        }
        (void)pthread_spin_unlock(&ibroker_lock);
    }
}

int
ibroker_send(broker_id_t bid, service_id_t sid)
{
    if (BROKER_IS_VALID(bid) && SERVICE_IS_VALID(sid)) {
        if (pthread_spin_lock(&ibroker_lock) == 0) {
            struct ibroker *ibroker = ibrokers[bid];

            if (ibroker) {
                struct ibroker_srv *srv = &ibroker->services[sid];

                if (srv->enabled) {
                    _senduipi(srv->uipi_index);
                    (void)pthread_spin_unlock(&ibroker_lock);
                    return 0;
                }
            }
            (void)pthread_spin_unlock(&ibroker_lock);
        }
    }
    return -1;
}

service_id_t
ibroker_add_service(broker_id_t bid, const char *name, service_id_t sid, ibroker_func_t func,
                    void *arg)
{
    struct ibroker_srv *srv = NULL;

    if (pthread_spin_lock(&ibroker_lock) == 0) {
        struct ibroker *ibroker = ibrokers[bid];
        int uintr_fd;

        if (!name || !func || !BROKER_IS_VALID(bid) || !SERVICE_IS_VALID(sid))
            goto err;

        if (!ibroker)
            goto err;

        srv = &ibroker->services[sid];

        if (srv->enabled || srv->uintr_fd != -1)
            goto err;

        uintr_fd = uintr_create_fd(sid, 0);

        if (uintr_fd < 0)
            goto err;

        srv->uintr_fd = uintr_fd;
        srv->func     = func;
        srv->arg      = arg;
        strlcpy(srv->name, name, sizeof(srv->name));

        srv->enabled = true;

        (void)pthread_spin_unlock(&ibroker_lock);
    }
    return 0;
err:
    (void)pthread_spin_unlock(&ibroker_lock);
    return -1;
}

int
ibroker_del_service(broker_id_t bid, service_id_t sid)
{
    if (pthread_spin_lock(&ibroker_lock) == 0) {
        if (BROKER_IS_VALID(bid)) {
            struct ibroker *ibroker = ibrokers[bid];

            if (ibroker) {
                if (SERVICE_IS_VALID(sid)) {
                    struct ibroker_srv *srv = &ibroker->services[sid];

                    if (srv->enabled) {
                        if (uintr_unregister_sender(srv->uintr_fd, 0) < 0) {
                            printf("%s: uintr_unregister_sender(%d, %d, %d) failed: %s\n", __func__,
                                   bid, sid, srv->uintr_fd, strerror(errno));
                            goto leave;
                        }

                        close(srv->uintr_fd);
                        srv->uintr_fd = -1;
                        srv->enabled  = false;
                        (void)pthread_spin_unlock(&ibroker_lock);
                        return 0;
                    }
                }
            }
        }
    leave:
        (void)pthread_spin_unlock(&ibroker_lock);
    }
    return -1;
}

int
ibroker_register_sender(broker_id_t bid, service_id_t sid)
{
    struct ibroker_srv *srv = NULL;

    if (pthread_spin_lock(&ibroker_lock) == 0) {
        if (!BROKER_IS_VALID(bid) || !SERVICE_IS_VALID(sid))
            goto err;
        else {
            struct ibroker *ibroker = ibrokers[bid];
            int ret;

            if (!ibroker)
                goto err;

            srv = &ibroker->services[sid];

            if (!srv->enabled)
                goto err;

            if ((ret = uintr_register_sender(srv->uintr_fd, 0)) < 0)
                goto err;

            srv->uipi_index = ret;
            srv->enabled    = true;
        }

        (void)pthread_spin_unlock(&ibroker_lock);
    }
    return 0;
err:
    (void)pthread_spin_unlock(&ibroker_lock);
    return -1;
}

int
ibroker_id_list(broker_id_t *ids, int len)
{
    int k = 0;

    /* Allow ids to be NULL and set len to max length */
    if (!ids)
        len = IBROKER_MAX_COUNT;
    if (ids && len <= 0)
        return -1;

    if (pthread_spin_lock(&ibroker_lock) == 0) {
        for (int i = 0; i < IBROKER_MAX_COUNT; i++) {
            if (ibrokers[i]) {
                if (ids)
                    ids[k] = i;
                if (++k >= len)
                    break;
            }
        }

        (void)pthread_spin_unlock(&ibroker_lock);
        return k;
    }
    return -1;
}

const char *
ibroker_get_name(broker_id_t bid)
{
    struct ibroker *ibroker = NULL;

    if (BROKER_IS_VALID(bid))
        ibroker = ibrokers[bid];

    return (ibroker) ? ibroker->name : NULL;
}

int
ibroker_service_fd(broker_id_t bid, service_id_t sid)
{
    struct ibroker *ibroker = NULL;

    if (BROKER_IS_VALID(bid) && SERVICE_IS_VALID(sid))
        ibroker = ibrokers[bid];

    return (ibroker) ? ibroker->services[sid].uintr_fd : -1;
}

const char *
ibroker_service_name(broker_id_t bid, service_id_t sid)
{
    struct ibroker *ibroker = NULL;

    if (BROKER_IS_VALID(bid) && SERVICE_IS_VALID(sid))
        ibroker = ibrokers[bid];

    return (ibroker) ? ibroker->services[sid].name : NULL;
}

broker_id_t
ibroker_find(const char *name)
{
    struct ibroker *ibroker = __search_broker(name);

    return (ibroker) ? ibroker->bid : -1;
}

int
ibroker_find_service(broker_id_t bid, const char *name)
{
    int sid = -1;

    if (name && (pthread_spin_lock(&ibroker_lock) == 0)) {
        struct ibroker *ibroker;

        for (int i = 0; i < IBROKER_MAX_COUNT; i++) {
            ibroker = ibrokers[i];

            if (!ibroker || ((bid >= 0) && (i != bid)))
                continue;

            for (int j = 0; j < IBROKER_MAX_SERVICES; j++) {
                struct ibroker_srv *srv = &ibroker->services[j];

                if (srv->enabled) {
                    if (!strncasecmp(name, srv->name, sizeof(srv->name))) {
                        sid = j;
                        goto leave;
                    }
                }
            }
        }

    leave:
        (void)pthread_spin_unlock(&ibroker_lock);
    }
    return sid;
}

int
ibroker_walk(ibroker_walk_t func, void *arg)
{
    struct ibroker *ibroker;

    if (pthread_spin_lock(&ibroker_lock) == 0) {
        for (int i = 0; i < IBROKER_MAX_COUNT; i++) {
            ibroker = ibrokers[i];

            if (ibroker && (func(ibroker->bid, arg) < 0))
                break;
        }

        (void)pthread_spin_unlock(&ibroker_lock);
    }

    return 0;
}

int
ibroker_info(broker_id_t bid, ibroker_info_t *info)
{
    struct ibroker *ibroker;

    if (!info || !BROKER_IS_VALID(bid))
        return -1;
    ibroker = ibrokers[bid];

    memset(info, 0, sizeof(*info));

    strlcpy(info->name, ibroker->name, sizeof(info->name));
    info->tid   = ibroker->tid;
    info->intrs = ibroker->intrs;
    info->bid   = ibroker->bid;

    for (int i = 0; i < IBROKER_MAX_SERVICES; i++) {
        struct ibroker_srv *srv    = &ibroker->services[i];
        struct service_info *sinfo = &info->services[i];
        sinfo->valid               = 0;
        if (srv->enabled)
            sinfo->valid = 1;

        sinfo->sid      = i;
        sinfo->uintr_fd = srv->uintr_fd;
        sinfo->call_cnt = srv->call_cnt;
        sinfo->err_cnt  = srv->err_cnt;
        strlcpy(sinfo->name, srv->name, sizeof(sinfo->name));
    }

    return 0;
}

// clang-format off
static void __attribute__((constructor))
ibroker_ctor(void)
{
    pthread_spin_init(&ibroker_lock, PTHREAD_PROCESS_PRIVATE);
}
// clang-format on
