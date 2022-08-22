/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

#include <inttypes.h>          // for PRIu32
#include <bsd/string.h>        // for strlcpy
#include <cne_common.h>        // for cne_align32pow2, CNE_CACHE_LINE_SIZE
#include <cne_log.h>           // for CNE_LOG, CNE_LOG_ERR, CNE_LOG_DEBUG
#include <errno.h>             // for EINVAL, errno, ENAMETOOLONG, ENOMEM
#include <stdio.h>             // for fprintf, NULL, size_t, FILE, stdout
#include <string.h>            // for memset, strnlen
#include <stddef.h>            // for offsetof
#include <stdint.h>            // for uint32_t
#include <stdlib.h>            // for calloc, free
#include <sys/types.h>         // for ssize_t
#include <pthread.h>
#include <cne_spinlock.h>
#include <cne_cycles.h>
#include <cne_mutex_helper.h>

#include "msgchan_priv.h"
#include "msgchan.h"

TAILQ_HEAD(msgchan_list, msg_chan);

static struct msgchan_list mc_list_head = TAILQ_HEAD_INITIALIZER(mc_list_head);
static pthread_mutex_t mc_list_mutex;

#ifdef MC_ENABLE_LOCK_DEBUG
#define MC_LIST_LOCK()                                \
    do {                                              \
        CNE_NOTICE("[orange]>> Lock[] List Mutex\n"); \
        mc_list_lock();                               \
    } while (0 /*CONSTCOND*/)
#define MC_LIST_UNLOCK()                                \
    do {                                                \
        CNE_NOTICE("[Orange]<< UnLock[] List Mutex\n"); \
        mc_list_unlock();                               \
    } while (0 /*CONSTCOND*/)
#else
#define MC_LIST_LOCK()   mc_list_lock()
#define MC_LIST_UNLOCK() mc_list_unlock()
#endif

static inline void
mc_list_lock(void)
{
    int ret = pthread_mutex_lock(&mc_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static inline void
mc_list_unlock(void)
{
    int ret = pthread_mutex_unlock(&mc_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static inline void
mc_child_lock(msg_chan_t *mc)
{
    int ret = pthread_mutex_lock(&mc->mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static inline void
mc_child_unlock(msg_chan_t *mc)
{
    int ret = pthread_mutex_unlock(&mc->mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static msgchan_t *
attach_child(msg_chan_t *parent)
{
    msg_chan_t *child = NULL;
    char name[MC_NAME_SIZE + 1];
    int n;

    child = calloc(1, sizeof(msg_chan_t));
    if (!child)
        CNE_NULL_RET("Failed to allocate new child msg_chan_t structure\n");

    snprintf(name, MC_NAME_SIZE, "C%d:", parent->child_count);
    n = strlcpy(child->name, name, sizeof(child->name));
    strlcpy(child->name + n, parent->name + 2, sizeof(child->name) - n);

    child->parent              = parent; /* Set the parent pointer in the child */
    child->cookie              = parent->cookie;
    child->rings[MC_RECV_RING] = parent->rings[MC_SEND_RING]; /* Swap Tx/Rx rings */
    child->rings[MC_SEND_RING] = parent->rings[MC_RECV_RING];

    mc_child_lock(parent);
    TAILQ_INSERT_TAIL(&parent->children, child, next);
    parent->child_count++;
    mc_child_unlock(parent);

    return child;
}

msgchan_t *
mc_create(const char *name, int sz, uint32_t flags)
{
    msg_chan_t *mc;
    char rname[CNE_RING_NAMESIZE + 1];
    bool allow_child_create;
    int n;

    /* Determine is a child can be created */
    allow_child_create = ((flags & MC_NO_CHILD_CREATE) == 0);
    flags &= ~MC_NO_CHILD_CREATE; /* Remove flag if present */

    /* Make sure the name is not already used or needs child created */
    MC_LIST_LOCK();
    mc = mc_lookup(name);
    if (mc) {
        msg_chan_t *child = NULL;

        if (allow_child_create)
            child = attach_child(mc);

        MC_LIST_UNLOCK();
        return child;
    }

    mc = calloc(1, sizeof(msg_chan_t));
    if (!mc)
        CNE_ERR_GOTO(err, "Unable to allocate memory\n");

    mc->cookie = MC_COOKIE;

    n = strlcpy(mc->name, "P:", sizeof(mc->name));
    strlcpy(mc->name + n, name, sizeof(mc->name) - n);

    n = strlcpy(rname, "RR:", sizeof(rname)); /* RR - Receive Ring */
    strlcpy(rname + n, name, sizeof(rname) - n);
    if ((mc->rings[MC_RECV_RING] = cne_ring_create(rname, 0, sz, flags)) == NULL)
        CNE_ERR_GOTO(err, "Failed to create Recv ring\n");

    n = strlcpy(rname, "SR:", sizeof(rname)); /* SR - Send Ring */
    strlcpy(rname + n, name, sizeof(rname) - n);
    if ((mc->rings[MC_SEND_RING] = cne_ring_create(rname, 0, sz, flags)) == NULL)
        CNE_ERR_GOTO(err, "Failed to create Send ring\n");

    if (cne_mutex_create(&mc->mutex, PTHREAD_MUTEX_RECURSIVE))
        CNE_ERR_GOTO(err, "creating recursive mutex failed\n");

    mc->mutex_inited = true;

    TAILQ_INIT(&mc->children);

    TAILQ_INSERT_TAIL(&mc_list_head, mc, next);

    MC_LIST_UNLOCK();

    return mc;
err:
    if (mc) {
        cne_ring_free(mc->rings[MC_RECV_RING]);
        cne_ring_free(mc->rings[MC_SEND_RING]);

        if (mc->mutex_inited && cne_mutex_destroy(&mc->mutex))
            CNE_ERR("Unable to destroy mutex\n");
        memset(mc, 0, sizeof(msg_chan_t));
        free(mc);
    }

    MC_LIST_UNLOCK();

    return NULL;
}

void
mc_destroy(msgchan_t *_mc)
{
    msg_chan_t *mc = _mc;

    if (mc && mc->cookie == MC_COOKIE) {
        MC_LIST_LOCK();
        if (!mc->parent) { /* Handle parent destroy */
            msg_chan_t *m;

            TAILQ_REMOVE(&mc_list_head, mc, next);

            cne_ring_free(mc->rings[MC_RECV_RING]);
            cne_ring_free(mc->rings[MC_SEND_RING]);

            while (!TAILQ_EMPTY(&mc->children)) {
                m = TAILQ_FIRST(&mc->children);

                TAILQ_REMOVE(&mc->children, m, next);

                memset(m, 0, sizeof(msg_chan_t));
                free(m);
            }

            memset(mc, 0, sizeof(msg_chan_t));

            if (mc->mutex_inited && cne_mutex_destroy(&mc->mutex))
                CNE_ERR("Unable to destroy mutex\n");

            free(mc);
        } else { /* Handle child destroy */
            mc_child_lock(mc->parent);
            TAILQ_REMOVE(&mc->parent->children, mc, next);
            mc_child_unlock(mc->parent);

            memset(mc, 0, sizeof(msg_chan_t));
            free(mc);
        }
        MC_LIST_UNLOCK();
    }
}

static int
__recv(msg_chan_t *mc, void **objs, int count, uint64_t msec)
{
    cne_ring_t *r;
    int nb_objs = 0;

    mc->recv_calls++;

    if (count == 0)
        return 0;

    r = mc->rings[MC_RECV_RING];

    if (msec) {
        uint64_t begin, stop;

        begin = cne_rdtsc_precise();
        stop  = begin + ((cne_get_timer_hz() / 1000) * msec);

        while (nb_objs == 0 && begin < stop) {
            nb_objs = cne_ring_dequeue_burst(r, objs, count, NULL);
            if (nb_objs == 0) {
                begin = cne_rdtsc_precise();
                cne_pause();
            }
        }
        if (nb_objs == 0)
            mc->recv_timeouts++;
    } else
        nb_objs = cne_ring_dequeue_burst(r, objs, count, NULL);

    mc->recv_cnt += nb_objs;
    return nb_objs;
}

static int
__send(msgchan_t *_mc, void **objs, int count)
{
    msg_chan_t *mc = _mc;
    cne_ring_t *r;
    int nb_objs;

    mc->send_calls++;

    r = mc->rings[MC_SEND_RING];

    nb_objs = cne_ring_enqueue_burst(r, objs, count, NULL);
    if (nb_objs < 0)
        CNE_ERR_RET("[orange]Sending to msgchan failed[]\n");

    mc->send_cnt += nb_objs;
    return nb_objs;
}

int
mc_send(msgchan_t *_mc, void **objs, int count)
{
    msg_chan_t *mc = _mc;

    if (!mc || !objs || mc->cookie != MC_COOKIE)
        CNE_ERR_RET("Invalid parameters\n");

    if (count < 0)
        CNE_ERR_RET("Count of objects is negative\n");

    return __send(mc, objs, count);
}

int
mc_recv(msgchan_t *_mc, void **objs, int count, uint64_t msec)
{
    msg_chan_t *mc = _mc;
    int n;

    if (!mc || !objs || mc->cookie != MC_COOKIE)
        CNE_ERR_RET("Invalid parameters\n");

    if (count < 0)
        CNE_ERR_RET("Count of objects is %d\n", count);

    n = __recv(mc, objs, count, msec);
    if (msec && n == 0)
        mc->recv_timeouts++;

    return n;
}

msgchan_t *
mc_lookup(const char *name)
{
    msg_chan_t *mc;
    char pname[MC_NAME_SIZE + 1];

    if (name) {
        int n;

        MC_LIST_LOCK();

        n = strlcpy(pname, "P:", sizeof(pname));
        strlcpy(pname + n, name, sizeof(pname) - n);

        TAILQ_FOREACH (mc, &mc_list_head, next) {
            if (!strcmp(pname, mc->name)) {
                MC_LIST_UNLOCK();
                return mc;
            }
        }
        MC_LIST_UNLOCK();
    }
    return NULL;
}

const char *
mc_name(msgchan_t *_mc)
{
    msg_chan_t *mc = _mc;

    return (mc && mc->cookie == MC_COOKIE) ? mc->name : NULL;
}

int
mc_size(msgchan_t *_mc, int *recv_free_cnt, int *send_free_cnt)
{
    msg_chan_t *mc = _mc;

    if (mc && mc->cookie == MC_COOKIE) {
        int ring1_sz, ring2_sz;

        ring1_sz = cne_ring_free_count(mc->rings[MC_RECV_RING]);
        ring2_sz = cne_ring_free_count(mc->rings[MC_SEND_RING]);

        if (recv_free_cnt)
            *recv_free_cnt = ring1_sz;
        if (send_free_cnt)
            *send_free_cnt = ring2_sz;

        return cne_ring_get_capacity(mc->rings[MC_RECV_RING]);
    }
    return -1;
}

int
mc_info(msgchan_t *_mc, msgchan_info_t *info)
{
    msg_chan_t *mc = _mc;

    if (mc && info && mc->cookie == MC_COOKIE) {
        info->recv_ring     = mc->rings[MC_RECV_RING];
        info->send_ring     = mc->rings[MC_SEND_RING];
        info->child_count   = mc->child_count;
        info->send_calls    = mc->send_calls;
        info->send_cnt      = mc->send_cnt;
        info->recv_calls    = mc->recv_calls;
        info->recv_cnt      = mc->recv_cnt;
        info->recv_timeouts = mc->recv_timeouts;
        return 0;
    }

    return -1;
}

void
mc_dump(msgchan_t *_mc)
{
    msg_chan_t *mc = _mc;

    if (mc && mc->cookie == MC_COOKIE) {
        int n = mc_size(_mc, NULL, NULL);
        msg_chan_t *m;

        cne_printf("  [cyan]%-16s [magenta]size [green]%d[], [magenta]rings: Recv [green]%p[], "
                   "[magenta]Send [green]%p [magenta]Children [green]%d[]\n",
                   mc->name, n, mc->rings[MC_RECV_RING], mc->rings[MC_SEND_RING], mc->child_count);

        cne_printf("     [magenta]Send calls [cyan]%ld [magenta]count [cyan]%ld[], [magenta]Recv "
                   "calls [cyan]%ld [magenta]count [cyan]%ld [magenta]timeouts [cyan]%ld[]\n",
                   mc->send_calls, mc->send_cnt, mc->recv_calls, mc->recv_cnt, mc->recv_timeouts);
        if (mc->child_count) {
            cne_printf("     [magenta]Children [orange]%d[]: ", mc->child_count);
            TAILQ_FOREACH (m, &mc->children, next) {
                cne_printf(" [cyan]%s[]", m->name);
            }
            cne_printf("\n");
        }
    } else
        CNE_ERR("MsgChan is invalid\n");
}

void
mc_list(void)
{
    msg_chan_t *mc;

    MC_LIST_LOCK();

    cne_printf("[yellow]** [cyan]MsgChan [yellow]**[]\n");
    TAILQ_FOREACH (mc, &mc_list_head, next)
        mc_dump(mc);

    MC_LIST_UNLOCK();
}

CNE_INIT_PRIO(mc_constructor, LAST)
{
    TAILQ_INIT(&mc_list_head);

    if (cne_mutex_create(&mc_list_mutex, PTHREAD_MUTEX_RECURSIVE))
        CNE_ERR("creating recursive mutex failed\n");
}
