/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2023 Intel Corporation
 */

#include <stdint.h>           // for uint32_t, uint8_t
#include <stdlib.h>           // for free, NULL, calloc
#include <pthread.h>          // for pthread_create, pthread_detach, pthread_yield
#include <sys/queue.h>        // for TAILQ_FOREACH, TAILQ_REMOVE, TAILQ_FIRST
#include <stdbool.h>          // for true, bool, false
#include <bsd/string.h>

#include <cne_common.h>        // for __cne_unused, CNE_SET_USED
#include <cne_log.h>           // for CNE_LOG_ERR, CNE_LOG_WARNING, CNE_WARN
#include <cne_mutex_helper.h>
#include <cne_cycles.h>

#include "idlemgr_priv.h"

static TAILQ_HEAD(idlemgr_list, imgr_s) imgr_list;
static pthread_mutex_t imgr_list_mutex;

static inline int
imgr_list_lock(void)
{
    int ret = pthread_mutex_lock(&imgr_list_mutex);

    if (ret)
        CNE_ERR_RET_VAL(0, "failed: %s\n", strerror(ret));

    return 1;
}

static inline void
imgr_list_unlock(void)
{
    int ret = pthread_mutex_unlock(&imgr_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static inline int
imgr_lock(imgr_t *imgr)
{
    int ret = pthread_mutex_lock(&imgr->mutex);

    if (ret)
        CNE_ERR_RET_VAL(0, "failed: %s\n", strerror(ret));
    return 1;
}

static inline void
imgr_unlock(imgr_t *imgr)
{
    int ret = pthread_mutex_unlock(&imgr->mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

idlemgr_t *
idlemgr_create(const char *name, uint16_t max_fds, uint32_t idle_timeout, uint32_t intr_timeout)
{
    imgr_t *imgr;

    if (!name || strlen(name) == 0)
        CNE_NULL_RET("invalid name provided\n");

    if (max_fds == 0 || max_fds > IDLE_MGR_MAX_FDS)
        CNE_NULL_RET("invalid max number of file descriptors %d, max %d\n", max_fds,
                     IDLE_MGR_MAX_FDS);

    if (idle_timeout > IDLE_MGR_MAX_IDLE_TIMEOUT)
        CNE_NULL_RET("invalid idle timeout must be %d > 0 && <= %d ms\n", idle_timeout,
                     IDLE_MGR_MAX_IDLE_TIMEOUT);

    if (intr_timeout > IDLE_MGR_MAX_INTR_TIMEOUT)
        CNE_NULL_RET("invalid interrupt timeout must be %d >= 0 && <= %d ms\n", intr_timeout,
                     IDLE_MGR_MAX_INTR_TIMEOUT);

    if (imgr_list_lock()) {
        if (idlemgr_find_by_name(name)) {
            imgr_list_unlock();
            CNE_NULL_RET("idlemgr with name %s exists already\n", name);
        }
        imgr_list_unlock();
    }

    imgr = calloc(1, sizeof(imgr_t));
    if (!imgr)
        CNE_NULL_RET("Failed to allocate idlemgr instance\n");
    strlcpy(imgr->name, name, sizeof(imgr->name));

    imgr->max_fds      = max_fds;
    imgr->epoll_fd     = -1;
    imgr->idle_timeout = idle_timeout;
    imgr->intr_timeout = intr_timeout;

    if (cne_mutex_create(&imgr->mutex, PTHREAD_MUTEX_RECURSIVE) < 0)
        CNE_ERR_GOTO(err_leave, "mutex init(hmap->mutex) failed: %s\n", strerror(errno));
    imgr->mutex_inited = 1;

    imgr->events = calloc(max_fds, sizeof(struct epoll_event));
    if (!imgr->events)
        CNE_ERR_GOTO(err_leave, "Failed to allocate epoll_event array of size %d\n", max_fds);

    for (int i = 0; i < max_fds; i++)
        imgr->events[i].data.fd = -1;

    imgr->epoll_fd = epoll_create1(0);
    if (imgr->epoll_fd < 0)
        CNE_ERR_GOTO(err_leave, "epoll_create1 failed: %s\n", strerror(errno));

    if (imgr_list_lock()) {
        TAILQ_INSERT_TAIL(&imgr_list, imgr, next);
        imgr_list_unlock();
    }

    return imgr;

err_leave:
    idlemgr_destroy(imgr);
    return NULL;
}

void
idlemgr_destroy(idlemgr_t *_imgr)
{
    imgr_t *imgr = _imgr;

    if (imgr) {
        if (imgr_list_lock()) {
            TAILQ_REMOVE(&imgr_list, imgr, next);
            imgr_list_unlock();
        }

        if (imgr->epoll_fd != -1)
            close(imgr->epoll_fd);
        imgr->epoll_fd = -1;

        if (imgr->mutex_inited && cne_mutex_destroy(&imgr->mutex) < 0)
            CNE_ERR("mutex destroy(imgr->mutex) failed: %s\n", strerror(errno));

        free(imgr->events);
        free(imgr);
    }
}

int
idlemgr_set_timeouts(idlemgr_t *_imgr, uint32_t idle, uint32_t intr)
{
    imgr_t *imgr = _imgr;

    if (!imgr)
        return -1;

    if (idle > IDLE_MGR_MAX_IDLE_TIMEOUT || intr > IDLE_MGR_MAX_INTR_TIMEOUT)
        return -1;

    if (imgr_lock(imgr)) {
        imgr->idle_timeout = idle;
        imgr->intr_timeout = intr;
        imgr_unlock(imgr);
        return 0;
    }

    return -1;
}

int
idlemgr_get_timeouts(idlemgr_t *_imgr, uint32_t *idle, uint32_t *intr)
{
    imgr_t *imgr = _imgr;

    if (!imgr || !idle || !intr)
        return -1;

    if (imgr_lock(imgr)) {
        *idle = imgr->idle_timeout;
        *intr = imgr->intr_timeout;
        imgr_unlock(imgr);
        return 0;
    }

    return -1;
}

int
idlemgr_add(idlemgr_t *_imgr, int fd, uint32_t eflags)
{
    imgr_t *imgr             = _imgr;
    struct epoll_event event = {.events = eflags, .data.fd = fd};

    if (!imgr || fd < 0)
        CNE_ERR_RET("invalid arguments or idlemgr_t pointer is NULL\n");

    if (imgr_lock(imgr)) {
        if (imgr->epoll_fd == -1)
            CNE_ERR_GOTO(err_leave, "invalid epoll FD value %d\n", imgr->epoll_fd);

        if (imgr->nb_fds >= imgr->max_fds)
            CNE_ERR_GOTO(err_leave, "too many file descriptors, max %d\n", imgr->max_fds);

        if (event.events == 0)
            event.events = EPOLLIN;

        /* add fd to epoll group */
        if (epoll_ctl(imgr->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
            CNE_ERR_GOTO(err_leave, "epoll control add failed: %s\n", strerror(errno));
        imgr->nb_fds++;

        imgr_unlock(imgr);
        return 0;
    }
    return -1;

err_leave:
    imgr_unlock(imgr);
    return -1;
}

int
idlemgr_del(idlemgr_t *_imgr, int fd)
{
    imgr_t *imgr = _imgr;

    if (!imgr || fd < 0)
        CNE_ERR_RET("invalid epoll FD value or idlemgr_t pointer is NULL\n");

    if (imgr_lock(imgr)) {
        if (imgr->epoll_fd == -1)
            CNE_ERR_GOTO(err_leave, "invalid epoll FD value\n");

        /* remove fd from epoll group */
        if (epoll_ctl(imgr->epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0)
            CNE_ERR_GOTO(err_leave, "epoll control delete failed: %s\n", strerror(errno));

        imgr->nb_fds--;

        imgr_unlock(imgr);
        return 0;
    }

err_leave:
    imgr_unlock(imgr);
    return -1;
}

int
idlemgr_process(idlemgr_t *_imgr, int active)
{
    imgr_t *imgr = _imgr;
    int nfds     = 0;

    if (!imgr)
        CNE_ERR_RET("argument idlemgr_t is NULL\n");

    if (active == 0) {
        uint64_t tstamp = cne_rdtsc_precise();

        if (imgr->idle_timeout && imgr->idle_timestamp == 0) {
            imgr->stats.start_idle_timo++;
            imgr->idle_timestamp = tstamp + ((cne_get_timer_hz() / MS_PER_S) * imgr->idle_timeout);
            return 0;
        }

        if (imgr->idle_timestamp && (tstamp > imgr->idle_timestamp)) {
            imgr->stats.called_epoll++;
            nfds = epoll_wait(imgr->epoll_fd, imgr->events, imgr->nb_fds, imgr->intr_timeout);
            imgr->idle_timestamp = 0;
            if (nfds == 0)
                imgr->stats.intr_timedout++;
            else if (nfds > 0)
                imgr->stats.intr_found_work++;
            else
                imgr->stats.epoll_wait_failed++;
        }
    } else {
        imgr->idle_timestamp = 0;
        if (imgr->idle_timeout)
            imgr->stats.stop_idle_timo++;
    }

    return nfds;
}

struct epoll_event *
idlemgr_get_events(idlemgr_t *_imgr)
{
    imgr_t *imgr = _imgr;

    return (imgr) ? imgr->events : NULL;
}

idlemgr_t *
idlemgr_find_by_name(const char *name)
{
    imgr_t *imgr = NULL;

    if (imgr_list_lock()) {
        TAILQ_FOREACH (imgr, &imgr_list, next) {
            if (strncmp(imgr->name, name, IDLE_MGR_MAX_NAME_SIZE) == 0)
                goto found;
        }
        imgr = NULL;
    found:
        imgr_list_unlock();
    }

    return imgr;
}

int
idlemgr_stats(idlemgr_t *_imgr, idlemgr_stats_t *stats)
{
    imgr_t *imgr = _imgr;

    if (!imgr || !stats)
        return -1;

    stats->start_idle_timo   = imgr->stats.start_idle_timo;
    stats->stop_idle_timo    = imgr->stats.stop_idle_timo;
    stats->called_epoll      = imgr->stats.called_epoll;
    stats->intr_found_work   = imgr->stats.intr_found_work;
    stats->intr_timedout     = imgr->stats.intr_timedout;
    stats->epoll_wait_failed = imgr->stats.epoll_wait_failed;

    return 0;
}

void
idlemgr_dump(idlemgr_t *_imgr)
{
    imgr_t *imgr = _imgr;

    if (!imgr)
        return;

    if (imgr_lock(imgr)) {
        cne_printf("  [yellow]%s [magenta]epoll fd [orange]%d[]\n", imgr->name, imgr->epoll_fd);
        cne_printf("     [magenta]idle_timeout      []: [cyan]%u[] ms\n", imgr->idle_timeout);
        cne_printf("     [magenta]intr_timeout      []: [cyan]%u[] ms\n", imgr->intr_timeout);
        cne_printf("     [magenta]start_idle_timo   []: [cyan]%lu[]\n",
                   imgr->stats.start_idle_timo);
        cne_printf("     [magenta]stop_idle_timo    []: [cyan]%lu[]\n", imgr->stats.stop_idle_timo);
        cne_printf("     [magenta]called epoll      []: [cyan]%lu[]\n", imgr->stats.called_epoll);
        cne_printf("     [magenta]intr_found_work   []: [cyan]%lu[]\n",
                   imgr->stats.intr_found_work);
        cne_printf("     [magenta]intr_timedout     []: [cyan]%lu[]\n", imgr->stats.intr_timedout);
        cne_printf("     [magenta]epoll wait failed []: [cyan]%lu[]\n",
                   imgr->stats.epoll_wait_failed);
        cne_printf("     [magenta]nb_fds/max_fds    []: [cyan]%3d /%3d[]\n", imgr->nb_fds,
                   imgr->max_fds);
        imgr_unlock(imgr);
    }
}

void
idlemgr_list_dump(void)
{
    imgr_t *imgr;

    TAILQ_FOREACH (imgr, &imgr_list, next)
        idlemgr_dump(imgr);
}

CNE_INIT_PRIO(imgr_constructor, LAST)
{
    TAILQ_INIT(&imgr_list);

    if (cne_mutex_create(&imgr_list_mutex, PTHREAD_MUTEX_RECURSIVE) < 0)
        CNE_RET("mutex init(imgr_list_mutex) failed\n");
}
