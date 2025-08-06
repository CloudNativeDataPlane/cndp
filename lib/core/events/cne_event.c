/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2025 Intel Corporation
 */

#include <stdint.h>              // for uint32_t, uint8_t
#include <stdlib.h>              // for free, NULL, calloc
#include <pthread.h>             // for pthread_create, pthread_detach, pthread_yield
#include <sys/queue.h>           // for TAILQ_FOREACH, TAILQ_REMOVE, TAILQ_FIRST
#include <unistd.h>              // for write, read, close, pipe
#include <string.h>              // for strerror, memset
#include <errno.h>               // for errno, EINVAL, EPIPE, EAGAIN, EINTR, ENOENT
#include <sys/epoll.h>           // for epoll_event, epoll_ctl, epoll_data_t, epol...
#include <stdbool.h>             // for true, bool, false
#include <cne_common.h>          // for __cne_unused, CNE_SET_USED
#include <cne_log.h>             // for CNE_LOG_ERR, CNE_LOG_WARNING, CNE_WARN
#include <cne_spinlock.h>        // for cne_spinlock_unlock, cne_spinlock_lock
#include <cne_event.h>           // for CNE_EVENT

#define EPOLL_WAIT_FOREVER (-1)

/*
 * union for pipe fds.
 */
union ev_pipefds {
    struct {
        int pipefd[2];
    };
    struct {
        int readfd;
        int writefd;
    };
};

TAILQ_HEAD(cne_ev_cb_list, cne_ev_callback);
TAILQ_HEAD(cne_ev_src_list, cne_ev_source);

struct cne_ev_callback {
    TAILQ_ENTRY(cne_ev_callback) next;
    cne_ev_callback_fn cb_fn;             /**< callback address */
    void *cb_arg;                         /**< parameter for callback */
    uint8_t pending_delete;               /**< delete after callback is called */
    cne_ev_unregister_callback_fn ucb_fn; /**< fn to call before cb is deleted */
};

struct cne_ev_source {
    TAILQ_ENTRY(cne_ev_source) next;
    struct cne_ev_handle ev_handle;  /**< interrupt handle */
    struct cne_ev_cb_list callbacks; /**< user callbacks */
    uint32_t active;
};

/* union buffer for pipe read/write */
static union ev_pipefds ev_pipe;

/* event handling thread */
static pthread_t ev_thread;

/* global spinlock for interrupt data operation */
static cne_spinlock_t ev_lock = CNE_SPINLOCK_INITIALIZER;

static int ev_init(void);
static int ev_initialized;

/* event sources list */
static struct cne_ev_src_list cne_ev_sources;

int
cne_ev_callback_register(const struct cne_ev_handle *ev_handle, cne_ev_callback_fn cb, void *cb_arg)
{
    int ret = 0, wake_thread;
    struct cne_ev_callback *callback;
    struct cne_ev_source *src;

    if (ev_init() < 0) /* Initialize the event system if the register is called */
        return -1;

    wake_thread = 0;

    /* first do parameter checking */
    if (ev_handle == NULL || ev_handle->fd < 0 || cb == NULL)
        return -EINVAL;

    /* allocate a new interrupt callback entity */
    callback = calloc(1, sizeof(*callback));

    if (callback == NULL)
        return -ENOMEM;

    callback->cb_fn          = cb;
    callback->cb_arg         = cb_arg;
    callback->pending_delete = 0;
    callback->ucb_fn         = NULL;

    cne_spinlock_lock(&ev_lock);

    /* check if there is at least one callback registered for the fd */
    TAILQ_FOREACH (src, &cne_ev_sources, next) {
        if (src->ev_handle.fd == ev_handle->fd) {
            /* we had no event for this */
            if (TAILQ_EMPTY(&src->callbacks))
                wake_thread = 1;

            TAILQ_INSERT_TAIL(&(src->callbacks), callback, next);
            break;
        }
    }

    /* no existing callbacks for this - add new source */
    if (src == NULL) {
        src = calloc(1, sizeof(*src));
        if (src == NULL) {
            free(callback);
            ret = -ENOMEM;
        } else {
            src->ev_handle = *ev_handle;
            TAILQ_INIT(&src->callbacks);
            TAILQ_INSERT_TAIL(&(src->callbacks), callback, next);
            TAILQ_INSERT_TAIL(&cne_ev_sources, src, next);
            wake_thread = 1;
        }
    }

    cne_spinlock_unlock(&ev_lock);

    if (wake_thread && write(ev_pipe.writefd, "1", 1) < 0)
        ret = -EPIPE;

    return ret;
}

int
cne_ev_callback_unregister(const struct cne_ev_handle *ev_handle, cne_ev_callback_fn cb_fn,
                           void *cb_arg)
{
    int ret;
    struct cne_ev_source *src;
    struct cne_ev_callback *cb, *next;

    /* do parameter checking first */
    if (ev_handle == NULL || ev_handle->fd < 0)
        return -EINVAL;

    cne_spinlock_lock(&ev_lock);

    /* check if the interrupt source for the fd is existent */
    TAILQ_FOREACH (src, &cne_ev_sources, next)
        if (src->ev_handle.fd == ev_handle->fd)
            break;

    /* No interrupt source registered for the fd */
    if (src == NULL)
        ret = -ENOENT;
    /* interrupt source has some active callbacks right now. */
    else if (src->active != 0)
        ret = -EAGAIN;
    /* ok to remove. */
    else {
        ret = 0;

        /* walk through the callbacks and remove all that match. */
        for (cb = TAILQ_FIRST(&src->callbacks); cb != NULL; cb = next) {

            next = TAILQ_NEXT(cb, next);

            if (cb->cb_fn == cb_fn && (cb_arg == (void *)-1 || cb->cb_arg == cb_arg)) {
                TAILQ_REMOVE(&src->callbacks, cb, next);
                free(cb);
                ret++;
            }
        }

        /* all callbacks for that source are removed. */
        if (TAILQ_EMPTY(&src->callbacks)) {
            TAILQ_REMOVE(&cne_ev_sources, src, next);
            free(src);
        }
    }

    cne_spinlock_unlock(&ev_lock);

    /* notify the pipe fd waited by epoll_wait to rebuild the wait list */
    if (ret >= 0 && write(ev_pipe.writefd, "1", 1) < 0)
        ret = -EPIPE;

    return ret;
}

int
cne_ev_callback_unregister_pending(const struct cne_ev_handle *ev_handle, cne_ev_callback_fn cb_fn,
                                   void *cb_arg, cne_ev_unregister_callback_fn ucb_fn)
{
    int ret;
    struct cne_ev_source *src;
    struct cne_ev_callback *cb, *next;

    /* do parameter checking first */
    if (ev_handle == NULL || ev_handle->fd < 0)
        return -EINVAL;

    cne_spinlock_lock(&ev_lock);

    /* check if the interrupt source for the fd is existent */
    TAILQ_FOREACH (src, &cne_ev_sources, next) {
        if (src->ev_handle.fd == ev_handle->fd)
            break;
    }

    /* No interrupt source registered for the fd */
    if (src == NULL)
        ret = -ENOENT;
    else if (src->active == 0) /* only usable if the source is active */
        ret = -EAGAIN;
    else {
        ret = 0;

        /* walk through the callbacks and mark all that match. */
        for (cb = TAILQ_FIRST(&src->callbacks); cb != NULL; cb = next) {
            next = TAILQ_NEXT(cb, next);
            if (cb->cb_fn == cb_fn && (cb_arg == (void *)-1 || cb->cb_arg == cb_arg)) {
                cb->pending_delete = 1;
                cb->ucb_fn         = ucb_fn;
                ret++;
            }
        }
    }

    cne_spinlock_unlock(&ev_lock);

    return ret;
}

static int
ev_process_event(__cne_unused struct epoll_event *events, __cne_unused int nfds)
{
    bool call = false;
    int n, bytes_read, rv;
    struct cne_ev_source *src;
    struct cne_ev_callback *cb, *next;
    struct cne_ev_read_buffer buf;
    struct cne_ev_callback active_cb;

    for (n = 0; n < nfds; n++) {
        /*
         * if the pipe fd is ready to read, return out to
         * rebuild the wait list.
         */
        if (events[n].data.fd == ev_pipe.readfd) {
            int r = read(ev_pipe.readfd, buf.charbuf, sizeof(buf.charbuf));
            CNE_SET_USED(r);
            return -1;
        }
        cne_spinlock_lock(&ev_lock);
        TAILQ_FOREACH (src, &cne_ev_sources, next)
            if (src->ev_handle.fd == events[n].data.fd)
                break;
        if (src == NULL) {
            cne_spinlock_unlock(&ev_lock);
            continue;
        }

        /* mark this interrupt source as active and release the lock. */
        src->active = 1;
        cne_spinlock_unlock(&ev_lock);

        switch (src->ev_handle.type) {
            /*TBD add more type*/
        case CNE_EV_HANDLE_EXT:
            bytes_read = 0;
            call       = true;
            break;
        default:
            bytes_read = 0;
            break;
        }

        if (bytes_read > 0) {
            /**
             * read out to clear the ready-to-be-read flag
             * for epoll_wait.
             */
            bytes_read = read(events[n].data.fd, &buf, bytes_read);
            if (bytes_read < 0) {
                if (errno == EINTR || errno == EWOULDBLOCK)
                    continue;
                /*
                 * The device is unplugged or buggy, remove
                 * it as an interrupt source and return to
                 * force the wait list to be rebuilt.
                 */
                cne_spinlock_lock(&ev_lock);
                TAILQ_REMOVE(&cne_ev_sources, src, next);
                cne_spinlock_unlock(&ev_lock);

                for (cb = TAILQ_FIRST(&src->callbacks); cb; cb = next) {
                    next = TAILQ_NEXT(cb, next);
                    TAILQ_REMOVE(&src->callbacks, cb, next);
                    free(cb);
                }
                free(src);
                return -1;
            } else if (bytes_read == 0)
                CNE_WARN("Read nothing from file descriptor %d\n", events[n].data.fd);
            else
                call = true;
        }

        /* grab a lock, again to call callbacks and update status. */
        cne_spinlock_lock(&ev_lock);

        if (call) {
            /* Finally, call all callbacks. */
            TAILQ_FOREACH (cb, &src->callbacks, next) {
                /* make a copy and unlock. */
                active_cb = *cb;
                cne_spinlock_unlock(&ev_lock);

                /* call the actual callback */
                active_cb.cb_fn(active_cb.cb_arg);

                /*get the lock back. */
                cne_spinlock_lock(&ev_lock);
            }
        }
        /* we done with that interrupt source, release it. */
        src->active = 0;

        rv = 0;

        /* check if any callback are supposed to be removed */
        for (cb = TAILQ_FIRST(&src->callbacks); cb != NULL; cb = next) {
            next = TAILQ_NEXT(cb, next);
            if (cb->pending_delete) {
                TAILQ_REMOVE(&src->callbacks, cb, next);
                if (cb->ucb_fn)
                    cb->ucb_fn(&src->ev_handle, cb->cb_arg);
                free(cb);
                rv++;
            }
        }

        /* all callbacks for that source are removed. */
        if (TAILQ_EMPTY(&src->callbacks)) {
            TAILQ_REMOVE(&cne_ev_sources, src, next);
            free(src);
        }

        /* notify the pipe fd waited by epoll_wait to rebuild the wait list */
        if (rv > 0 && write(ev_pipe.writefd, "1", 1) < 0) {
            cne_spinlock_unlock(&ev_lock);
            return -EPIPE;
        }

        cne_spinlock_unlock(&ev_lock);
    }

    return 0;
}

static void
ev_handle_event(int pfd, unsigned totalfds)
{
    struct epoll_event events[totalfds];

    for (;;) {
        int nfds = epoll_wait(pfd, events, totalfds, EPOLL_WAIT_FOREVER);

        /* epoll_wait fail */
        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            CNE_WARN("epoll_wait returns with fail\n");
            return;
        } else if (nfds == 0) /* epoll_wait timeout, will never happens here */
            continue;

        /* epoll_wait has at least one fd ready to read */
        if (ev_process_event(events, nfds) < 0)
            return;
    }
}

static __attribute__((noreturn)) void *
ev_thread_main(__cne_unused void *arg)
{
    /* host thread, never break out */
    for (;;) {
        /* build up the epoll fd with all descriptors we are to
         * wait on then pass it to the handle_interrupts function
         */
        static struct epoll_event pipe_event = {
            .events = EPOLLIN | EPOLLPRI,
        };
        struct cne_ev_source *src;
        unsigned numfds = 0;

        /* create epoll fd */
        int pfd = epoll_create(1);
        if (pfd < 0)
            CNE_WARN("Cannot create epoll instance\n");

        pipe_event.data.fd = ev_pipe.readfd;
        /*
         * add pipe fd into wait list, this pipe is used to
         * rebuild the wait list.
         */
        if (epoll_ctl(pfd, EPOLL_CTL_ADD, ev_pipe.readfd, &pipe_event) < 0)
            CNE_ERR("Error adding fd to %d epoll_ctl, %s\n", ev_pipe.readfd, strerror(errno));

        numfds++;

        cne_spinlock_lock(&ev_lock);

        TAILQ_FOREACH (src, &cne_ev_sources, next) {
            struct epoll_event ev;

            if (src->callbacks.tqh_first == NULL)
                continue; /* skip those with no callbacks */

            memset(&ev, 0, sizeof(ev));
            ev.events  = EPOLLIN | EPOLLPRI | EPOLLRDHUP | EPOLLHUP;
            ev.data.fd = src->ev_handle.fd;

            /*
             * add all the uio device file descriptor
             * into wait list.
             */
            if (epoll_ctl(pfd, EPOLL_CTL_ADD, src->ev_handle.fd, &ev) < 0)
                CNE_ERR("Error adding fd %d epoll_ctl, %s\n", src->ev_handle.fd, strerror(errno));
            else
                numfds++;
        }
        cne_spinlock_unlock(&ev_lock);

        /* serve the interrupt */
        ev_handle_event(pfd, numfds);

        /*
         * when we return, we need to rebuild the
         * list of fds to monitor.
         */
        close(pfd);
    }
}

static int
ev_init(void)
{
    cne_spinlock_lock(&ev_lock);

    if (ev_initialized == 0) {
        ev_initialized = 1;

        TAILQ_INIT(&cne_ev_sources);

        /*
         * create a pipe which will be waited by epoll and notified to
         * rebuild the wait list of epoll.
         */
        if (pipe(ev_pipe.pipefd) < 0)
            CNE_ERR_GOTO(error, "Error Init pipe \n");
        else {
            /* create the host thread to wait/handle the interrupt */
            if (pthread_create(&ev_thread, NULL, ev_thread_main, NULL) < 0)
                CNE_ERR_GOTO(error, "Failed to start thread for cne_ev_init()\n");
            pthread_detach(ev_thread);

            sched_yield();
        }
    }

    cne_spinlock_unlock(&ev_lock);
    return 0;
error:
    ev_initialized = 0;
    cne_spinlock_unlock(&ev_lock);

    return -1;
}
