/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <inttypes.h>          // for PRIuPTR
#include <stdio.h>             // for fprintf, size_t, snprintf, NULL
#include <stdint.h>            // for uint32_t, uint8_t, uint64_t, uint...
#include <getopt.h>            // for no_argument, getopt_long_only
#include <pthread.h>           // for pthread_self, pthread_create, pth...
#include <sys/epoll.h>         // for epoll_event, epoll_ctl, epoll_wait
#include <cne_ring.h>          // for cne_ring_t
#include <tst_info.h>          // for tst_error, TST_ASSERT_AND_CLEANUP
#include <cne_tailq.h>         // for TAILQ_FOREACH_SAFE
#include <cne_common.h>        // for cne_countof
#include <cne_log.h>           // for cne_exit
#include <errno.h>             // for errno
#include <stdlib.h>            // for calloc, free
#include <string.h>            // for strerror, strncmp, strlen, memset
#include <sys/queue.h>         // for TAILQ_FOREACH, TAILQ_INSERT_TAIL
#include <time.h>              // for timespec, clock_gettime, CLOCK_MO...
#include <unistd.h>            // for read, write, close, pipe, ssize_t

#include "ring_api.h"
#include "cne_ring_api.h"                 // for cne_ring_dequeue_bulk, cne_ring_e...
#include "cne_ring_api_internal.h"        // for cne_ring_mc_dequeue_bulk, cne_rin...
#include "cne_stdio.h"                    // for cne_printf
#include "vt100_out.h"                    // for vt_color, VT_NO_CHANGE, VT_OFF

#define RING_SIZE 1024

#define BULK_SIZE        50
#define DEFAULT_ELEMENTS 1000

static int verbose        = 0;
static int help           = 0;
static int opt_list_tests = 0;
static int opt_run_all    = 0;

struct ring_test_info {
    tst_info_t *tst;
    struct cne_ring *r;
};

static int
test_ring_fill_object_range(uint64_t *obj, size_t obj_sz, uint32_t id, uint32_t start)
{
    size_t i = 0;
    for (i = 0; i < obj_sz; i++) {
        obj[i] = ((uint64_t)id << 32) + (start + i);
    }
    return i;
}

struct worker_info;

TAILQ_HEAD(worker_list, worker_info);

struct test_ring_progress_info {
    struct worker_list worker_list;

    size_t total_produced;
    size_t total_consumed;

    tst_info_t *tst;
    struct cne_ring *r;
};

typedef unsigned (*test_enqueue_bulk_fn)(cne_ring_t *, void *const *, unsigned int, unsigned int *);
typedef unsigned (*test_dequeue_bulk_fn)(cne_ring_t *, void **, unsigned int, unsigned int *);

struct test_ring_create_args {
    unsigned int flags; /**< flags passed to cne_ring_create */
    unsigned int count; /**< element count passed to cne_ring_create */
};

struct test_ring_api_cfg {
    char name[128];
    test_enqueue_bulk_fn enqueue;
    test_dequeue_bulk_fn dequeue;
    struct test_ring_create_args ring_args;
    uint32_t elements;

    uint32_t producer_count;
    size_t producer_bulk;
    size_t total_produced;

    uint32_t consumer_count;
    size_t consumer_bulk;
    size_t total_consumed;

    int should_fail;
    int run;
    int result;
};

static size_t
test_dump_create_args(char *const out, size_t out_n, struct test_ring_create_args *args)
{
    return snprintf(out, out_n, "{flags:%d, count:%d}", args->flags, args->count);
}

static size_t
test_dump_cfg(char *const out, size_t out_n, struct test_ring_api_cfg *cfg)
{
    size_t total       = 0;
    char close_brace[] = "};";
    char close_trunc[] = "...};";
    size_t tail_sz     = sizeof(close_trunc);
    size_t written = snprintf(out, out_n - tail_sz, "cfg:%p {name:'%s', enqueue:%p, dequeue:%p, ",
                              cfg, cfg->name, cfg->enqueue, cfg->dequeue);
    if (written >= out_n - tail_sz) {
        total += snprintf(out + out_n - tail_sz, out_n - written, "%s", close_trunc);
        return total;
    }
    total += written;
    written = snprintf(out + total, out_n - total - tail_sz, "create_args:");
    if (written >= out_n - total - tail_sz) {
        total += snprintf(out + total, out_n - total, "%s", close_trunc);
        return total;
    }
    total += written;
    written = test_dump_create_args(out + total, out_n - total - tail_sz, &cfg->ring_args);
    if (written >= out_n - total - tail_sz) {
        total += snprintf(out + total, out_n - total, "%s", close_trunc);
        return total;
    }
    total += written;
    written =
        snprintf(out + total, out_n - total - tail_sz,
                 ", elements:%d, producer_count:%d, producer_bulk:%zu, "
                 "consumer_count:%d, consumer_bulk:%zu total_consumed:%zu, "
                 "should_fail:%d, run:%d, result:%d ",
                 cfg->elements, cfg->producer_count, cfg->producer_bulk, cfg->consumer_count,
                 cfg->consumer_bulk, cfg->total_consumed, cfg->should_fail, cfg->run, cfg->result);
    if (written >= out_n - total - tail_sz) {
        total += snprintf(out + total, out_n - total, "%s", close_trunc);
        return total;
    }
    total += written;
    total += snprintf(out + total, out_n - total, "%s", close_brace);
    return total;
}

struct worker_args {
    enum {
        enqueue_bulk,
        dequeue_bulk,
    } fn_type;
    union {
        test_enqueue_bulk_fn enqueue_bulk;
        test_dequeue_bulk_fn dequeue_bulk;
    } fn;
};

/** function used to wait for worker to finish and gather end state */
typedef int (*worker_join_fn)(struct worker_info *wi);
/** function to signal worker to stop */
typedef int (*worker_stop_fn)(struct worker_info *wi, uint8_t reason);
/** free worker memory */
typedef void (*worker_free_fn)(struct worker_info *wi);
/** cancel running worker */
typedef int (*worker_cancel_fn)(struct worker_info *wi);

/**
 * Structure describing test worker for each thread/process which is doing
 * actual ring enqueue/dequeue tasks.
 */
struct worker_info {
    enum {
        wi_type_thread,
        wi_type_process,
    } type;
    union {
        uintptr_t num;
        pthread_t thread;
        pid_t process;
    } id;
    TAILQ_ENTRY(worker_info) next;

    int read_fd;  /** message pipe from worker to supervisor */
    int write_fd; /** message pipe from supervisor to worker */

    int result;
    int producer; /**< check if worker is producer */
    // unsigned int produce_burst;

    int consumer; /**< check if worker is consumer */
    // unsigned int consume_burst;

    // size_t elements;

    size_t produced; /**< count of elements produced by this worker */
    size_t consumed; /**< count of elements consumed by this worker */
    int finished;    /**< worker is marked as finished and ready to clean */

    struct cne_ring *r;
    tst_info_t *tst;

    void *pvt;

    worker_join_fn join;     /**< wait for worker to finish and get result information*/
    worker_stop_fn stop;     /**< signal worker that it should stop */
    worker_cancel_fn cancel; /**< stop worker */
    worker_free_fn free;     /**< free worker memory */
};

struct worker_thread_state;

/** function which is run for worker */
typedef int (*worker_fn)(struct worker_thread_state *test);
/** function used by worker to exit */
typedef int (*worker_exit_fn)(struct worker_thread_state *ws);

/**
 * Structure used to store internal worker thread information.
 */
struct worker_thread_state {
    pthread_t id;
    int read_fd;  /** message pipe from supervisor to worker */
    int write_fd; /** message pipe from worker to supervisor */

    int stop;
    int finished;

    unsigned int elements;

    unsigned int produce_burst;
    unsigned int consume_burst;

    size_t produced;
    size_t consumed;

    struct cne_ring *r;
    tst_info_t *tst;

    worker_fn function;
    struct worker_args args;

    worker_exit_fn exit; /**< exit worker */
};

static int
worker_close(struct worker_thread_state *ws, int fd)
{
    if (verbose)
        cne_printf("%s: id:%lu close(%d)\n", __func__, (uintptr_t)ws->id, fd);
    return close(fd);
}

/********************************/
/* supervisor protocol messages */
/********************************/
enum supervisor_msg_type {
    CNE_SMT_FINISHED,
    CNE_SMT_DONE,
};

struct worker_finished_msg {
    uint8_t type; /* always worker_finished */
    uint8_t result;
    uintptr_t id;
    uint32_t produced; /* count of messages enqueued */
    uint32_t consumed; /* count of messages dequeued */
};

struct worker_done_msg {
    uint8_t type; /* always worker_done */
    uintptr_t id;
    uint32_t produced; /* count of messages enqueued */
    uint32_t consumed; /* count of messages dequeued */
};

union supervisor_msg {
    uint8_t type;
    struct worker_finished_msg fin;
    struct worker_done_msg done;
};

/*****************************/
/* worker protocol messages  */
/*****************************/
enum worker_msg_type {
    CNE_WMT_STOP,
};

struct worker_stop_msg {
    uint8_t type; /* always CNE_WMT_STOP */
    uint8_t reason;
    uintptr_t id;
};

union worker_msg {
    uint8_t type;
    struct worker_stop_msg stop;
};

static int
worker_thread_exit(struct worker_thread_state *ws)
{
    if (ws->id == pthread_self()) {
        worker_close(ws, ws->read_fd);
        worker_close(ws, ws->write_fd);
        pthread_exit(ws);
    }
    cne_exit("Exit called outside of current thread id:%lu self:%lu\n", (uintptr_t)ws->id,
             (uintptr_t)pthread_self());
    return -1;
}

static int
supervisor_worker_thread_cancel(struct worker_info *wi)
{
    if (wi->id.thread == pthread_self()) {
        cne_exit("Cancel called for self\n");
    }
    return pthread_cancel(wi->id.thread);
}

static int
worker_stop(struct worker_info *wi, uint8_t reason)
{
    struct worker_stop_msg msg;
    size_t written;

    cne_printf("############################## STOP wi:%p id:%" PRIuPTR "\n", wi, wi->id.num);

    msg.type   = CNE_WMT_STOP;
    msg.reason = reason;
    msg.id     = wi->id.num;

    written = write(wi->write_fd, &msg, sizeof(msg));

    return written;
}

static void
process_stop_message(struct worker_thread_state *ws, struct worker_stop_msg *msg)
{
    int reason = 1;

    if (!ws) {
        tst_error("Invalid thread info for worker id\n");
        return;
    }

    if ((uintptr_t)ws->id != msg->id) {
        tst_error("Wrong worker id=%" PRIuPTR " passed. current id=%" PRIuPTR "\n", msg->id,
                  ws->id);
        return;
    }
    if (msg->reason != 0)
        reason = msg->reason;

    cne_printf("%s: reason:%d\n", __func__, reason);

    ws->stop = reason;
}

static int
worker_thread_join(struct worker_info *wi)
{
    void *ret;
    int err = pthread_join(wi->id.thread, &ret);

    worker_close((struct worker_thread_state *)(wi->pvt), wi->read_fd);
    wi->read_fd = -1;
    worker_close((struct worker_thread_state *)(wi->pvt), wi->write_fd);
    wi->write_fd = -1;

    wi->id.num = 0;

    if (err)
        tst_error("join worker=%" PRIuPTR " error=%d: %s\n", wi->id.num, err, strerror(err));

    return err;
}

static void
process_supervisor_message(struct worker_thread_state *ws)
{
    union worker_msg msg;
    int n;

    n = read(ws->read_fd, &msg, 1);
    if (n <= 0) {
        int err = errno;
        if (n != 0)
            tst_error("Error=%d reading message: %s\n", err, strerror(err));
        ws->exit(ws);
    }

    cne_printf("----------> %s: msg.type:%d\n", __func__, msg.type);

    switch (msg.type) {
    case CNE_WMT_STOP:
        n = read(ws->read_fd, ((char *)&msg) + 1, sizeof(struct worker_stop_msg) - 1);
        process_stop_message(ws, &msg.stop);
        break;
    }
}

/* handle messages from worker to supervisor */

static void
process_finished_message(struct worker_info *wi, struct worker_finished_msg *msg)
{
    wi->produced = msg->produced;
    wi->consumed = msg->consumed;
    wi->finished = 1;
}

static void
process_done_message(struct worker_info *wi, struct worker_done_msg *msg)
{
    wi->produced = msg->produced;
    wi->consumed = msg->consumed;
}

/**
 * Function to handle messages received from worker
 */
static void
process_worker_message(struct worker_info *wi)
{
    union supervisor_msg msg;
    ssize_t n;

    n = read(wi->read_fd, &msg, 1);
    if (n <= 0) {
        if (n != 0)
            tst_error("Error=%d reading message: %s\n", errno, strerror(errno));
        wi->cancel(wi);
    }

    switch (msg.type) {
    case CNE_SMT_FINISHED:
        n += read(wi->read_fd, ((char *)&msg) + 1, sizeof(struct worker_finished_msg) - 1);
        if (n != sizeof(struct worker_finished_msg))
            cne_printf("%s: fd:%d n:%zd sz:%zu\n", __func__, wi->read_fd, n,
                       sizeof(struct worker_finished_msg));
        process_finished_message(wi, &msg.fin);
        break;
    case CNE_SMT_DONE:
        n += read(wi->read_fd, ((char *)&msg) + 1, sizeof(struct worker_done_msg) - 1);
        if (n != sizeof(struct worker_done_msg))
            cne_printf("%s: fd:%d n:%zd sz:%zu\n", __func__, wi->read_fd, n,
                       sizeof(struct worker_done_msg));
        process_done_message(wi, &msg.done);
        break;
    }
}

static int
producer(struct worker_thread_state *test)
{
    unsigned enq_cnt;
    uint64_t enq_obj[1024];
    unsigned int burst_size;
    unsigned int free_space;

    if (!test)
        return -1;

    if (test->produce_burst == 0) {
        test->finished = 1;
        return 0;
    } else
        burst_size = test->produce_burst;
    if (test->elements == 0) {
        test->finished = 2;
        return 0;
    }
    if (burst_size > test->elements)
        burst_size = test->elements;

    free_space = cne_ring_free_count(test->r);
    if (burst_size > free_space)
        burst_size = free_space;

    if (!test->args.fn.enqueue_bulk || test->args.fn_type != enqueue_bulk) {
        tst_error("Wrong enqueue function passed fn_type=%d fn=%p\n", test->args.fn_type,
                  test->args.fn.dequeue_bulk);
        test->finished = 3;
        return 0;
    }

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, test->r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
        cne_printf("%s: produce_burst:%d id:%lu produced:%zu\n", __func__, test->produce_burst,
                   (uintptr_t)test->id, test->produced);
    }
    enq_cnt = test_ring_fill_object_range(enq_obj, burst_size, (uint32_t)(uintptr_t)test->id,
                                          test->produced);
    enq_cnt = test->args.fn.enqueue_bulk(test->r, (void **)enq_obj, enq_cnt, &free_space);
    test->elements -= enq_cnt;
    test->produced += enq_cnt;

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_printf("%s: enq_cnt:%d burst_size:%d id:%lu produced:%zu\n", __func__, enq_cnt,
                   burst_size, (uintptr_t)test->id, test->produced);
        cne_ring_dump(NULL, test->r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }

    if (test->elements <= 0)
        test->finished = 1;

    return enq_cnt;
}

static int
consumer(struct worker_thread_state *test)
{
    uint64_t deq_obj[1024];
    unsigned int available;
    unsigned int burst_size;
    unsigned int deq_cnt;

    if (!test)
        return -1;

    if (test->consume_burst == 0) {
        test->finished = 1;
        return 0;
    } else
        burst_size = test->consume_burst;

    available = cne_ring_count(test->r);
    if (burst_size > available)
        burst_size = available;
    if (burst_size > test->elements)
        burst_size = test->elements;

    if (!test->args.fn.dequeue_bulk || test->args.fn_type != dequeue_bulk) {
        tst_error("Wrong dequeue function passed fn_type=%d fn=%p\n", test->args.fn_type,
                  test->args.fn.dequeue_bulk);
        test->finished = 1;
        return 0;
    }

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_ring_dump(NULL, test->r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }

    deq_cnt = test->args.fn.dequeue_bulk(test->r, (void **)deq_obj, burst_size, &available);
    test->elements -= deq_cnt;
    test->consumed += deq_cnt;

    if (verbose) {
        vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
        cne_printf("%s: deq_cnt:%d burst_size:%d id:%lu elements:%u consumed:%zu available:%d\n",
                   __func__, deq_cnt, burst_size, (uintptr_t)test->id, test->elements,
                   test->consumed, available);
        cne_ring_dump(NULL, test->r);
        cne_printf("\n");
        vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    }

    if (test->elements <= 0)
        test->finished = 1;

    return deq_cnt;
}

static void
test_ring_threaded_cleanup(struct test_ring_progress_info *tst)
{
    struct worker_info *worker, *worker_next;

    if (!tst)
        return;

    TAILQ_FOREACH_SAFE (worker, &tst->worker_list, next, worker_next) {
        worker->stop(worker, 2);
        worker->join(worker);
        TAILQ_REMOVE(&tst->worker_list, worker, next);
        if (worker->producer)
            tst->total_produced += worker->produced;
        if (worker->consumer)
            tst->total_consumed += worker->consumed;

        worker->free(worker);
    }
    vt_color(VT_GREEN, VT_NO_CHANGE, VT_OFF);
    cne_printf("%s: Total produced=%zu consumed=%zu\n", __func__, tst->total_produced,
               tst->total_consumed);
    vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
    if (tst->r) {
        cne_ring_free(tst->r);
        tst->r = 0;
    }
    if (tst->tst) {
        tst_end(tst->tst, TST_FAILED);
        tst->tst = 0;
    }
}

static int
worker_send_done(struct worker_thread_state *ws)
{
    ssize_t cnt;
    struct worker_done_msg msg = {.type     = CNE_SMT_DONE,
                                  .id       = (uintptr_t)ws->id,
                                  .produced = ws->produced,
                                  .consumed = ws->consumed};

    cnt = write(ws->write_fd, &msg, sizeof(struct worker_done_msg));
    if (cnt == -1)
        cne_exit("Error=%d writing message: %s\n", errno, strerror(errno));
    if (cnt != sizeof(struct worker_done_msg))
        cne_exit("Error writing message cnt:%zu != %zu\n", cnt, sizeof(struct worker_done_msg));

    return cnt;
}

static void *
test_ring_thread(void *args)
{
    struct worker_thread_state *ws = (struct worker_thread_state *)args;
    ssize_t cnt;
    int epfd;
    int rdy;
    struct epoll_event ev;
    union supervisor_msg msg;

    if (!ws)
        return 0;
    epfd = epoll_create(1);
    if (epfd == -1) {
        perror("epoll_create");
        return 0;
    }

    ev.events  = EPOLLIN;
    ev.data.fd = ws->read_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, ws->read_fd, &ev);
    ev.data.fd = EPOLLOUT;
    epoll_ctl(epfd, EPOLL_CTL_ADD, ws->write_fd, &ev);

    do {
        ws->function(ws);

        // cne_printf("Done test function ws:%p id:%"PRIuPTR"\n", ws, ws->id);
        rdy = epoll_wait(epfd, &ev, 2, 0);
        for (int i = 0; i < rdy; i++) {
            if (ev.events & EPOLLIN) {
                process_supervisor_message(ev.data.ptr);
            } else if (ev.events & EPOLLHUP) {
                ws->finished = 1;
            } else if (ev.events & EPOLLERR) {
                ws->finished = 1;
            }
        }

        worker_send_done(ws);

        if (ws->stop)
            ws->finished = 1;
    } while (!ws->finished);

    epoll_ctl(epfd, EPOLL_CTL_DEL, ws->read_fd, &ev);

    rdy = epoll_wait(epfd, &ev, 1, 0);
    if (rdy) {
        msg.type         = CNE_SMT_FINISHED;
        msg.fin.id       = (uintptr_t)ws->id;
        msg.fin.produced = ws->produced;
        msg.fin.consumed = ws->consumed;

        cne_printf("%s: Worker finish id:%" PRIuPTR
                   " finished:%d msg.fin.produced=%d msg.fin.consumed=%d\n",
                   __func__, (uintptr_t)ws->id, ws->finished, msg.fin.produced, msg.fin.consumed);
        cnt = write(ws->write_fd, &msg, sizeof(struct worker_finished_msg));
        if (cnt == -1)
            tst_error("Error=%d writing message: %s\n", errno, strerror(errno));
    }

    worker_close(ws, ws->write_fd);
    worker_close(ws, ws->read_fd);
    worker_close(ws, epfd);

    return args;
}

static void
test_free_worker_thread(struct worker_info *wi)
{
    struct worker_thread_state *ts;

    if (wi) {
        ts = wi->pvt;
        if (wi->write_fd > 0)
            worker_close(ts, wi->write_fd);
        if (wi->read_fd > 0)
            worker_close(ts, wi->read_fd);
        free(wi);
    }
}

/**
 * create test worker and setup communication channel between creator and worker.
 */
static struct worker_info *
test_create_worker_thread(void)
{
    struct worker_info *wi = (struct worker_info *)calloc(
        1, sizeof(struct worker_info) + sizeof(struct worker_thread_state));

    if (!wi)
        return NULL;

    struct worker_thread_state *t = (struct worker_thread_state *)(&wi[1]);
    int ret;
    int pipe_fd[2];

    ret = pipe(pipe_fd);
    if (ret == -1)
        cne_exit("Error:%d create communication pipe: %s", errno, strerror(errno));
    wi->write_fd = pipe_fd[1];
    t->read_fd   = pipe_fd[0];
    ret          = pipe(pipe_fd);
    if (ret == -1)
        cne_exit("Error:%d create communication pipe: %s", errno, strerror(errno));
    wi->read_fd = pipe_fd[0];
    t->write_fd = pipe_fd[1];

    wi->join   = worker_thread_join;
    wi->stop   = worker_stop;
    wi->cancel = supervisor_worker_thread_cancel;
    wi->free   = test_free_worker_thread;

    t->stop     = 0;
    t->finished = 0;

    t->exit = worker_thread_exit;

    wi->pvt  = t;
    wi->type = wi_type_thread;

    return wi;
}

static int
test_ring_threaded(void *arg)
{
    int result                         = 0;
    struct test_ring_progress_info tst = {0};
    struct test_ring_api_cfg *test     = (struct test_ring_api_cfg *)arg;
    unsigned int ring_size             = RING_SIZE;
    int running                        = 0;
    struct timespec ts_start, ts_report, ts_now;
    uint32_t i;
    int epfd;

    memset(&ts_report, 0, sizeof(ts_report));

    if (verbose) {
        char print_buffer[1024];
        test_dump_cfg(print_buffer, sizeof(print_buffer), test);
        cne_printf("%s: '%s': %s\n", __func__, test->name, print_buffer);
    }

    if (!test)
        return -1;

    if (test->ring_args.count)
        ring_size = test->ring_args.count;
    if (test->producer_count == 0)
        test->producer_count = 1;
    if (test->consumer_count == 0)
        test->consumer_count = 1;
    if (test->elements == 0)
        test->elements = DEFAULT_ELEMENTS;

    cne_printf("%s: '%s': Create ring name='%s' esize=%u count=%u flags=%u\n", __func__, test->name,
               test->name, 0, ring_size, test->ring_args.flags);
    tst.r = cne_ring_create(test->name, 0, ring_size, test->ring_args.flags);
    TST_ASSERT_AND_CLEANUP(tst.r != NULL, "'%s': Ring create failed\n", test_ring_threaded_cleanup,
                           &tst, test->name);

    tst.tst = tst_start(test->name);

    epfd = epoll_create(test->producer_count + test->consumer_count);
    TST_ASSERT_AND_CLEANUP(epfd != -1, "'%s': epoll_create failed: %d %s\n",
                           test_ring_threaded_cleanup, &tst, test->name, errno, strerror(errno));

    TAILQ_INIT(&tst.worker_list);
    for (i = 0; i < test->producer_count; i++) {
        struct epoll_event ev = {EPOLLIN};
        struct worker_info *p = test_create_worker_thread();
        TST_ASSERT_AND_CLEANUP(p, "'%s': producer_info allocation failed\n",
                               test_ring_threaded_cleanup, &tst, test->name);
        struct worker_thread_state *t = p->pvt;
        TST_ASSERT_AND_CLEANUP(t, "'%s': worker_thread_state allocation failed\n",
                               test_ring_threaded_cleanup, &tst, test->name);
        p->r   = tst.r;
        p->tst = tst.tst;

        t->r                    = tst.r;
        t->function             = producer;
        t->args.fn_type         = enqueue_bulk;
        t->args.fn.enqueue_bulk = test->enqueue;
        t->elements             = test->elements;
        t->produce_burst        = test->producer_bulk ? test->producer_bulk : BULK_SIZE;

        TAILQ_INSERT_TAIL(&tst.worker_list, p, next);
        TST_ASSERT_AND_CLEANUP(0 == pthread_create(&t->id, 0, test_ring_thread, p->pvt),
                               "'%s': producer thread create failed\n", test_ring_threaded_cleanup,
                               &tst, test->name);
        p->id.thread = t->id;

        ev.data.ptr = p;
        epoll_ctl(epfd, EPOLL_CTL_ADD, p->read_fd, &ev);
    }

    size_t consumer_elements     = (i * test->elements) / test->consumer_count;
    size_t consumer_elements_mod = (i * test->elements) % test->consumer_count;
    for (i = 0; i < test->consumer_count; i++) {
        struct epoll_event ev = {EPOLLIN};
        struct worker_info *c = test_create_worker_thread();
        if (!c) {
            result = -1;
            goto end;
        }
        struct worker_thread_state *t = c->pvt;

        TST_ASSERT_AND_CLEANUP(c && t, "'%s': consumer_info allocation failed\n",
                               test_ring_threaded_cleanup, &tst, test->name);
        c->r   = tst.r;
        c->tst = tst.tst;

        t->r                    = tst.r;
        t->function             = consumer;
        t->args.fn_type         = dequeue_bulk;
        t->args.fn.dequeue_bulk = test->dequeue;
        t->consume_burst        = test->consumer_bulk ? test->consumer_bulk : BULK_SIZE;
        t->elements             = consumer_elements;
        if (i == 0)
            t->elements += consumer_elements_mod;

        TAILQ_INSERT_TAIL(&tst.worker_list, c, next);
        TST_ASSERT_AND_CLEANUP(0 == pthread_create(&t->id, 0, test_ring_thread, t),
                               "'%s': consumer thread create failed\n", test_ring_threaded_cleanup,
                               &tst, test->name);
        c->id.thread = t->id;

        ev.data.ptr = c;
        epoll_ctl(epfd, EPOLL_CTL_ADD, c->read_fd, &ev);
    }

    if (clock_gettime(CLOCK_MONOTONIC, &ts_start) == -1)
        cne_exit("clock_gettime: errno:%d %s\n", errno, strerror(errno));

    int count = 0;
    do {
        int timeout = 100;
        double duration;
        struct epoll_event events[100];
        struct worker_info *worker, *worker_tmp;
        int fd_count;

        if (clock_gettime(CLOCK_MONOTONIC, &ts_now) == -1)
            cne_exit("clock_gettime: errno:%d %s\n", errno, strerror(errno));

        duration = (ts_now.tv_sec - ts_report.tv_sec) * 1e9;
        duration = (duration + (ts_now.tv_nsec - ts_report.tv_nsec)) * 1e-9;
        if (duration > 2) {
            size_t consumed = 0, produced = 0;
            /* print report every second */
            if (verbose) {
                vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
                cne_ring_dump(NULL, tst.r);
                cne_printf("\n");
                vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
            }
            cne_printf("------------------------------\n# '%s': time: {%lds, %ldns}\n", test->name,
                       ts_now.tv_sec, ts_now.tv_nsec);
            TAILQ_FOREACH (worker, &tst.worker_list, next) {
                cne_printf("## '%s': worker id:%lu produced:%zu consumed:%zu\n", test->name,
                           worker->id.num, worker->produced, worker->consumed);
                consumed += worker->consumed;
                produced += worker->produced;
            }
            cne_printf("# '%s': total produced:%zu consumed:%zu\n------------------------------\n",
                       test->name, produced, consumed);
            count++;
            if (clock_gettime(CLOCK_MONOTONIC, &ts_report) == -1)
                cne_exit("clock_gettime: errno:%d %s\n", errno, strerror(errno));
        }

        if (count > 30) {
            duration = (ts_now.tv_sec - ts_start.tv_sec) * 1e9;
            duration = (duration + (ts_now.tv_nsec - ts_start.tv_nsec)) * 1e-9;
            cne_printf(
                "------------------------------\n'%s': count:%d duration:%f\nSending STOP to all "
                "workers\n------------------------------\n",
                test->name, count, duration);
            TAILQ_FOREACH (worker, &tst.worker_list, next) {
                worker->stop(worker, 10);
            }
        }

        fd_count = epoll_wait(epfd, events, cne_countof(events), timeout);
        for (int i = 0; i < fd_count; i++) {
            struct worker_info *wi = events[i].data.ptr;
            if (events[i].events & EPOLLIN)
                process_worker_message(wi);
            else if (events[i].events & EPOLLHUP) {
                wi->finished = 1;
            }
        }

        // cne_printf("------------------------------\nCleanup finished
        // workers\n------------------------------\n");
        TAILQ_FOREACH_SAFE (worker, &tst.worker_list, next, worker_tmp) {
            if (worker->finished) {
                cne_printf(">> '%s': Worker finished id:%" PRIuPTR
                           " produced:%zu consumed:%zu result:%d\n",
                           test->name, worker->id.num, worker->produced, worker->consumed,
                           worker->result);
                worker->join(worker);
                TAILQ_REMOVE(&tst.worker_list, worker, next);

                tst.total_produced += worker->produced;
                tst.total_consumed += worker->consumed;

                epoll_ctl(epfd, EPOLL_CTL_DEL, worker->read_fd, 0);
                worker->free(worker);
            } else
                running++;
        }
        if (TAILQ_EMPTY(&tst.worker_list))
            running = 0;

    } while (running);
    tst_ok("%s: test:'%s' done produced:%zu consumed:%zu\n", __func__, tst.tst->name,
           tst.total_produced, tst.total_consumed);

end:
    close(epfd);
    tst_end(tst.tst, result == 0 ? TST_PASSED : TST_FAILED);
    cne_ring_free(tst.r);

    return result;
}

static struct test_ring_api_cfg *
find_test_by_name(struct test_ring_api_cfg *tests, size_t tests_n, char const *name)
{
    size_t tst_idx                = 0;
    struct test_ring_api_cfg *tst = NULL;

    if (!tests)
        return NULL;
    if (!name)
        return NULL;

    for (tst_idx = 0; tst_idx < tests_n; tst_idx++) {
        if (tests[tst_idx].name[0] == '\0')
            continue;
        if (!strncmp(tests[tst_idx].name, name, sizeof(tst[tst_idx].name))) {
            tst = &tests[tst_idx];
            break;
        }
    }
    return tst;
}

int
ring_api_main(int argc, char **argv)
{
    int opt;
    char **argvopt;
    int option_index;
    int idx;
    int result                       = 0;
    size_t tst_idx                   = 0;
    struct test_ring_api_cfg tests[] = {
        /* bulk */
        {"bulk", cne_ring_enqueue_bulk, cne_ring_dequeue_bulk, .elements = 111, .producer_bulk = 10,
         .consumer_bulk = 5, .consumer_count = 2},
        /* single object bulk size */
        {"bulk bulk=1",
         cne_ring_enqueue_bulk,
         cne_ring_dequeue_bulk,
         {0, 2048},
         .producer_bulk = 1},
        /* SP bulk */
        {"sp_bulk", cne_ring_enqueue_bulk, cne_ring_dequeue_bulk,
         .ring_args = {.flags = RING_F_SP_ENQ}, .consumer_count = 2},
        /* sc bulk */
        {"sc_bulk", cne_ring_enqueue_bulk, cne_ring_dequeue_bulk, {RING_F_SC_DEQ}},
        /* sp/sc bulk */
        {"sp/sc_bulk",
         cne_ring_enqueue_bulk,
         cne_ring_dequeue_bulk,
         {RING_F_SP_ENQ | RING_F_SC_DEQ}},
        /* EXACT bulk */
        {"exact bulk", cne_ring_enqueue_bulk, cne_ring_dequeue_bulk, {RING_F_EXACT_SZ, 2000}},
        /* wrong create size */
        {"bulk cnt=2000", .ring_args = {0, 2000}, .should_fail = 1},
        {
            "blk",
            cne_ring_enqueue_bulk,
            cne_ring_dequeue_bulk,
            .ring_args      = {.flags = RING_F_SC_DEQ | RING_F_SP_ENQ},
            .elements       = 10000,
            .producer_count = 1,
            .consumer_count = 1,
            .producer_bulk  = 50,
            .consumer_bulk  = 50,
        },
        {
            "blk 2p 2c",
            cne_ring_enqueue_bulk,
            cne_ring_dequeue_bulk,
            .elements       = 10000,
            .producer_count = 2,
            .consumer_count = 2,
            .producer_bulk  = 50,
            .consumer_bulk  = 50,
        },
        {
            "blk 3p 3c",
            cne_ring_enqueue_bulk,
            cne_ring_dequeue_bulk,
            .elements       = 1000000,
            .producer_count = 1,
            .consumer_count = 3,
            .producer_bulk  = 50,
            .consumer_bulk  = 50,
        },
        {
            "blk ring=131072 2p 1c",
            cne_ring_enqueue_bulk,
            cne_ring_dequeue_bulk,
            .ring_args      = {.count = 131072},
            .elements       = 10000000,
            .producer_count = 2,
            .producer_bulk  = 100,
            .consumer_count = 1,
            .consumer_bulk  = 100,
        },
        {
            "blk 1 ring=131072 2p 1c",
            cne_ring_enqueue_bulk,
            cne_ring_dequeue_bulk,
            .ring_args      = {.count = 131072, .flags = RING_F_SC_DEQ},
            .elements       = 10000000,
            .producer_count = 2,
            .producer_bulk  = 100,
            .consumer_count = 1,
            .consumer_bulk  = 100,
        },

        /* burst */
        {"burst", cne_ring_enqueue_burst, cne_ring_dequeue_burst, .producer_count = 20,
         .consumer_count = 20, .producer_bulk = 20, .consumer_bulk = 20},
        /* SP burst */
        {"sp_burst", cne_ring_enqueue_burst, cne_ring_dequeue_burst,
         .ring_args = {.flags = RING_F_SP_ENQ}, .consumer_count = 2},
        /* sc burst */
        {"sc_burst", cne_ring_enqueue_burst, cne_ring_dequeue_burst, {RING_F_SC_DEQ}},
        /* sp/sc burst */
        {"sp/sc_burst",
         cne_ring_enqueue_burst,
         cne_ring_dequeue_burst,
         {RING_F_SP_ENQ | RING_F_SC_DEQ}},
        /* EXACT burst */
        {"exact burst", cne_ring_enqueue_burst, cne_ring_dequeue_burst, {RING_F_EXACT_SZ, 2000}},
        {
            "burst",
            cne_ring_enqueue_burst,
            cne_ring_dequeue_burst,
            .elements       = 10000,
            .producer_count = 1,
            .consumer_count = 1,
            .producer_bulk  = 50,
            .consumer_bulk  = 50,
        },
        {
            "burst 2p 2c",
            cne_ring_enqueue_burst,
            cne_ring_dequeue_burst,
            .elements       = 10000,
            .producer_count = 2,
            .consumer_count = 2,
            .producer_bulk  = 50,
            .consumer_bulk  = 50,
        },
        {
            "burst 3p 3c",
            cne_ring_enqueue_burst,
            cne_ring_dequeue_burst,
            .elements       = 1000000,
            .producer_count = 1,
            .consumer_count = 3,
            .producer_bulk  = 50,
            .consumer_bulk  = 50,
        },
        {
            "brst ring=131072 2p 1c",
            cne_ring_enqueue_burst,
            cne_ring_dequeue_burst,
            .ring_args      = {.count = 131072},
            .elements       = 10000000,
            .producer_count = 2,
            .producer_bulk  = 100,
            .consumer_count = 1,
            .consumer_bulk  = 100,
        },
        {
            "brst ring=131072 2p 1c",
            cne_ring_enqueue_burst,
            cne_ring_dequeue_burst,
            .ring_args      = {.count = 131072, .flags = RING_F_SC_DEQ},
            .elements       = 10000000,
            .producer_count = 2,
            .producer_bulk  = 100,
            .consumer_count = 1,
            .consumer_bulk  = 100,
        },
        /* internal API functions */
        /* multi producer/consumer */
        {"m_bulk", cne_ring_mp_enqueue_bulk, cne_ring_mc_dequeue_bulk},
        {"m_bulk bulk=1",
         cne_ring_mp_enqueue_bulk,
         cne_ring_mc_dequeue_bulk,
         {0, 2048},
         .producer_bulk = 1},
        {"sp_m_bulk", cne_ring_mp_enqueue_bulk, cne_ring_mc_dequeue_bulk},
        {"sc_m_bulk", cne_ring_mp_enqueue_bulk, cne_ring_mc_dequeue_bulk},
        {"sp/sc_m_bulk", cne_ring_mp_enqueue_bulk, cne_ring_mc_dequeue_bulk},
        {"exact m_bulk", cne_ring_mp_enqueue_bulk, cne_ring_mc_dequeue_bulk,
         .ring_args = {.flags = RING_F_EXACT_SZ, .count = 2000}, .producer_count = 4,
         .consumer_count = 20, .producer_bulk = 100, .consumer_bulk = 20},

        {"m_burst", cne_ring_mp_enqueue_burst, cne_ring_mc_dequeue_burst},
        {"sc_m_burst", cne_ring_mp_enqueue_burst, cne_ring_mc_dequeue_burst},
        {"sm_burst", cne_ring_mp_enqueue_burst, cne_ring_mc_dequeue_burst},
        {"exact m_burst", cne_ring_mp_enqueue_burst, cne_ring_mc_dequeue_burst,
         .ring_args = {.flags = RING_F_EXACT_SZ, .count = 2000}, .producer_count = 4,
         .consumer_count = 20, .producer_bulk = 100, .consumer_bulk = 20},

        /* single producer/consumer */
        {"s_bulk",
         cne_ring_sp_enqueue_bulk,
         cne_ring_sc_dequeue_bulk,
         {.flags = RING_F_SP_ENQ | RING_F_SC_DEQ}},
        {"s_bulk bulk=1",
         cne_ring_sp_enqueue_bulk,
         cne_ring_sc_dequeue_bulk,
         {.flags = RING_F_SP_ENQ | RING_F_SC_DEQ},
         .producer_bulk = 1},
        {"sc_s_bulk",
         cne_ring_sp_enqueue_bulk,
         cne_ring_sc_dequeue_bulk,
         {.flags = RING_F_SP_ENQ | RING_F_SC_DEQ}},
        {"exact s_bulk",
         cne_ring_sp_enqueue_bulk,
         cne_ring_sc_dequeue_bulk,
         {.flags = RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ, .count = 2000}},

        {"s_burst",
         cne_ring_sp_enqueue_burst,
         cne_ring_sc_dequeue_burst,
         {.flags = RING_F_SP_ENQ | RING_F_SC_DEQ}},
        {"s_burst burst=1", cne_ring_sp_enqueue_burst, cne_ring_sc_dequeue_burst,
         .ring_args = {.flags = RING_F_SP_ENQ | RING_F_SC_DEQ}, .producer_bulk = 1},
        {"sp/sc_s_burst", cne_ring_sp_enqueue_burst, cne_ring_sc_dequeue_burst,
         .ring_args = {.flags = RING_F_SP_ENQ | RING_F_SC_DEQ}},
        {"exact s_burst", cne_ring_sp_enqueue_burst, cne_ring_sc_dequeue_burst,
         .ring_args = {.flags = RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ, .count = 2000}},
    };

    static const struct option lgopts[] = {{"verbose", no_argument, &verbose, 1},
                                           {"list", no_argument, &opt_list_tests, 1},
                                           {"help", no_argument, &help, 1},
                                           {"all", no_argument, &opt_run_all, 1},
                                           {NULL, 0, 0, 0}};

    verbose        = 0;
    help           = 0;
    opt_list_tests = 0;
    opt_run_all    = 0;

    argvopt = argv;

    optind = 0;
    opterr = 0;
    while ((opt = getopt_long_only(argc, argvopt, "Vlha", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'h':
            help = 1;
            break;
        case 'l':
            opt_list_tests = 1;
            break;
        case 'a':
            opt_run_all = 1;
            break;
        case 'V':
            verbose = 1;
            break;
        case ':':
            fprintf(stderr, "Option %c requires an argument\n", optopt);
            break;
        case '?':
            fprintf(stderr, "Unknown option -%c\n", optopt);
            break;
        default:
            break;
        }
    }

    if (help) {
        fprintf(stdout, "Run ring_api test with parameters:\n"
                        "\t--list - list tests which can be use as positional argument to run\n"
                        "\t--all - run all available tests. If no positional test name passed then "
                        "by default all tests are run\n"
                        "\t-V - run verbose\n"
                        "\t--help - print this help message\n");
        return 1;
    }

    fprintf(stdout, "option_index=%d argc=%d opt_run_all=%d verbose=%d\n", option_index, argc,
            opt_run_all, verbose);
    if (opt_list_tests) {
        fprintf(stdout, "listing available tests:");
        for (tst_idx = 0; tst_idx < cne_countof(tests); tst_idx++) {
            fprintf(stdout, "%s\n", tests[tst_idx].name);
        }
        return 1;
    }

    /* search for all option */
    if (optind == argc) {
        opt_run_all = 1;
    } else {
        for (idx = optind; idx < argc; idx++) {
            if (!strncmp(argv[idx], "api", strlen(argv[idx]))) {
            }
            if (!strncmp(argv[idx], "all", strlen(argv[idx]))) {
                fprintf(stdout, "Option %d -> %s\n", idx, argv[idx]);
                opt_run_all = 1;
            }
        }
    }

    fprintf(stdout, "option_index=%d argc=%d opt_run_all=%d verbose=%d\n", option_index, argc,
            opt_run_all, verbose);
    if (option_index == argc || opt_run_all) {
        fprintf(stdout, "Running all test\n");
        for (tst_idx = 0; tst_idx < cne_countof(tests); tst_idx++) {
            tests[tst_idx].run    = 1;
            tests[tst_idx].result = test_ring_threaded(&tests[tst_idx]);
        }
    } else {
        for (option_index = optind; option_index < argc; option_index++) {
            fprintf(stdout, "Running test %s\n", argv[option_index]);
            struct test_ring_api_cfg *tst =
                find_test_by_name(tests, cne_countof(tests), argv[option_index]);
            if (tst) {
                tst->result = test_ring_threaded(tst);
            } else {
                fprintf(stdout, "No test named '%s' found\n", argv[option_index]);
            }
        }
    }

    for (tst_idx = 0; tst_idx < cne_countof(tests); tst_idx++) {
        if (tests[tst_idx].run) {
            if (tests[tst_idx].result && !tests[tst_idx].should_fail) {
                result = tests[tst_idx].result;
                tst_error("Error in test name='%s' err=%d\n", tests[tst_idx].name,
                          tests[tst_idx].result);
            }
        }
    }

    return result;
}
