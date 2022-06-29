/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2020 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>               // for NULL, snprintf, EOF
#include <getopt.h>              // for getopt_long, option
#include <tst_info.h>            // for tst_end, tst_error, tst_start, TST_FAILED
#include <cne_common.h>          // for CNE_USED, __cne_cache_aligned, __cne_u...
#include <stdatomic.h>           // for atomic_store, atomic_bool, atomic_load
#include <cne_log.h>             // for CNE_LOG_ERR, CNE_ERR, CNE_ERR_GOTO
#include <cne.h>                 // for cne_max_threads
#include <cthread_api.h>         // for cthread_create, cthread_detach, cthrea...
#include <pthread.h>             // for pthread_create, pthread_join, pthread_...
#include <stdbool.h>             // for true
#include <stdint.h>              // for uint64_t
#include <stdlib.h>              // for atoi, calloc
#include <string.h>              // for memset
#include <cthread_sema.h>        // for cthread_sema_init, cthread_sema_reset, ..

#include "cthread_test.h"
#include "cne_cycles.h"        // for cne_rdtsc
#include "cne_stdio.h"         // for cne_printf
#include "cne_system.h"        // for cne_get_timer_hz

#define THREAD_WAIT_TIME     5
#define DEFAULT_THREAD_COUNT 2
#define CTHREAD_TYPE         0
#define PTHREAD_TYPE         1

typedef struct {
    uint64_t begin, end;
    uint64_t cnt;
    pthread_t pthd;
    struct cthread *cthd;
} thread_data_t __cne_cache_aligned;

static thread_data_t *data;
static int thread_cnt  = DEFAULT_THREAD_COUNT;
static int thread_time = THREAD_WAIT_TIME;
static atomic_bool failed;

static void
cthread_Tester(void *arg)
{
    thread_data_t *d = arg;

    d->begin = cne_rdtsc();
    d->end   = d->begin + (cne_get_timer_hz() * thread_time);

    while (cne_rdtsc() < d->end) {
        cthread_yield();
        d->cnt++;
    }
}

static void *
pthread_Tester(void *arg)
{
    thread_data_t *d = arg;

    d->begin = cne_rdtsc();
    d->end   = d->begin + (cne_get_timer_hz() * thread_time);

    while (cne_rdtsc() < d->end) {
        sched_yield();
        d->cnt++;
    }
    return NULL;
}

static void
print_data(int type)
{
    for (int i = 0; i < thread_cnt; i++) {
        thread_data_t *d = &data[i];
        cne_printf("  [green]Finished [yellow]%s [magenta]%d [green]count [red]%10ld[], "
                   "[green]cycles per loop [red]%6ld[]\n",
                   (type == CTHREAD_TYPE) ? "cthread" : "pthread", i, d->cnt,
                   (d->end - d->begin) / d->cnt);
    }
}

static int
cthread_sema_tests(void)
{
    struct cthread_sema *s, sema = {0};
    const char *sema_name    = "testcne semaphore";
    struct timespec waittime = {.tv_sec = 5};
    int ret                  = 0;

    s = &sema;

    ret = cthread_sema_init(sema_name, &s, NULL);
    if (ret < 0) {
        ret = errno;
        tst_error("Unable to initialize a semaphore, %s\n", strerror(errno));
        /* return errno if this test fails due to permission error */
        return (ret == EPERM) || (ret == EACCES) ? ret : -1;
    }

    tst_ok("PASS --- TEST: Initialize semaphore\n");

    ret = cthread_sema_reset(s);
    if (ret < 0) {
        tst_error("Unable to reset semaphore, %s\n", strerror(errno));
        goto err;
    }

    tst_ok("PASS --- TEST: Reset semaphore\n");

    ret = cthread_sema_timedwait(s, NULL, &waittime);
    if (ret < 0) {
        tst_error("Error waiting on semaphore, %s\n", strerror(errno));
        goto err;
    }

    tst_ok("PASS --- TEST: Timed wait on semaphore\n");

    ret = cthread_sema_signal(s);
    if (ret < 0) {
        tst_error("Error signaling semaphore, %s\n", strerror(errno));
        goto err;
    }

    tst_ok("PASS --- TEST: Signal semaphore\n");

    ret = cthread_sema_flush_no_sched(s);
    if (ret < 0) {
        tst_error("Error flushing semaphore w/o rescheduling threads, %s\n", strerror(errno));
        goto err;
    }

    tst_ok("PASS --- TEST: Flush semaphore, w/o rescheduling threads\n");

    ret = cthread_sema_flush(s);
    if (ret < 0) {
        tst_error("Error flushing semaphore, %s\n", strerror(errno));
        goto err;
    }

    tst_ok("PASS --- TEST: Flush semaphore\n");

    ret = cthread_sema_destroy(s);
    if (ret < 0) {
        tst_error("Unable to destroy semaphore, %s\n", strerror(errno));
        goto err;
    }

    tst_ok("PASS --- TEST: Destroy semaphore\n");

    return 0;

err:
    if (s)
        cthread_sema_destroy(s);

    return -1;
}

static int
cthread_start_threads(void)
{
    char name[32];
    tst_info_t *tst;
    int err = 0;

    for (int i = 0; i < thread_cnt; i++) {
        thread_data_t *d = &data[i];

        cne_printf("[green]Create [yellow]cthread [magenta]%3d [green]Started\n", i);

        snprintf(name, sizeof(name), "cthread-%d", i);
        d->cthd = cthread_create(name, cthread_Tester, (void *)d);
        if (d->cthd == NULL) {
            tst_error("%s cthread_create() failed\n", name);
            atomic_store(&failed, true);
            return -1;
        }
    }

    for (int i = 0; i < thread_cnt; i++)
        cthread_join(data[i].cthd, NULL);

    print_data(CTHREAD_TYPE);

    cne_printf("\n");
    tst = tst_start("Cthread Semaphore");

    err = cthread_sema_tests();
    if (err < 0)
        tst_end(tst, TST_FAILED);
    else if (err == EPERM || err == EACCES)
        tst_end(tst, TST_SKIPPED);
    else
        tst_end(tst, TST_PASSED);

    return err < 0 ? -1 : 0;
}

static void
cthread_spawner(void *arg __cne_unused)
{
    cthread_detach();

    cthread_start_threads();
}

/*
 * Start main scheduler with initial lthread spawning rx and tx lthreads
 * (main_lthread_main).
 */
static void
cthread_main_spawner(void)
{
    memset(data, 0, (thread_cnt * sizeof(thread_data_t)));

    /* create a main thread to spawn the rest of the threads */
    if (cthread_create("Main", cthread_spawner, NULL) == NULL) {
        CNE_ERR("Unable to start main cthread spawner routine\n");
        atomic_store(&failed, true);
    }

    cthread_run();
}

static int
pthread_start_threads(void)
{
    for (int i = 0; i < thread_cnt; i++) {
        thread_data_t *d = &data[i];

        cne_printf("[green]Create [yellow]pthread [magenta]%d [green]Started\n", i);

        if (pthread_create(&d->pthd, NULL, pthread_Tester, (void *)d) < 0) {
            tst_error("pthread_create() failed\n");
            atomic_store(&failed, true);
            return -1;
        }
    }

    for (int i = 0; i < thread_cnt; i++)
        pthread_join(data[i].pthd, NULL);

    print_data(PTHREAD_TYPE);

    return 0;
}

/*
 * Start main scheduler with initial lthread spawning rx and tx lthreads
 * (main_lthread_main).
 */
static void
pthread_main_spawner(void)
{
    memset(data, 0, (thread_cnt * sizeof(thread_data_t)));

    if (pthread_start_threads() < 0) {
        CNE_ERR("Unable to start pthread_start_threads()\n");
        atomic_store(&failed, true);
    }
}

int
cthread_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    optind = 0;
    while ((opt = getopt_long(argc, argvopt, "Vn:t:", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'n':
            thread_cnt = atoi(optarg);
            if (thread_cnt > cne_max_threads())
                thread_cnt = cne_max_threads();
            break;
        case 't':
            thread_time = atoi(optarg);
            break;
        case 'V':
            verbose = 1;
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("cthread & pthread");

    data = calloc(thread_cnt, sizeof(thread_data_t));
    if (!data)
        CNE_ERR_GOTO(leave, "Unable to allocate thread_data_t\n");

    cne_printf("[green]Waiting [red]%d [green]seconds[]\n", thread_time);

    cthread_main_spawner();

    cne_printf("\n");
    pthread_main_spawner();

leave:
    if (atomic_load(&failed))
        tst_end(tst, TST_FAILED);
    else
        tst_end(tst, TST_PASSED);

    return 0;
}
