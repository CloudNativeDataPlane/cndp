/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#include "test.h"             // for TEST_FAILED, TEST_SUCCESS
#include "cne_stdio.h"        // for cne_printf

/*
 * Timer
 * =====
 *
 * #. Stress test 1.
 *
 *    The objective of the timer stress tests is to check that there are no
 *    race conditions in list and status management. This test launches,
 *    resets and stops the timer very often on many cores at the same
 *    time.
 *
 *    - Only one timer is used for this test.
 *    - On each core, the cne_timer_manage() function is called from the main
 *      loop every 3 microseconds.
 *    - In the main loop, the timer may be reset (randomly, with a
 *      probability of 0.5 %) 100 microseconds later on a random core, or
 *      stopped (with a probability of 0.5 % also).
 *    - In callback, the timer is can be reset (randomly, with a
 *      probability of 0.5 %) 100 microseconds later on the same core or
 *      on another core (same probability), or stopped (same
 *      probability).
 *
 * # Stress test 2.
 *
 *    The objective of this test is similar to the first in that it attempts
 *    to find if there are any race conditions in the timer library. However,
 *    it is less complex in terms of operations performed and duration, as it
 *    is designed to have a predictable outcome that can be tested.
 *
 *    - A set of timers is initialized for use by the test
 *    - All cores then simultaneously are set to schedule all the timers at
 *      the same time, so conflicts should occur.
 *    - Then there is a delay while we wait for the timers to expire
 *    - Then the main thread calls timer_manage() and we check that all
 *      timers have had their callbacks called exactly once - no more no less.
 *    - Then we repeat the process, except after setting up the timers, we have
 *      all cores randomly reschedule them.
 *    - Again we check that the expected number of callbacks has occurred when
 *      we call timer-manage.
 *
 * #. Basic test.
 *
 *    This test performs basic functional checks of the timers. The test
 *    uses four different timers that are loaded and stopped under
 *    specific conditions in specific contexts.
 *
 *    - Four timers are used for this test.
 *    - On each core, the cne_timer_manage() function is called from main loop
 *      every 3 microseconds.
 *
 *    The autotest python script checks that the behavior is correct:
 *
 *    - timer0
 *
 *      - At initialization, timer0 is loaded by the main core, on main core
 *        in "single" mode (time = 1 second).
 *      - In the first 19 callbacks, timer0 is reloaded on the same core,
 *        then, it is explicitly stopped at the 20th call.
 *      - At t=25s, timer0 is reloaded once by timer2.
 *
 *    - timer1
 *
 *      - At initialization, timer1 is loaded by the main core, on the
 *        main core in "single" mode (time = 2 seconds).
 *      - In the first 9 callbacks, timer1 is reloaded on another
 *        core. After the 10th callback, timer1 is not reloaded anymore.
 *
 *    - timer2
 *
 *      - At initialization, timer2 is loaded by the main core, on the
 *        main core in "periodical" mode (time = 1 second).
 *      - In the callback, when t=25s, it stops timer3 and reloads timer0
 *        on the current core.
 *
 *    - timer3
 *
 *      - At initialization, timer3 is loaded by the main core, on
 *        another core in "periodical" mode (time = 1 second).
 *      - It is stopped at t=25s by timer2.
 */

#include <stdio.h>             // for NULL, stdout
#include <string.h>            // for memset
#include <stdlib.h>            // for free, calloc, rand
#include <stdint.h>            // for uint64_t, int32_t, int64_t
#include <tst_info.h>          // for tst_error, tst_ok
#include <cne_common.h>        // for __cne_unused
#include <cne.h>               // for cne_id, cne_next_id, cne_initial_uid
#include <cne_cycles.h>        // for cne_rdtsc
#include <cne_timer.h>         // for cne_timer_manage, cne_timer_stop_sync, SINGLE
#include <cne_pause.h>         // for cne_pause
#include <cne_system.h>        // for cne_get_timer_hz
#include <cne_thread.h>        // for thread_create, thread_wait_all
#include <stdatomic.h>         // for atomic_int, atomic_store, atomic_load, atomi...
#include <unistd.h>            // for usleep

#include "timer_test.h"        // for test_timer

#define TEST_DURATION_S 5 /* in seconds */

#define CNE_LOGTYPE_TESTTIMER CNE_LOGTYPE_USER3

static volatile uint64_t end_time;
static volatile int test_failed;

struct mytimerinfo {
    struct cne_timer tim;
    unsigned id;
    unsigned count;
};

static struct mytimerinfo *mytiminfo;

static void timer_basic_cb(struct cne_timer *tim, void *arg);

static void
mytimer_reset(struct mytimerinfo *timinfo, uint64_t ticks, enum cne_timer_type type,
              unsigned tim_thread, cne_timer_cb_t fct)
{
    cne_timer_reset_sync(&timinfo->tim, ticks, type, tim_thread, fct, timinfo);
}

/* timer callback for stress tests */
static void
timer_stress_cb(__cne_unused struct cne_timer *tim, __cne_unused void *arg)
{
    long r;
    unsigned tid = cne_id();
    uint64_t hz  = cne_get_timer_hz();

    if (cne_timer_pending(tim))
        return;

    r = rand();
    if ((r & 0xff) == 0)
        mytimer_reset(&mytiminfo[0], hz, SINGLE, tid, timer_stress_cb);
    else if ((r & 0xff) == 1)
        mytimer_reset(&mytiminfo[0], hz, SINGLE, cne_next_id(tid, 1, 1), timer_stress_cb);
    else if ((r & 0xff) == 2)
        cne_timer_stop(&mytiminfo[0].tim);
}

static void
timer_stress_initial_loop(__cne_unused void *arg)
{
    uint64_t hz = cne_get_timer_hz();
    int tid     = cne_id();
    uint64_t cur_time;
    long r;

    cur_time = cne_rdtsc();
    end_time = cur_time + (cne_get_timer_hz() * TEST_DURATION_S);

    do {
        /* call the timer handler on each thread */
        cne_timer_manage();

        /* simulate the processing of a packet
         * (1 us = 2000 cycles at 2 Ghz) */
        usleep(1);

        /* randomly stop or reset timer */
        r   = rand();
        tid = cne_next_id(tid, 0, 1);
        if (tid >= 0) {
            if ((r & 0xff) == 0) /* 100 us */
                mytimer_reset(&mytiminfo[0], hz / 10000, SINGLE, tid, timer_stress_cb);
            else if ((r & 0xff) == 1)
                cne_timer_stop_sync(&mytiminfo[0].tim);
        }
        cur_time = cne_rdtsc();
    } while (cur_time < end_time);
}

/* Need to synchronize workers threads through multiple steps. */
enum { WORKER_WAITING = 1, WORKER_RUN_SIGNAL, WORKER_RUNNING, WORKER_FINISHED };
static atomic_int *worker_state;
static int *worker_uid;
static int num_workers;

#define foreach_worker(i) \
    for (int _w = 0, i = worker_uid[_w]; _w < num_workers; i = worker_uid[++_w])

static void
initial_init_workers(void)
{
    foreach_worker(i) atomic_store(&worker_state[i], WORKER_WAITING);
}

static void
initial_start_workers(void)
{
    foreach_worker(i) atomic_store(&worker_state[i], WORKER_RUN_SIGNAL);

    foreach_worker(i)
    {
        while (atomic_load(&worker_state[i]) != WORKER_RUNNING)
            cne_pause();
    }
}

static void
initial_wait_for_workers(void)
{
    foreach_worker(i)
    {
        while (atomic_load(&worker_state[i]) != WORKER_FINISHED)
            cne_pause();
    }
}

static void
workers_wait_to_start(void)
{
    int tid = cne_id();

    while (atomic_load(&worker_state[tid]) != WORKER_RUN_SIGNAL)
        cne_pause();
    atomic_store(&worker_state[tid], WORKER_RUNNING);
}

static void
workers_finish(void)
{
    unsigned tid = cne_id();

    atomic_store(&worker_state[tid], WORKER_FINISHED);
}

static volatile int cb_count = 0;

/* callback for second stress test. will only be called
 * on main thread */
static void
timer_stress2_cb(struct cne_timer *tim __cne_unused, void *arg __cne_unused)
{
    cb_count++;
}

#define NB_STRESS2_TIMERS 8192

static void
timer_stress2_initial_loop(__cne_unused void *arg)
{
    static struct cne_timer *timers;
    int i, ret;
    uint64_t delay        = cne_get_timer_hz() / 20;
    unsigned tid          = cne_id();
    unsigned main         = cne_initial_uid();
    int32_t my_collisions = 0;
    static atomic_int collisions;

    if (tid == main) {
        cb_count    = 0;
        test_failed = 0;
        atomic_store(&collisions, 0);
        initial_init_workers();
        timers = calloc(NB_STRESS2_TIMERS, sizeof(*timers));
        if (timers == NULL) {
            tst_error("Failed to allocate memory for timers\n");
            test_failed = 1;
            initial_start_workers();
            goto cleanup;
        }
        for (i = 0; i < NB_STRESS2_TIMERS; i++)
            cne_timer_init(&timers[i]);
        initial_start_workers();
    } else {
        workers_wait_to_start();
        if (test_failed)
            goto cleanup;
    }

    /* have all cores schedule all timers on main thread */
    for (i = 0; i < NB_STRESS2_TIMERS; i++) {
        ret = cne_timer_reset(&timers[i], delay, SINGLE, main, timer_stress2_cb, NULL);
        /* there will be collisions when multiple cores simultaneously
         * configure the same timers */
        if (ret != 0)
            my_collisions++;
    }
    if (my_collisions != 0)
        atomic_fetch_add(&collisions, my_collisions);

    /* wait long enough for timers to expire */
    usleep(100 * 1000);

    /* all cores rendezvous */
    if (tid == main)
        initial_wait_for_workers();
    else
        workers_finish();

    /* now check that we get the right number of callbacks */
    if (tid == main) {
        my_collisions = atomic_load(&collisions);
        if (my_collisions != 0)
            cne_printf("- %d timer reset collisions (OK)\n", my_collisions);
        cne_timer_manage();
        if (cb_count != NB_STRESS2_TIMERS) {
            tst_error("- Stress test 2, part 1 failed\n");
            cne_printf("- Expected %d callbacks, got %d\n", NB_STRESS2_TIMERS, cb_count);
            test_failed = 1;
            initial_start_workers();
            goto cleanup;
        }
        cb_count = 0;

        /* proceed */
        initial_start_workers();
    } else {
        /* proceed */
        workers_wait_to_start();
        if (test_failed)
            goto cleanup;
    }

    /* now test again, just stop and restart timers at random after init*/
    for (i = 0; i < NB_STRESS2_TIMERS; i++)
        cne_timer_reset(&timers[i], delay, SINGLE, main, timer_stress2_cb, NULL);

    /* pick random timer to reset, stopping them first half the time */
    for (i = 0; i < 100000; i++) {
        int r = rand() % NB_STRESS2_TIMERS;
        if (i % 2)
            cne_timer_stop(&timers[r]);
        cne_timer_reset(&timers[r], delay, SINGLE, main, timer_stress2_cb, NULL);
    }

    /* wait long enough for timers to expire */
    usleep(100 * 1000);

    /* now check that we get the right number of callbacks */
    if (tid == main) {
        initial_wait_for_workers();

        cne_timer_manage();
        if (cb_count != NB_STRESS2_TIMERS) {
            tst_error("- Stress test 2, part 2 failed\n");
            cne_printf("- Expected %d callbacks, got %d\n", NB_STRESS2_TIMERS, cb_count);
            test_failed = 1;
        } else
            tst_ok("Timer stress tests done\n");
    }

cleanup:
    if (tid == main) {
        initial_wait_for_workers();
        if (timers != NULL) {
            free(timers);
            timers = NULL;
        }
    } else
        workers_finish();
}

/* timer callback for basic tests */
static void
timer_basic_cb(struct cne_timer *tim, void *arg)
{
    struct mytimerinfo *timinfo = arg;
    uint64_t hz                 = cne_get_timer_hz();
    unsigned tid                = cne_id();

    if (cne_timer_pending(tim))
        return;

    timinfo->count++;

    /* reload timer 0 on same core */
    if (timinfo->id == 0 && timinfo->count < 20) {
        mytimer_reset(timinfo, hz, SINGLE, tid, timer_basic_cb);
        return;
    }

    /* reload timer 1 on next core */
    if (timinfo->id == 1 && timinfo->count < 10) {
        mytimer_reset(timinfo, hz * 2, SINGLE, cne_next_id(tid, 1, 1), timer_basic_cb);
        return;
    }

    /* Explicitelly stop timer 0. Once stop() called, we can even
     * erase the content of the structure: it is not referenced
     * anymore by any code (in case of dynamic structure, it can
     * be freed) */
    if (timinfo->id == 0 && timinfo->count == 20) {

        /* stop_sync() is not needed, because we know that the
         * status of timer is only modified by this core */
        cne_timer_stop(tim);
        memset(tim, 0xAA, sizeof(struct cne_timer));
        return;
    }

    /* stop timer3, and restart a new timer0 (it was removed 5
     * seconds ago) for a single shot */
    if (timinfo->id == 2 && timinfo->count == 25) {
        cne_timer_stop_sync(&mytiminfo[3].tim);

        /* need to reinit because structure was erased with 0xAA */
        cne_timer_init(&mytiminfo[0].tim);
        mytimer_reset(&mytiminfo[0], hz, SINGLE, tid, timer_basic_cb);
    }
}

static void
timer_basic_initial_loop(__cne_unused void *arg)
{
    uint64_t hz  = cne_get_timer_hz();
    unsigned tid = cne_id();
    uint64_t cur_time;
    int64_t diff = 0;

    /* launch all timers on core 0 */
    if (tid == 0) {
        mytimer_reset(&mytiminfo[0], hz / 4, SINGLE, tid, timer_basic_cb);
        mytimer_reset(&mytiminfo[1], hz / 2, SINGLE, tid, timer_basic_cb);
        mytimer_reset(&mytiminfo[2], hz / 4, PERIODICAL, tid, timer_basic_cb);
        mytimer_reset(&mytiminfo[3], hz / 4, PERIODICAL, cne_next_id(tid, 1, 1), timer_basic_cb);
    }

    cur_time = cne_rdtsc();
    end_time = cur_time + (cne_get_timer_hz() * TEST_DURATION_S);
    while (diff >= 0) {

        /* call the timer handler on each core */
        cne_timer_manage();

        /* simulate the processing of a packet
         * (3 us = 6000 cycles at 2 Ghz) */
        usleep(3);

        cur_time = cne_rdtsc();
        diff     = end_time - cur_time;
    }
}

int
test_timer(int nb_timers)
{
    int status = 0;

    mytiminfo = calloc(nb_timers, sizeof(struct mytimerinfo));
    if (!mytiminfo)
        return -1;

    /* init timer */
    for (int i = 0; i < nb_timers; i++) {
        memset(&mytiminfo[i], 0, sizeof(struct mytimerinfo));
        mytiminfo[i].id = i;
        cne_timer_init(&mytiminfo[i].tim);
    }

    /* start other cores */
    cne_printf("Start timer stress tests\n");
    for (int i = 0; i < nb_timers; i++)
        thread_create("Timer-1", timer_stress_initial_loop, NULL);
    timer_stress_initial_loop(NULL);
    thread_wait_all(0, 100, 1);

    /* stop timer 0 used for stress test */
    cne_timer_stop_sync(&mytiminfo[0].tim);

    /* run a second, slightly different set of stress tests */
    cne_printf("\nStart timer stress tests 2\n");
    num_workers  = nb_timers;
    worker_state = calloc(num_workers, sizeof(*worker_state));
    if (!worker_state) {
        tst_error("Failed to allocate worker state memory\n");
        free(mytiminfo);
        return TEST_FAILED;
    }
    worker_uid = calloc(num_workers, sizeof(*worker_uid));
    if (!worker_uid) {
        free(mytiminfo);
        free(worker_state);
        tst_error("Failed to allocate worker uid memory\n");
        return TEST_FAILED;
    }

    test_failed = 0;
    for (int i = 0; i < num_workers; i++) {
        int uid = thread_create("Timer-2", timer_stress2_initial_loop, NULL);

        if (uid < 0) {
            /* This worker wasn't created, but some threads may have already started, so let them
             * finish, but mark the test failed anyway.
             */
            status      = 1;
            num_workers = i;
            break;
        } else
            worker_uid[i] = uid;
    }
    if (num_workers) {
        timer_stress2_initial_loop(NULL);
        thread_wait_all(0, 100, 1);
    }
    free(worker_state);
    free(worker_uid);
    if (test_failed || status) {
        free(mytiminfo);
        return TEST_FAILED;
    }

    /* start other cores */
    cne_printf("\nStart timer basic tests\n");
    for (int i = 0; i < nb_timers; i++)
        thread_create("Timer-3", timer_basic_initial_loop, NULL);
    timer_basic_initial_loop(NULL);
    thread_wait_all(0, 100, 1);

    /* stop all timers */
    for (int i = 0; i < nb_timers; i++)
        cne_timer_stop_sync(&mytiminfo[i].tim);

    cne_timer_dump_stats(stdout);
    free(mytiminfo);

    return TEST_SUCCESS;
}
