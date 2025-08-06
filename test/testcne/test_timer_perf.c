/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2025 Intel Corporation
 */

#include <stdio.h>             // for NULL
#include <unistd.h>            // for usleep
#include <inttypes.h>          // for PRIu64
#include <cne_cycles.h>        // for cne_rdtsc
#include <cne_timer.h>         // for cne_timer_manage, cne_timer_reset, cne_timer
#include <cne_common.h>        // for __cne_unused
#include <cne.h>               // for cne_id
#include <cne_system.h>        // for cne_get_timer_hz
#include <stdint.h>            // for uint64_t
#include <stdlib.h>            // for calloc, free, rand

#include "timer_test.h"        // for test_timer_perf
#include "cne_stdio.h"         // for cne_printf

#define MAX_ITERATIONS 1000000

int outstanding_count = 0;

static void
timer_cb(struct cne_timer *t __cne_unused, void *param __cne_unused)
{
    outstanding_count--;
}

#define DELAY_SECONDS 3

#define do_delay() usleep(10)

int
test_timer_perf(void)
{
    unsigned iterations = 100;
    unsigned i;
    struct cne_timer *tms;
    uint64_t start_tsc, end_tsc, delay_start;
    unsigned lcore_id = cne_id();

    tms = calloc(MAX_ITERATIONS, sizeof(*tms));
    if (!tms)
        return -1;

    for (i = 0; i < MAX_ITERATIONS; i++)
        cne_timer_init(&tms[i]);

    const uint64_t ticks        = cne_get_timer_hz() * DELAY_SECONDS;
    const uint64_t ticks_per_ms = cne_get_timer_hz() / 1000;
    const uint64_t ticks_per_us = ticks_per_ms / 1000;

    while (iterations <= MAX_ITERATIONS) {

        cne_printf("Appending %u timers\n", iterations);
        start_tsc = cne_rdtsc();
        for (i = 0; i < iterations; i++)
            cne_timer_reset(&tms[i], ticks, SINGLE, lcore_id, timer_cb, NULL);
        end_tsc = cne_rdtsc();
        cne_printf("Time for %u timers: %" PRIu64 " (%" PRIu64 "ms), ", iterations,
                   end_tsc - start_tsc, (end_tsc - start_tsc + ticks_per_ms / 2) / (ticks_per_ms));
        cne_printf("Time per timer: %" PRIu64 " (%" PRIu64 "us)\n",
                   (end_tsc - start_tsc) / iterations,
                   ((end_tsc - start_tsc) / iterations + ticks_per_us / 2) / (ticks_per_us));
        outstanding_count = iterations;
        delay_start       = cne_rdtsc();
        while (cne_rdtsc() < delay_start + ticks)
            do_delay();

        start_tsc = cne_rdtsc();
        while (outstanding_count)
            cne_timer_manage();
        end_tsc = cne_rdtsc();
        cne_printf("Time for %u callbacks: %" PRIu64 " (%" PRIu64 "ms), ", iterations,
                   end_tsc - start_tsc, (end_tsc - start_tsc + ticks_per_ms / 2) / (ticks_per_ms));
        cne_printf("Time per callback: %" PRIu64 " (%" PRIu64 "us)\n",
                   (end_tsc - start_tsc) / iterations,
                   ((end_tsc - start_tsc) / iterations + ticks_per_us / 2) / (ticks_per_us));

        cne_printf("Resetting %u timers\n", iterations);
        start_tsc = cne_rdtsc();
        for (i = 0; i < iterations; i++)
            cne_timer_reset(&tms[i], rand() % ticks, SINGLE, lcore_id, timer_cb, NULL);
        end_tsc = cne_rdtsc();
        cne_printf("Time for %u timers: %" PRIu64 " (%" PRIu64 "ms), ", iterations,
                   end_tsc - start_tsc, (end_tsc - start_tsc + ticks_per_ms / 2) / (ticks_per_ms));
        cne_printf("Time per timer: %" PRIu64 " (%" PRIu64 "us)\n",
                   (end_tsc - start_tsc) / iterations,
                   ((end_tsc - start_tsc) / iterations + ticks_per_us / 2) / (ticks_per_us));
        outstanding_count = iterations;

        delay_start = cne_rdtsc();
        while (cne_rdtsc() < delay_start + ticks)
            do_delay();

        cne_timer_manage();
        if (outstanding_count != 0) {
            cne_printf("Error: outstanding callback count = %d\n", outstanding_count);
            return -1;
        }

        iterations *= 10;
        cne_printf("\n");
    }

    cne_printf("All timers processed ok\n");

    /* measure time to poll an empty timer list */
    start_tsc = cne_rdtsc();
    for (i = 0; i < iterations; i++)
        cne_timer_manage();
    end_tsc = cne_rdtsc();
    cne_printf("\nTime per cne_timer_manage with zero timers: %" PRIu64 " cycles\n",
               (end_tsc - start_tsc + iterations / 2) / iterations);

    /* measure time to poll a timer list with timers, but without
     * calling any callbacks */
    cne_timer_reset(&tms[0], ticks * 100, SINGLE, lcore_id, timer_cb, NULL);
    start_tsc = cne_rdtsc();
    for (i = 0; i < iterations; i++)
        cne_timer_manage();
    end_tsc = cne_rdtsc();
    cne_printf("Time per cne_timer_manage with zero callbacks: %" PRIu64 " cycles\n",
               (end_tsc - start_tsc + iterations / 2) / iterations);

    free(tms);
    return 0;
}
