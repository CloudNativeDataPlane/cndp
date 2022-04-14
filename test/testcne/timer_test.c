/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for EOF, NULL
#include <stdlib.h>            // for atoi
#include <getopt.h>            // for getopt_long, option
#include <tst_info.h>          // for tst_end, tst_error, tst_start, TST_FAILED
#include <cne_common.h>        // for CNE_SET_USED
#include <cne_timer.h>         // for cne_timer_subsystem_init
#include <uid.h>               // for DEFAULT_MAX_THREADS

#include "timer_test.h"
#include "cne_stdio.h"        // for cne_printf

#define DEFAULT_TIMERS 16

/* timer_test() creates a thread per timer, so MAX_TIMERS should not exceed MAX_THREADS */
#define MAX_TIMERS DEFAULT_MAX_THREADS

int
timer_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt, nb_timers;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    optind    = 0;
    nb_timers = DEFAULT_TIMERS;
    while ((opt = getopt_long(argc, argvopt, "Vn:", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        case 'n':
            nb_timers = atoi(optarg);
            if (nb_timers <= 0 || nb_timers > MAX_TIMERS) {
                tst_error("Invalid number of timers: %d\n", nb_timers);
                return -1;
            }
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("Timer");

    cne_timer_subsystem_init();

    cne_printf("[blue]Number of timers[]: %d\n", nb_timers);

    if (test_timer(nb_timers))
        goto err;

    if (test_timer_perf())
        goto err;

    tst_end(tst, TST_PASSED);

    return 0;
err:
    tst_end(tst, TST_FAILED);
    return -1;
}
