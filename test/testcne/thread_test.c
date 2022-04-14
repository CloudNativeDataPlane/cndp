/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, EOF
#include <getopt.h>            // for getopt_long, option
#include <cne_thread.h>        // for thread_create, thread_wait
#include <tst_info.h>          // for tst_error, tst_end, tst_start, TST_FAILED
#include <cne_common.h>        // for CNE_USED
#include <stdatomic.h>         // for atomic_exchange, atomic_int_least32_t
#include <stdbool.h>           // for bool

#include "thread_test.h"
#include "cne_stdio.h"        // for cne_printf

static atomic_int_least32_t tester_running;

static void
Tester(void *arg)
{
    (void)arg;

    cne_printf("Tester Started\n");
    // clang-format off
    while (atomic_load(&tester_running)) { }
    // clang-format on
    cne_printf("Tester Finished\n");
}

int
thread_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt, tid;
    bool result = TST_PASSED;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    optind = 0;
    while ((opt = getopt_long(argc, argvopt, "V", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("Thread");

    atomic_exchange(&tester_running, 1);
    tid = thread_create("Test", Tester, NULL);
    if (tid < 0) {
        tst_error("Thread create failed\n");
        result = TST_FAILED;
        goto leave;
    }

leave:
    atomic_exchange(&tester_running, 0);
    if (tid >= 0) {
        if (thread_wait(tid, 0, 0)) {
            tst_error("Thread wait failed\n");
            result = TST_FAILED;
        }
    }
    tst_end(tst, result);

    return 0;
}
