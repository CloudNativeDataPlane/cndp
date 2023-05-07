/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdlib.h>             // for exit, free, EXIT_FAILURE, EXIT_SUCCESS
#include <signal.h>             // for signal, SIGUSR1, SIGSEGV, SIGTERM
#include <execinfo.h>           // for backtrace, backtrace_symbols
#include <cne.h>                // for cne_dump, cne_init, cne_unregister
#include <cne_version.h>        // for cne_version
#include <cne_thread.h>         // for thread_set_affinity
#include <cne_log.h>            // for CNE_ERR, CNE_LOG_ERR
#include <cli.h>                // for cli_destroy, cli_execute_cmd, cli_set_...
#include <tst_info.h>           // for tst_summary
#include <unistd.h>             // for sleep
#include <stddef.h>             // for size_t, NULL

#include "testcne.h"
#include "cne_stdio.h"        // for cne_printf, cne_printf_pos
#include "vt100_out.h"        // for vt_setw, vt_cls

#define MAX_BACKTRACE 32

static void
sig_handler(int v)
{
    void *array[MAX_BACKTRACE];
    size_t size;
    char **strings;
    size_t i;

    vt_setw(1); /* Reset the window size, from possible crash run. */

    cne_printf("\n======");

    if (v == SIGSEGV)
        cne_printf(" Got a Segment Fault\n");
    else if (v == SIGUSR1)
        cne_printf("  Received a SIGUSR1\n");
    else if (v == SIGTERM)
        cne_printf(" Received a SIGTERM\n");
    else
        cne_printf(" Received signal %d\n", v);

    if (v == SIGUSR1)
        return;

    cne_printf("\n");

    size    = backtrace(array, MAX_BACKTRACE);
    strings = backtrace_symbols(array, size);

    cne_printf("Obtained %zd stack frames.\n", size);

    for (i = 0; i < size; i++)
        cne_printf("%s\n", strings[i]);

    free(strings);

    cne_printf("Cleanup and Exit\n");

    cli_destroy();

    exit(-1);
}

int
main(int argc, char **argv)
{
    myargs_t a = {0};
    int ret, tidx;

    signal(SIGSEGV, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGUSR1, sig_handler);

    a.argc = argc;
    a.argv = argv;
    ret    = parse_args(&a);
    if (ret < 0) {
        cne_printf("Failed to parse arguments\n");
        return -1;
    }

    if (a.verbose)
        cne_printf("Testcne version %s started with %d threads\n", cne_version(), a.nb_threads);

    tidx = cne_init();

    if (a.initial_lcore >= 0) {
        /* TODO: set affinity */
        cne_printf("Set initial thread affinity to %d\n", a.initial_lcore);
        thread_set_affinity(a.initial_lcore);
    }

    if (a.verbose)
        cne_dump(NULL);

    if (a.debug) {
        cne_printf("Wait %d seconds for GDB to attach\n", a.debug);
        sleep(a.debug);
    }

    if (setup_cli() < 0)
        return 0;

    if (optind >= a.argc) {
        cli_set_prompt(my_prompt);

        vt_cls();
        cne_printf_pos(128, 1, "\n");

        cli_start("Test-CNE");

        vt_setw(1);
        cne_printf_pos(128, 1, "\n");
    } else
        cli_execute_cmd(a.argc - optind, &a.argv[optind]);

    cli_destroy();

    if (cne_unregister(tidx) < 0)
        CNE_ERR("cne_unregister(%d) failed\n", tidx);

    tst_summary();
    return tst_exit_code();
}
