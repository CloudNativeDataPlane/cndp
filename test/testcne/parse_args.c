/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>              // for NULL, EOF
#include <stdlib.h>             // for atoi, exit
#include <getopt.h>             // for getopt_long, required_argument, no_arg...
#include <cne_version.h>        // for cne_version
#include <cli.h>                // for cli_add_cmdfile
#include <libgen.h>             // for basename
#include <cne.h>                // for cne_max_threads

#include "testcne.h"          // for myargs_t, parse_args
#include "cne_stdio.h"        // for cne_printf

/* Long options start at 256 to distinguish from short options */
#define OPT_NO_COLOR     "no-color"
#define OPT_NO_COLOR_NUM 256

int
parse_args(myargs_t *a)
{
    int argc;
    char **argv;
    int opt, ret;
    char **argvopt;
    int option_index;
    const int old_optind   = optind;
    const int old_optopt   = optopt;
    char *const old_optarg = optarg;
    // clang-format off
    static const struct option lgopts[] = {
        {"verbose", no_argument, NULL, 'v'},
        {"threads", optional_argument, NULL, 'T'},
        {"version", no_argument, NULL, 'V'},
        {"cmdfile", required_argument, NULL, 'c'},
        {"initial-thread", required_argument, NULL, 'm'},
        {"debug", required_argument, NULL, 'd'},
        {OPT_NO_COLOR, no_argument, NULL, OPT_NO_COLOR_NUM},
        {NULL, 0, NULL, 0}
    };
    // clang-format on

    if (!a)
        return -1;
    argc = a->argc;
    argv = a->argv;

    if (argc <= 0)
        return -1;

    ret              = -1;
    argvopt          = argv;
    optind           = 1;
    a->nb_threads    = 8;
    a->initial_lcore = -1;
    a->verbose       = 0;

    while ((opt = getopt_long(argc, argvopt, "Vvc:T:m:d:", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            cne_printf("%s: Version: %s\n", basename(argv[0]), cne_version());
            exit(0);
        case 'v':
            a->verbose = 1;
            break;
        case 'c':
            cli_add_cmdfile(optarg);
            break;
        case 'T':
            a->nb_threads = atoi(optarg);
            if (a->nb_threads == 0)
                a->nb_threads = 1;
            else if (a->nb_threads >= cne_max_threads())
                goto out;
            break;
        case 'm':
            a->initial_lcore = atoi(optarg);
            break;
        case 'd':
            a->debug = atoi(optarg);
            if (a->debug == 0) {
                cne_printf("debug argument is not a number (%s)\n", optarg);
                exit(0);
            }
            break;
        case OPT_NO_COLOR_NUM:
            tty_disable_color();
            break;
        default:
            break;
        }
    }
    ret = optind - 1;

    a->argc -= ret;
    a->argv += ret;

out:
    /* restore getopt lib state */
    optind = old_optind;
    optopt = old_optopt;
    optarg = old_optarg;

    return ret;
}
