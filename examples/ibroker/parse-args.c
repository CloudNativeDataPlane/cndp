/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <pthread.h>           // for pthread_self, pthread_setaffinity_np
#include <sched.h>             // for CPU_COUNT, CPU_ISSET, CPU_SETSIZE, cpu...
#include <stdio.h>             // for NULL, size_t, EOF
#include <stdlib.h>            // for calloc
#include <unistd.h>            // for usleep
#include <getopt.h>            // for getopt_long, option
#include <bsd/string.h>        // for strlcpy
#include <stdint.h>            // for uint16_t
#include <strings.h>           // for strcasecmp

#include <ibroker.h>

#include "main.h"        // for fwd, fwd_info, enable_metrics, fwd_port

static void
print_usage(char *prog_name)
{
    printf("Usage: %s [-h] -b brokers -s services\n"
           "  -b NUM         Number of brokers\n"
           "  -s NUM         Number of services per broker\n"
           "  -h             Display the help information\n",
           prog_name);
}

int
parse_args(int argc, char **argv)
{
    struct option lgopts[] = {{NULL, 0, 0, 0}};
    int opt, option_index, val;

    app->num_brokers  = NUM_DEFAULT_BROKERS;
    app->num_services = NUM_DEFAULT_SERVICES;

    /* Parse the input arguments. */
    for (;;) {
        opt = getopt_long(argc, argv, "hb:s:", lgopts, &option_index);
        if (opt == EOF)
            break;

        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return -1;

        case 'b':
            val = atoi(optarg);
            if (val > 0 && val < IBROKER_MAX_COUNT)
                app->num_brokers = val;
            else {
                printf("Number of brokers (%d) invalid\n", val);
                return -1;
            }
            break;

        case 's':
            val = atoi(optarg);
            if (val > 0 && val < IBROKER_MAX_SERVICES)
                app->num_services = val;
            else {
                printf("Number of services (%d) is invalid\n", val);
                return -1;
            }
            break;

        default:
            print_usage(argv[0]);
            printf("Invalid command option (%c)\n", opt);
            return -1;
        }
    }

    return 0;
}
