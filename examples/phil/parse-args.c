/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation.
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <pthread.h>             // for pthread_self, pthread_setaffinity_np
#include <sched.h>               // for CPU_COUNT, CPU_ISSET, CPU_SETSIZE, cpu...
#include <stdio.h>               // for NULL, size_t, EOF
#include <stdlib.h>              // for calloc
#include <unistd.h>              // for usleep
#include <getopt.h>              // for getopt_long, option
#include <bsd/string.h>          // for strlcpy
#include <cne_log.h>             // for CNE_LOG_ERR, CNE_ERR_RET, CNE_ERR, CNE...
#include <jcfg.h>                // for jcfg_obj_t, jcfg_umem_t, jcfg_lport_t
#include <jcfg_process.h>        // for jcfg_process
#include <stdint.h>              // for uint16_t
#include <strings.h>             // for strcasecmp
#include <cne_thread.h>

#include "main.h"        // for fwd, fwd_info, enable_metrics, fwd_port

static int
process_callback(jcfg_info_t *j __cne_unused, void *_obj, void *arg __cne_unused, int idx)
{
    jcfg_obj_t obj;

    if (!_obj)
        return -1;

    obj.hdr = _obj;

    switch (obj.hdr->cbtype) {
    case JCFG_APPLICATION_TYPE:
        break;

    case JCFG_DEFAULT_TYPE:
        break;

    case JCFG_OPTION_TYPE:
        break;

    case JCFG_UMEM_TYPE:
        break;

    case JCFG_LPORT_TYPE:
        break;

    case JCFG_LGROUP_TYPE:
        break;

    case JCFG_LPORT_GROUP_TYPE:
        break;

    case JCFG_THREAD_TYPE:
        if (!strcasecmp("cli", obj.thd->thread_type)) { /* Main thread */
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                   &obj.thd->group->lcore_bitmap);
        } else if (!strcasecmp("phil", obj.thd->thread_type)) {
            if (thread_create(obj.thd->name, thread_func, obj.thd) < 0)
                CNE_ERR_RET("Failed to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                            obj.thd->thread_type);
        } else
            CNE_ERR_RET("*** Unknown thread type '%s'\n", obj.thd->thread_type);
        break;
    default:
        return -1;
    }

    return 0;
}

static void
print_usage(char *prog_name)
{
    cne_printf("Usage: %s [-h] [-c json_file] <mode>\n"
               "  -c <json-file> The JSON configuration file\n"
               "  -C             Wait on unix domain socket for JSON or JSON-C file\n"
               "  -d             More debug stats are displayed\n"
               "  -D             JCFG debug decoding\n"
               "  -V             JCFG information verbose\n"
               "  -P             JCFG debug parsing\n"
               "  -h             Display the help information\n",
               prog_name);
}

int
parse_args(int argc, char **argv)
{
    struct option lgopts[] = {{NULL, 0, 0, 0}};
    int opt, option_index, flags = 0;
    char json_file[1024] = {0};

    app->num_threads = NUM_DEFAULT_PHILOSPHERS;

    /* Parse the input arguments. */
    for (;;) {
        opt = getopt_long(argc, argv, "hc:dCDPVt:", lgopts, &option_index);
        if (opt == EOF)
            break;

        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return -1;

        case 'c':
            strlcpy(json_file, optarg, sizeof(json_file));
            flags |= JCFG_PARSE_FILE;
            break;

        case 'd':
            app->flags |= APP_DEBUG_STATS;
            break;

        case 'C':
            flags |= JCFG_PARSE_SOCKET;
            break;

        case 'D':
            flags |= JCFG_DEBUG_DECODING;
            break;

        case 'P':
            flags |= JCFG_DEBUG_PARSING;
            break;

        case 'V':
            flags |= JCFG_INFO_VERBOSE;
            break;

        default:
            CNE_ERR("Invalid command option\n");
            print_usage(argv[0]);
            return -1;
        }
    }

    if (optind < argc)
        app->num_threads = atoi(argv[optind]);

    app->jinfo = jcfg_parser(flags, (const char *)json_file);
    if (app->jinfo == NULL)
        CNE_ERR_RET("*** Did not find any configuration to use ***\n");

    if (jcfg_process(app->jinfo, flags, process_callback, app))
        CNE_ERR_RET("*** Invalid configuration ***\n");

    return 0;
}
