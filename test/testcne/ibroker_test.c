/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for size_t, EOF, NULL
#include <getopt.h>            // for getopt_long, option
#include <cne_mmap.h>          // for MMAP_HUGEPAGE_4KB, MMAP_HUGEPAGE_2MB
#include <tst_info.h>          // for tst_cleanup, tst_error, tst_end, tst_s...
#include <unistd.h>            // for getpagesize
#include <cne_common.h>        // for CNE_SET_USED, cne_countof
#include <cne.h>
#include <cne_log.h>
#include <ibroker.h>        // for ibroker_create, ibroker_destroy, ...

#include "ibroker_test.h"

static int
walk_routine(broker_id_t bid, void *arg)
{
    cne_printf("   [magenta]Name[]: '[green]%-24s[]', [magenta]arg[]: [green]%p[]\n",
               ibroker_get_name(bid), arg);

    return 0;
}

static int
ibroker_start(void)
{
    broker_id_t bid;
    char buff[128];

    snprintf(buff, sizeof(buff), "Broker %d", cne_id());
    bid = ibroker_create((const char *)buff);
    if (bid < 0) {
        tst_error("Creating ibroker(%d) failed\n", cne_id());
        return -1;
    }

    tst_ok("ibroker_create() on thread %d succeeded\n", cne_id());

    if (ibroker_walk(walk_routine, NULL) < 0) {
        tst_error("ibroker_walk() failed\n");
        return -1;
    } else
        tst_ok("ibroker_walk()\n");

    if (ibroker_find(ibroker_get_name(bid)) < 0) {
        tst_error("ibroker_find('[red]%s[]') failed\n", buff);
        return -1;
    } else
        tst_ok("Found ibroker_find('[green]%s[]')\n", buff);

    ibroker_destroy(bid);

    return 0;
}

int
ibroker_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
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

    tst = tst_start("ibroker");

    tst_end(tst, (ibroker_start() < 0) ? TST_FAILED : TST_PASSED);

    return 0;
}
