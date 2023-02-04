/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2023 Intel Corporation
 */

#include <cne.h>               // for cne_id, cne_max_threads, cne_unregister, cne...
#include <cne_system.h>        // for cne_max_lcores, cne_max_numa_nodes
#include <cne_log.h>           // for CNE_ERR_RET, CNE_LOG_ERR, cne_panic
#include <cne_thread.h>        // for thread_create, thread_wait_all
#include <stdlib.h>            // for atoi
#include <unistd.h>            // for usleep

#include "cne_common.h"        // for __cne_unused
#include "cne_stdio.h"         // for cne_printf

static void
hello_world(void *arg __cne_unused)
{
    cne_printf("[yellow]hello world! [magenta]thread id [red]%4d[]\n", cne_id());

    /* sleep for some time to allow for all threads to start up */
    usleep((cne_id() * 10000) + 100000);

    cne_printf("[yellow]hello world! [magenta]thread id [red]%4d [yellow]Done[]\n", cne_id());
}

int
main(int argc __cne_unused, char **argv __cne_unused)
{
    int tidx;
    int num_threads = 1;

    if (argc > 1)
        num_threads = atoi(argv[1]);

    if (num_threads > cne_max_threads())
        CNE_ERR_RET("Number of threads to create exceeds %d\n", cne_max_threads());

    tidx = cne_init(); /* set the thread_id() function or any function */

    cne_printf("\n[magenta]Max threads[]: [red]%d[], [magenta]Max lcores[]: [red]%d[], "
               "[magenta]NUMA nodes[]: [red]%d[], [magenta]Num Threads[]: [red]%d[]\n\n",
               cne_max_threads(), cne_max_lcores(), cne_max_numa_nodes(), num_threads);

    for (int i = 0; i < num_threads; i++) {
        int idx = thread_create("Hello", hello_world, (void *)0);
        if (idx < 0) {
            cne_unregister(tidx);
            cne_panic("Failed to start thread\n");
        }
    }
    usleep(1000);

    cne_printf("\n[magenta]Waiting for all threads to stop![]\n\n");

    thread_wait_all(0, 1000, 1);

    cne_printf("\n[magenta]All threads have stopped![]\n");

    cne_unregister(tidx);

    cne_printf("\n[yellow]Good Bye![]\n\n");

    return 0;
}
