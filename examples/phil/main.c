/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation.
 */

#include <pthread.h>           // for pthread_self, pthread_setaffinity_np
#include <signal.h>            // for signal, SIGUSR1, SIGINT
#include <sched.h>             // for cpu_set_t
#include <stdio.h>             // for fflush, stdout, NULL
#include <stdlib.h>            // for exit
#include <string.h>            // for memset
#include <unistd.h>            // for usleep, getpid, sleep
#include <cne_common.h>        // for __cne_unused
#include <cne.h>               // for cne_init, cne_register
#include <cne_log.h>           // for CNE_ERR_RET, CNE_LOG_ERR
#include <metrics.h>           // for metrics_destroy
#include <cthread.h>
#include <cthread_api.h>
#include <cli.h>

#include "main.h"
#include "phil.h"

static struct app_info app_info = {0};
struct app_info *app            = &app_info;

enum {
    MAX_SCRN_ROWS = 43,
    MAX_SCRN_COLS = 132,

    COLUMN_WIDTH_0 = 18,
    COLUMN_WIDTH_1 = 22
};

struct sched_args {
    int row;
    int col;
    int sched_id;
};

static pthread_once_t once = PTHREAD_ONCE_INIT;

static int
_cthread_stats(struct cthread *c, void *arg, int cthread_id)
{
    struct cthread_sched *sched;
    struct sched_args *a = arg;
    phil_info_t *phil;
    int row, col, sched_id;

    phil = cthread_thread_private(c);
    if (!phil)
        return 0;

    sched_id = a->sched_id;
    sched    = cthread_sched_find(sched_id);
    row      = a->row++;
    col      = a->col + ((sched_id - 1) * COLUMN_WIDTH_1);

    // Only change the screen if the value has changed.
    if (phil->saved_doing != phil->doing) {

        cne_printf_pos(3, col, "[deeppink:-:italic]%s[]",
                       phil->solution == CLAIM_BASED ? "  Claim-Based" : "  Ticket-Based");
        cne_printf_pos(4, col, "  [lightskyblue]-----   [deeppink]%d   [lightskyblue]-----[]",
                       sched_id);
        cne_printf_pos(row, 1, "[fuchsia]%s[]:", cthread_get_name(cthread_find(sched, cthread_id)));

        // clang-format off
        switch(phil->doing) {
        case PHIL_THINKING:         cne_printf_pos(row, col, "[palegoldenrod]%s[]", doing_str[phil->doing]); break;
        case PHIL_WANTS_TO_EAT:     cne_printf_pos(row, col, "[yellow]%s[]", doing_str[phil->doing]); break;
        case PHIL_WAIT_FORK:        cne_printf_pos(row, col, "[teal]%s[]", doing_str[phil->doing]); break;
        case PHIL_EATING:           cne_printf_pos(row, col, "[green]%s[]", doing_str[phil->doing]); break;
        case PHIL_ASK_RIGHT_FORK:   cne_printf_pos(row, col, "[yellow]%s[]", doing_str[phil->doing]); break;
        case PHIL_WAIT_RIGHT_FORK:  cne_printf_pos(row, col, "[red]%s[]", doing_str[phil->doing]); break;
        case PHIL_ASK_LEFT_FORK:    cne_printf_pos(row, col, "[yellow]%s[]", doing_str[phil->doing]); break;
        case PHIL_WAIT_LEFT_FORK:   cne_printf_pos(row, col, "[red]%s[]", doing_str[phil->doing]); break;
        case PHIL_GIVE_FORK:        cne_printf_pos(row, col, "[blue]%s[]", doing_str[phil->doing]); break;
        case PHIL_UNKNOWN_STATE:    cne_printf_pos(row, col, "%s", doing_str[phil->doing]); break;
        default: cne_printf_pos(row, col, " =================="); break;
        }
        // clang-format on
        phil->saved_doing = phil->doing;
    }
    return 0;
}

static int
_sched_stats(struct cthread_sched *s, void *arg, int sched_id)
{
    struct sched_args *a = arg;

    a->row      = 3;
    a->col      = COLUMN_WIDTH_0;
    a->sched_id = sched_id;

    cne_printf_pos(a->row++, 1, "[yellow]Solution[]:");
    cne_printf_pos(a->row++, 1, "[yellow]Scheduler[]:");

    return cthread_foreach(s, _cthread_stats, a);
}

static void
page_stats(void)
{
    struct sched_args args = {0};

    cthread_sched_foreach(_sched_stats, &args);
}

void
thread_func(void *arg)
{
    jcfg_thd_t *thd = arg;

    if (thd->group->lcore_cnt > 0)
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &thd->group->lcore_bitmap);

    cthread_sched_create(0); /* create a scheduler per pthread created */

    pthread_once(&once, phil_create_barriers);

    if (cthread_create(thd->name, (cthread_func_t)phil_demo_start, (void *)app) == NULL)
        CNE_RET("Failed to create cthread\n");

    cthread_run();
}

static int
_thread_quit(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_thd_t *thd = obj;

    thd->quit = 1;

    return 0;
}

static void
my_exit(void)
{
    cne_printf_pos(99, 1, "\n");
    cne_printf("*** Terminating the application\n");
    fflush(stdout);
    usleep(5000);

    jcfg_thread_foreach(app->jinfo, _thread_quit, app);
    app->quit = 1;

    fflush(stdout);
    usleep(5000);
}

static void
signal_handler(int sig)
{
    cne_printf("Signal: %d\n", sig);
    if (sig == SIGUSR1)
        return;

    my_exit();
    exit(0);
}

int
main(int argc, char **argv)
{
    int lcore_id;

    atexit(my_exit);

    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);

    // Setup the random number seed.
    lcore_id = cne_lcore_id();
    if (lcore_id < 0 || lcore_id > INT_MAX)
        srand(0x19560630);
    else
        srand(0x19560630 + lcore_id * 333);

    if (cne_init() < 0)
        CNE_ERR_RET("Failed to initialize the CNE system\n");

    if (parse_args(argc, argv))
        CNE_ERR_RET("Failed to parse the arguments\n");

    vt_cls();
    cne_printf_pos(2, 1, "*** [yellow]Dining Philosphers[], [magenta]PID: [lightskyblue]%d[]\n",
                   getpid());
    sleep(1);

    app->quit = 0;
    while (!app->quit) {
        page_stats();
        sleep(1);
    }
    return 0;
}
