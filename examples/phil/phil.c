/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

/* phil.c - Dining Philosophers problem */

/**
DESCRIPTION
This demo demonstrates multitasking by providing two
solutions to Dijkstra's famous dining philosophers problem. The main goal
of the problem is to find ways to avoid both deadlock and starvation
when a finite set of actors share a finite set of resources that
can be used by one actor only at a time.

The problem is described as follows: five philosophers sit around a table to
think and eat. Between each adjacent philosopher there is a fork. When a
philosopher is done thinking she/he needs to grab the two forks on his/her
immediate right and left to be able to eat. When the philosopher is done eating
she/he puts down the forks and go back to thinking for a while till he or she
is hungry again, etc., etc.

In this implementation the number of philosophers can be changed (five being
the default). Also the duration of a philosopher's thinking phase is not the
same for all. This brings a more realistic touch to the situation since,
usually, actors accessing a resource do not all have the same frequency of
access to that resource. This implementation simply lets a philosopher think for
a number of seconds equal to the philosopher's order number around the table
(i.e. 1 to x) instead of some random time or an equal amount of time for all.

The two solutions implemented here are 1) a ticket-based one, and 2) a
claim-based one. The ticket-based solution is fair in the sense that all
philosophers get to access the resource for the same amount of time in average
whether they think quick (or shallowy...) or long. The drawback is that the
faster thinkers get to wait more for accessing the resource. The claim-based
solution is addressing this by letting the faster thinkers access the resource
as long as it is not claimed by another philosopher (in which case the
requestor still has to wait until the other philosopher has gotten a chance to
use the resource).

INCLUDE FILES: N/A
*/

/* Includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <stdbool.h>

#include <cne_log.h>
#include <cne_tailq.h>
#include <cne_common.h>
#include <cne_cycles.h>
#include <cne_prefetch.h>
#include <cne_system.h>
#include <cne_per_thread.h>
#include <cne_branch_prediction.h>
#include <cne_timer.h>
#include <cne_spinlock.h>
#include <cne.h>

#include <ctx.h>
#include <cthread.h>
#include <cthread_api.h>
#include <cthread_barrier.h>
#include <cthread_once.h>

#include "main.h"
#include "phil.h"

// clang-format off
const char *doing_str[] = {
    "  thinking..........",        // 0
    "  wants to eat......",        // 1
    "  wait for forks....",        // 2
    "  eating............",        // 3
    "  ask right fork....",        // 4
    "  wait right fork...",        // 5
    "  ask left fork.....",        // 6
    "  wait left fork....",        // 7
    "  give all forks....",        // 8
    "  ------------------",        // 9
    NULL
};
// clang-format on

static struct cthread_barrier **barriers;
static volatile int phil_quit = 0;

void
phil_create_barriers(void)
{
    int max_threads = cne_max_threads();

    barriers = calloc(max_threads, sizeof(struct cthread_barrier *));
    if (!barriers)
        CNE_RET("Unable to allocate cthread_barrier structures\n");
}

/*******************************************************************************
 *
 * forks_get - Get the right-hand and left-hand pair of forks
 *
 * This routine attempts to acquire the forks a philosopher needs to be able to
 * eat. Forks are always acquired in pair, i.e. if only one of the forks is
 * available then no fork is acquired.
 *
 * RETURNS: TRUE if both forks are acquired, FALSE otherwise.
 * ERRNO: N/A
 *
 * \NOMANUAL
 */

static BOOL
forks_get(phil_info_t *phil, int my_num, /* Philosopher's order number */
          int solution,                  /* Solution to execute */
          fork_attr_t *forks_attr)       /* Forks attributes */
{
    BOOL forks_acquired = false;
    BOOL pass_turn      = false;
    int right_fork      = my_num;
    int left_fork       = (my_num + 1) % forks_attr->num_forks;

    /* Acquire the mutex protecting the critical section */

    phil->saved_count = 3;
    cthread_mutex_lock(forks_attr->fork_mutex);

    if (solution == TICKET_BASED) {
        /* Check whether it is this philosopher's turn to get the forks */

        if (((forks_attr->forks[right_fork].philosopher == my_num) ||
             (forks_attr->forks[right_fork].philosopher == NOBODY)) &&
            ((forks_attr->forks[left_fork].philosopher == my_num) ||
             (forks_attr->forks[left_fork].philosopher == NOBODY)))
            forks_acquired = true;
    } else { /* Claim-based solution */
        /*
         * A fork can be acquired only if it is not in use and if no one else
         * has claimed it. If the fork is in use already then the philosopher
         * simply claims it and waits for it to be available. If the fork is
         * available but has already been claimed then the philosopher must
         * wait for his/her turn.
         *
         * Note: if we were to randomize the think time of the philosophers it
         *       might be more efficient for a philosopher to claim the fork
         *       when the fork is available but has been claimed by the other
         *       philosopher (i.e. implement a two-slot queue for the fork).
         */

        if (forks_attr->forks[right_fork].status == FORK_IN_USE) {
            forks_attr->forks[right_fork].philosopher = my_num;
            pass_turn                                 = true;
            phil->saved_doing                         = PHIL_ASK_RIGHT_FORK;
        } else if ((forks_attr->forks[right_fork].philosopher != my_num) &&
                   (forks_attr->forks[right_fork].philosopher != NOBODY)) {
            pass_turn = true;

            phil->saved_doing = PHIL_WAIT_RIGHT_FORK;
        }

        if (forks_attr->forks[left_fork].status == FORK_IN_USE) {
            forks_attr->forks[left_fork].philosopher = my_num;
            pass_turn                                = true;

            phil->saved_doing = PHIL_ASK_LEFT_FORK;
        } else if ((forks_attr->forks[left_fork].philosopher != my_num) &
                   (forks_attr->forks[left_fork].philosopher != NOBODY)) {
            pass_turn = true;

            phil->saved_doing = PHIL_WAIT_LEFT_FORK;
        }

        /*
         * if both forks are available and claimed by no one else then the
         * philosopher may acquire them.
         */

        if (!pass_turn) {
            forks_attr->forks[right_fork].status      = FORK_IN_USE;
            forks_attr->forks[left_fork].status       = FORK_IN_USE;
            forks_attr->forks[right_fork].philosopher = NOBODY;
            forks_attr->forks[left_fork].philosopher  = NOBODY;

            forks_acquired = true;
        }
    }

    /* Release the mutex protecting the critical section */

    phil->saved_count = PHIL_ASK_RIGHT_FORK;
    cthread_mutex_unlock(forks_attr->fork_mutex);

    return forks_acquired;
}

/*******************************************************************************
 *
 * forks_put - Put down the right-hand and left-hand pair of forks
 *
 * This routine simply releases the forks a philosopher was using to eat.
 *
 * RETURNS: N/A
 * ERRNO: N/A
 *
 * \NOMANUAL
 */

static void
forks_put(phil_info_t *phil, int my_num, /* Philosopher's order number */
          int solution,                  /* Solution to execute */
          fork_attr_t *forks_attr)       /* Forks attributes*/
{
    int right_fork = my_num;
    int left_fork  = (my_num + 1) % forks_attr->num_forks;

    /* Acquire the mutex protecting the critical section */
    phil->saved_count = PHIL_WAIT_RIGHT_FORK;

    cthread_mutex_lock(forks_attr->fork_mutex);

    if (solution == TICKET_BASED) {
        /*
         * The forks are handed over to the philosophers on the immediate right
         * and immediate left of the philosopher that is done eating.
         */

        forks_attr->forks[right_fork].philosopher =
            (right_fork ? right_fork - 1 : (forks_attr->num_forks - 1));
        forks_attr->forks[left_fork].philosopher = left_fork;

        phil->saved_doing = PHIL_GIVE_FORK;
    } else { /* Claim-based solution */
        /* The forks are simply flagged as available */

        forks_attr->forks[right_fork].status = FORK_AVAILABLE;
        forks_attr->forks[left_fork].status  = FORK_AVAILABLE;
    }

    /* Release the mutex protecting the critical section */
    phil->saved_count = PHIL_ASK_LEFT_FORK;
    cthread_mutex_unlock(forks_attr->fork_mutex);
}

/*******************************************************************************
 *
 * philosopher_run - A philosopher task's run routine
 *
 * This routine is the starting point for each of the philosopher task.
 *
 * RETURNS: N/A
 * ERRNO: N/A
 *
 * \NOMANUAL
 */

static void
philosopher_run(void *arg)
{
    phil_info_t *phil              = arg;
    int my_num                     = phil->idx;         /* This philosopher's order number */
    int solution                   = phil->solution;    /* Solution to execute */
    phil_attr_t *phils_attr        = phil->philos_attr; /* Philosophers attributes */
    fork_attr_t *forks_attr        = phil->forks_attr;  /* Forks attributes*/
    stats_t *pStats                = phil->stats;       /* statistics data */
    struct cthread_barrier **b     = &barriers[cne_id()];
    phils_attr->i_am_ready[my_num] = true;

    if (cthread_set_thread_private(NULL, phil) < 0) {
        cne_printf("Failed to set private data for thread\n");
        return;
    }

    cthread_barrier_wait(*b);

    do {
        phil->doing = PHIL_THINKING;

        phil->saved_count = 0;
        cthread_sleep_msec(rand() & 0x3FF);

        phil->doing = PHIL_WANTS_TO_EAT;

        /*
         * If the forks cannot be acquired this implementation simply does
         * an active wait and checks again for the fork's availability after a
         * random milli-seconds of delay.
         */

        while (forks_get(phil, my_num, solution, forks_attr) == false) {
            if (solution == TICKET_BASED)
                phil->doing = PHIL_WAIT_FORK;
            if (phil->quit)
                break;
            pStats->go_hungry[my_num]++;
            phil->saved_count = 1;
            cthread_sleep_msec(rand() & 0x3FF);
        }

        phil->doing = PHIL_ASK_RIGHT_FORK;

        pStats->food_in_take[my_num]++;
        phil->saved_count = 2;
        cthread_sleep_msec(rand() & 0x3FF);

        forks_put(phil, my_num, solution, forks_attr);
    } while (phil->quit == 0);
}

/*******************************************************************************
 *
 * phil_demo_start - Dining philosopher demo
 *
 * This is the main entry of the dining philosopher's demo.
 *
 * If the demo is left to run forever (the default) then it will stop and
 * print statistics when the main task is resumed from the shell.
 *
 * RETURNS: N/A
 * ERRNO: N/A
 */

void
phil_demo_start(void *arg)
{
    struct app_info *a = arg;
    phil_info_t *phil;
    unsigned int solution;   /* Either one of the impl. solutions */
    phil_attr_t philos_attr; /* Philosopher attributes */
    fork_attr_t forks_attr;  /* Fork attributes */
    stats_t stats;           /* Statistic data */
    char name[32];

    /* By default let's run the claim-based solution */
    solution = TICKET_BASED;

    /* Default number of philosophers */
    philos_attr.num_phil = (a->num_threads > cne_max_threads()) ? cne_max_threads()
                                                                : a->num_threads;

    /* There is as many forks as there are philosophers */
    forks_attr.num_forks = philos_attr.num_phil;

    /* Create the various arrays used in this implementation */
    philos_attr.i_am_ready = calloc((size_t)philos_attr.num_phil, sizeof(BOOL));
    stats.food_in_take     = calloc((size_t)philos_attr.num_phil, sizeof(unsigned int));
    forks_attr.forks       = calloc((size_t)philos_attr.num_phil, sizeof(fork_t));
    stats.go_hungry        = calloc((size_t)philos_attr.num_phil, sizeof(unsigned int));

    if (forks_attr.forks) {
        /* Initialize the owner of the forks */
        for (int i = 0; i < philos_attr.num_phil; i++)
            forks_attr.forks[i].philosopher = -1;
    } else
        goto err;

    /* Create mutex semaphore protecting the critical sections */
    cthread_mutex_init("phil mutex", &forks_attr.fork_mutex, NULL);

    int id                     = cne_id();
    struct cthread_barrier **b = &barriers[id];

    snprintf(name, sizeof(name), "Barrier-%d", id);
    cthread_barrier_init(name, b, philos_attr.num_phil + 1);

    /* Create philosopher tasks */
    for (int i = 0; i < philos_attr.num_phil; i++) {
        phil = calloc(1, sizeof(phil_info_t));
        if (!phil)
            CNE_ERR_GOTO(error, "Unable to allocate philosopher structure %d\n", i);
        phil->doing       = PHIL_THINKING;
        phil->idx         = i;
        phil->solution    = solution;
        phil->philos_attr = &philos_attr;
        phil->forks_attr  = &forks_attr;
        phil->stats       = &stats;
        snprintf(name, sizeof(name), "Philosopher-%d", i);
        phil->cthd = cthread_create(name, philosopher_run, phil);
        if (!phil->cthd)
            CNE_RET("Unable to start philosopher cthread %d\n", i);
    }

    cthread_barrier_wait(*b);

    cthread_barrier_destroy(*b);

    do {
        cthread_sleep_msec(250);
    } while (phil_quit == 0);

error:
    /* Free resources */
    cthread_mutex_destroy(forks_attr.fork_mutex);
err:
    free(philos_attr.i_am_ready);
    free(stats.food_in_take);
    free(stats.go_hungry);
    free(forks_attr.forks);
}

void
phil_demo_quit(void)
{
    phil_quit = 1;
}
