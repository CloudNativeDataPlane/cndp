/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#ifndef __INC_PHIL_H
#define __INC_PHIL_H

#define FORK_AVAILABLE   0
#define FORK_IN_USE      1
#define NOBODY           -1
#define MAX_PHIL_THREADS 16

#define CLAIM_BASED  1
#define TICKET_BASED 2

#define PRINT_LOCK_ACQUIRE \
    do {                   \
        scrn_save();       \
    } while ((0))
#define PRINT_LOCK_RELEASE \
    do {                   \
        fflush(stdout);    \
        scrn_restore();    \
    } while ((0))

typedef int32_t BOOL;

/*
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
*/
enum {
    PHIL_THINKING = 0,
    PHIL_WANTS_TO_EAT,
    PHIL_WAIT_FORK,
    PHIL_EATING,
    PHIL_ASK_RIGHT_FORK,
    PHIL_WAIT_RIGHT_FORK,
    PHIL_ASK_LEFT_FORK,
    PHIL_WAIT_LEFT_FORK,
    PHIL_GIVE_FORK,
    PHIL_UNKNOWN_STATE
};

typedef struct phil_attr_t {
    int num_phil;                           /* number of philosophers */
    struct cthread *phil[MAX_PHIL_THREADS]; /* Points to an array of philosopher task IDs */
    BOOL *i_am_ready;                       /* Array collecting philosopher's ready status */
} phil_attr_t;

typedef struct fork_s {
    int status;      /* FORK_AVAILABLE or FORK_IN_USE */
    int philosopher; /* Philosopher requesting the fork */
} fork_t;

typedef struct fork_attr_s {
    fork_t *forks;                    /* The set of forks on the table */
    int num_forks;                    /* number of forks */
    struct cthread_mutex *fork_mutex; /* Protection mutex for the fork resource */
} fork_attr_t;

typedef struct stats_s {
    unsigned int *go_hungry;    /* The number of times a philosopher waits */
    unsigned int *food_in_take; /* the number of times a philosopher eats */
} stats_t;

typedef struct phil_info_s {
    struct cthread *cthd;
    unsigned int duration;
    unsigned int solution;    /* Either one of the impl. solutions */
    phil_attr_t *philos_attr; /* Philosopher attributes */
    fork_attr_t *forks_attr;  /* Fork attributes */
    stats_t *stats;           /* Statistic data */
    int idx;                  /* Loop counter */
    uint8_t doing;
    uint8_t saved_count;
    uint8_t saved_doing;
    uint8_t pad0;
    volatile BOOL quit;
} phil_info_t;

/* Forward declarations */
void phil_demo_start(void *arg);
void phil_demo_quit(void);

extern const char *doing_str[];

#endif /* __INC_PHIL_H */
