/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation.
 */

#ifndef _MAIN_H_
#define _MAIN_H_

/**
 * @file
 *
 * CNE AF_XDP low-level abstraction example
 *
 * This file provides a low-level abstraction to CNE applications for AF_XDP.
 */

#include <stdint.h>        // for uint64_t, uint32_t, uint8_t
#include <sys/types.h>
#include <strings.h>        // for strcasecmp

#ifdef __cplusplus
extern "C" {
#endif

#include <jcfg.h>        // for jcfg_t
#include <jcfg_process.h>

#define NUM_DEFAULT_PHILOSPHERS 16

struct app_info {
    jcfg_info_t *jinfo; /**< JSON-C configuration */
    uint32_t flags;     /**< Application set of flags */
    int num_threads;    /**< Number of Philosphers or threads */
    volatile int quit;  /**< flags to start and stop the application */
};

extern struct app_info *app; /**< global application information pointer */

#define APP_VERBOSE_FLAG (1 << 0) /**< Output more information about setup and config */
#define APP_DEBUG_STATS  (1 << 1) /**< Output more debug stats on screen */

int parse_args(int argc, char **argv);
void thread_func(void *arg);
void phil_create_barriers(void);

#ifdef __cplusplus
}
#endif

#endif /* _MAIN_H_ */
