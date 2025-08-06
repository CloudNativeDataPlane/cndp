/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _CNE_TEST_H_
#define _CNE_TEST_H_

/**
 * @file
 * CNE Test
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#define TESTCNE_MAX_THREADS 32

typedef struct myargs {
    int argc;
    char **argv;
    int nb_threads;
    int initial_lcore;
    int debug;
    int verbose;
} myargs_t;

#include <stddef.h>        // for size_t

#include "log_test.h"
#include "loop_test.h"
#include "mbuf_test.h"
#include "mempool_test.h"
#include "mmap_test.h"
#include "ring_test.h"
#include "thread_test.h"
#include "uid_test.h"
#include "kvargs_test.h"
#include "xskdev_test.h"
#include "ring_profile.h"

#define SIZE_1MB (1024L * 1024L)
#define SIZE_1BB (1024L * 1024L * 1024L)

#define GENERAL_HEAP_SIZE (2 * SIZE_1MB)
#define HEAP_MEMORY_SIZE  SIZE_1MB

int my_prompt(int cont);
int init_tree(void);
int setup_cli(void);

int parse_args(myargs_t *a);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_TEST_H_ */
