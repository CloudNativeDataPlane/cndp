/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation.
 */

#ifndef _MAIN_H_
#define _MAIN_H_

/**
 * @file
 *
 * CNE iBroker interface
 *
 * This file provides an example of ibroker interface.
 */

#include <stdint.h>        // for uint64_t, uint32_t, uint8_t
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NUM_DEFAULT_BROKERS  6
#define NUM_DEFAULT_SERVICES 5
#define MAX_THREADS          64

struct app_info {
    uint32_t flags;            /**< Application set of flags */
    pthread_barrier_t barrier; /**< Barrier for startup */
    int num_brokers;           /**< Number of brokers */
    int num_services;          /**< Number of services per broker */
    volatile int quit;         /**< flags to start and stop the application */
    pthread_t thread_ids[MAX_THREADS];
    pthread_t sender_id;
};

extern struct app_info *app; /**< global application information pointer */

extern uint64_t total_interrupts;

int srv_func(int vector, void *arg);
int parse_args(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* _MAIN_H_ */
