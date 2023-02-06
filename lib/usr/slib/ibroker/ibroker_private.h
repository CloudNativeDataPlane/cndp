/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */

#ifndef _IBROKER_PRIV_H_
#define _IBROKER_PRIV_H_

/**
 * @file
 * CNE UIPI-Broker
 *
 * This library provides a simple interface to use UIPI features. The implementation will
 * abstract as much as possible to give the developer an opportunity to use UIPI features.
 *
 * Giving the developer an easy to use interface to the UIPI or interrupt based services.
 */

#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/syscall.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void ibroker_t; /**< Opaque object for ibroker */

/**
 * short definition to mark a function parameter unused
 */
#define __ibroker_unused __attribute__((__unused__))

#define HIDE_API __attribute__((visibility("hidden")))

#define BROKER_IS_VALID(_b)  ((_b >= 0) && (_b < IBROKER_MAX_COUNT))
#define SERVICE_IS_VALID(_s) ((_s >= 0) && (_s < IBROKER_MAX_SERVICES))

struct ibroker;

struct ibroker_srv {
    bool enabled;                 /**< true if service is enabled */
    char name[IBROKER_NAME_SIZE]; /**< Name of service */
    int uintr_fd;                 /**< UINTR_FD value for a given service */
    uint64_t uipi_index;          /**< UIPI index value from uintr_register_sender() call */
    ibroker_func_t func;          /**< Service function pointer */
    void *arg;                    /**< Service function argument pointer */

    uint64_t call_cnt; /**< Number of service calls */
    uint64_t err_cnt;  /**< Number of errors returned from service */
};

struct ibroker {
    broker_id_t bid;              /**< Broker ID */
    char name[IBROKER_NAME_SIZE]; /**< Name of this ibroker instance */
    int tid;                      /**< Thread ID value from gettid() */

    struct ibroker_srv services[IBROKER_MAX_SERVICES]; /**< Service list */

    uint64_t intrs;           /**< Number of interrupts */
    uint64_t invalid_service; /**< Invalid service number */
};

/**
 * Declare a per thread pointer for ibroker and a define to access the variable.
 */
extern __thread struct ibroker *per_thread_ibroker;
#define this_ibroker per_thread_ibroker

#ifdef __cplusplus
}
#endif

#endif /* _IBROKER_PRIV_H_ */
