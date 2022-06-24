/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _FWD_H_
#define _FWD_H_

/**
 * @file
 *
 * CNE AF_XDP low-level abstraction used as a helper for Rust layer.
 *
 * This file provides a low-level abstraction to CNE applications for AF_XDP.
 */

#include <stdint.h>        // for uint64_t, uint32_t, uint8_t
#include <sys/types.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pthread.h>        // for pthread_barrier_t
#include <strings.h>        // for strcasecmp
#include <stdbool.h>        // for bool

#ifdef __cplusplus
extern "C" {
#endif

#include <jcfg.h>        // for jcfg_info_t, jcfg_thd_t
#include <jcfg_process.h>

#include "metrics.h"        // for metrics_info_t
#include "pktmbuf.h"        // for pktmbuf_t

#define MAX_THREADS 16
#define MAX_BURST   256
#define TX_BURST    128
#define DST_LPORT   5

enum {
    FWD_DEBUG_STATS = (1 << 0), /**< Show debug stats */
    FWD_NO_METRICS  = (1 << 1), /**< Disable the Metrics function */
    FWD_NO_RESTAPI  = (1 << 2), /**< Disable the REST API */
    FWD_CLI_ENABLE  = (1 << 3), /**< Enable the CLI */
};

#define NO_METRICS_TAG "no-metrics" /**< json tag for no-metrics */
#define NO_RESTAPI_TAG "no-restapi" /**< json tag for no-restapi */
#define ENABLE_CLI_TAG "cli"        /**< json tag to enable/disable CLI */
#define MODE_TAG       "mode"       /**< json tag to set the mode flag */

#define MODE_DROP     "drop"     /**< Drop the received packets */
#define MODE_RX_ONLY  "rx-only"  /**< Alias for MODE_DROP */
#define MODE_LB       "lb"       /**< Loopback mode */
#define MODE_LOOPBACK "loopback" /**< Alias for MODE_LB */
#define MODE_TX_ONLY  "tx-only"  /**< Transmit only */
#define MODE_FWD      "fwd"      /**< L2 Forwarding mode */

typedef enum { UNKNOWN_TEST, DROP_TEST, LOOPBACK_TEST, TXONLY_TEST, FWD_TEST } test_t;

typedef void (*thd_func_t)(void *);

typedef int (*test_t_func)(jcfg_lport_t *lport);

struct fwd_port {
    jcfg_thd_t *thd;                /**< reference to processing thread */
    int lport;                      /**< PKTDEV lport id */
    pktmbuf_t *rx_mbufs[MAX_BURST]; /**< RX mbufs array */
    uint64_t ipackets;              /**< previous rx packets */
    uint64_t opackets;              /**< previous tx packets */
    uint64_t ibytes;                /**< previous rx bytes */
    uint64_t obytes;                /**< previous tx bytes */
};

struct app_options {
    bool no_metrics; /**< Enable metrics*/
    bool no_restapi; /**< Enable REST API*/
    bool cli;        /**< Enable Cli*/
    char *mode;      /**< Application mode*/
};

struct fwd_test {
    test_t test;
    test_t_func cb_func;
};

struct fwd_info {
    jcfg_info_t *jinfo;          /**< JSON-C configuration */
    uint32_t flags;              /**< Application set of flags */
    test_t test;                 /**< Test type to be run */
    struct fwd_test test_arr[5]; /**< Test type and callback functions to run */
    volatile int timer_quit;     /**< flags to start and stop the application */
    pthread_barrier_t barrier;   /**< Barrier for all threads */
    struct app_options opts;     /**< Application options*/
};

int parse_args(int argc, char *const argv[], struct fwd_info *fwd);
int enable_metrics(struct fwd_info *fwd);
void print_port_stats_all(struct fwd_info *fwd);
void free_lport(jcfg_lport_t *lport);

/**
 * Routine to convert the type string to a enum value
 *
 * @param type
 *   The string mode type used to compare to known modes
 * @return
 *   The index value of the mode or UNKNOW value is returned.
 */
static inline uint8_t
get_app_mode(const char *type)
{
    if (!strcasecmp(type, MODE_DROP) || !strcasecmp(type, MODE_RX_ONLY))
        return DROP_TEST;
    else if (!strcasecmp(type, MODE_LB) || !strcasecmp(type, MODE_LOOPBACK))
        return LOOPBACK_TEST;
    else if (!strcasecmp(type, MODE_TX_ONLY))
        return TXONLY_TEST;
    else if (!strcasecmp(type, MODE_FWD))
        return FWD_TEST;

    return UNKNOWN_TEST;
}

#ifdef __cplusplus
}
#endif

#endif /* _FWD_H_ */
