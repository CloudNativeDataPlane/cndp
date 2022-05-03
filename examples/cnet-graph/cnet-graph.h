/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _CNET_GRAPH_H_
#define _CNET_GRAPH_H_

/**
 * @file
 *
 * CNE Graph Node example code for CNET.
 *
 * A simple cnet-graph example using the graph node libraries.
 */

#include <stdint.h>        // for uint64_t, uint32_t
#include <sys/types.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <strings.h>        // for strcasecmp
#include <stdbool.h>        // for bool
#include <pthread.h>        // for pthread_barrier_t

#ifdef __cplusplus
extern "C" {
#endif

#include <cne_graph.h>        // for cne_graph_t
#include <jcfg.h>             // for jcfg_info_t
#include <jcfg_process.h>

#include "metrics.h"        // for metrics_info_t
#include "pktmbuf.h"        // for pktmbuf_t

#define MAX_THREADS    16
#define BURST_SIZE     128
#define MAX_BURST_SIZE 256
#define DST_LPORT      5

enum {
    FWD_DEBUG_STATS      = (1 << 0), /**< Show debug stats */
    FWD_NO_METRICS       = (1 << 1), /**< Disable the Metrics function */
    FWD_NO_RESTAPI       = (1 << 2), /**< Disable the REST API */
    FWD_CLI_ENABLE       = (1 << 3), /**< Enable the CLI */
    FWD_ENABLE_UDP_CKSUM = (1 << 4), /**< Enable the UDP checksum function */
};

#define MODE_DROP     "drop"     /**< Drop the received packets */
#define MODE_RX_ONLY  "rx-only"  /**< Alias for MODE_DROP */
#define MODE_LB       "lb"       /**< Loopback mode */
#define MODE_LOOPBACK "loopback" /**< Alias for MODE_LB */
#define MODE_TX_ONLY  "tx-only"  /**< Transmit only */
#define MODE_CONNECT  "connect"  /**< Open a connection */

// clang-format off
typedef enum {
    UNKNOWN_TEST,
    DROP_TEST,
    LOOPBACK_TEST,
    TXONLY_TEST,
    MAX_TESTS
} test_t;

#define MODE_MAP_DATA                   \
    {                                   \
        {MODE_DROP,     DROP_TEST},     \
        {MODE_RX_ONLY,  DROP_TEST},     \
        {MODE_LB,       LOOPBACK_TEST}, \
        {MODE_LOOPBACK, LOOPBACK_TEST}, \
        {MODE_TX_ONLY,  TXONLY_TEST}    \
    }
// clang-format on

#define NO_METRICS_TAG "no-metrics" /**< json tag for no-metrics */
#define NO_RESTAPI_TAG "no-restapi" /**< json tag for no-restapi */
#define ENABLE_CLI_TAG "cli"        /**< json tag to enable/disable CLI */

struct fwd_port {
    int lport;                           /**< PKTDEV lport id */
    pktmbuf_t *rx_mbufs[MAX_BURST_SIZE]; /**< RX mbufs array */
    uint64_t ipackets;                   /**< previous rx packets */
    uint64_t opackets;                   /**< previous tx packets */
    uint64_t ibytes;                     /**< previous rx bytes */
    uint64_t obytes;                     /**< previous tx bytes */
};

struct app_options {
    bool no_metrics; /**< Enable metrics*/
    bool no_restapi; /**< Enable REST API*/
    bool cli;        /**< Enable Cli*/
    unsigned int node_cnt;
    unsigned int node_sz;
    const char **nodes;
};

typedef struct graph_info_s {
    cne_graph_t id;
    struct cne_graph *graph;
    int cnt;
    int nb_patterns;
    const char **patterns;
} graph_info_t;

#define MAX_GRAPH_COUNT 128

struct cnet_info {
    struct cnet *cnet;                        /**< CNET structure pointer */
    test_t test;                              /**< Test type to be run */
    int burst;                                /**< Burst Size */
    jcfg_info_t *jinfo;                       /**< JSON-C configuration */
    uint32_t flags;                           /**< Application set of flags */
    volatile int timer_quit;                  /**< flags to start and stop the application */
    struct app_options opts;                  /**< Application options*/
    pthread_barrier_t barrier;                /**< Barrier for all threads */
    bool barrier_inited;                      /**< Barrier for all threads */
    graph_info_t graph_info[MAX_GRAPH_COUNT]; /**< Graph information */
    void *netlink;                            /**< Network information */
    char *connect;                            /**< Connection string */
};

extern struct cnet_info *cinfo; /**< global application information pointer */

#define MAX_STRLEN_SIZE 16

/**
 * Routine to convert the type string to a enum value
 *
 * @param type
 *   The string mode type used to compare to known modes
 * @return
 *   The index value of the mode or UNKNOWN value is returned.
 */
static inline uint8_t
get_app_mode(const char *type)
{
    if (type) {
        size_t nlen = strnlen(type, MAX_STRLEN_SIZE);
        struct {
            const char *name;
            int mode;
        } modes[] = MODE_MAP_DATA;

        for (int i = 0; i < cne_countof(modes); i++)
            if (!strncasecmp(type, modes[i].name, nlen))
                return modes[i].mode;

        cne_printf("[yellow]*** [magenta]Unknown mode[]: '[red]%s[]'\n", type);
        cne_printf("    [magenta]Known modes[]: ");
        for (int i = 0; i < cne_countof(modes); i++)
            cne_printf("'[cyan]%s[]' ", modes[i].name);
        cne_printf("\n");
    }

    return UNKNOWN_TEST;
}

int parse_args(int argc, char **argv);
void thread_func(void *arg);
void thread_timer_func(void *arg);
void netlink_thread(void *arg);
int enable_metrics(void);

#ifdef __cplusplus
}
#endif

#endif /* _CNET_GRAPH_H_ */
