/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation.
 */

#ifndef _MAIN_H_
#define _MAIN_H_

/**
 * @file
 *
 * CNE AF_XDP example for xskdev and pktdev APIs
 *
 * This file provides a APIs and configuration for the cndpfwd example.
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

#include <xskdev.h>        // for xskdev_info_t
#include <uds_connect.h>
#include <pktdev.h>            // for pktdev_rx_burst, pktdev_tx_burst
#include <pktdev_api.h>        // for pktdev_buf_alloc, pktdev_close
#include <txbuff.h>
#ifdef ENABLE_HYPERSCAN
#include <hs/hs.h>
#endif

#include <jcfg.h>        // for jcfg_info_t, jcfg_thd_t
#include <jcfg_process.h>

#include <net/cne_ip.h>        // for CNE_IPV4

#include "metrics.h"        // for metrics_info_t
#include "pktmbuf.h"        // for pktmbuf_t

#define MAX_THREADS    16
#define BURST_SIZE     256
#define MAX_BURST_SIZE 256
#define DST_LPORT      5

enum {
    FWD_DEBUG_STATS = (1 << 0), /**< Show debug stats */
    FWD_NO_METRICS  = (1 << 1), /**< Disable the Metrics function */
    FWD_NO_RESTAPI  = (1 << 2), /**< Disable the REST API */
    FWD_CLI_ENABLE  = (1 << 3), /**< Enable the CLI */
    FWD_ACL_STATS   = (1 << 4), /**< Enable printing ACL stats */
};

#define PKT_API_TAG          "pkt_api"         /**< Packet API json tag */
#define NO_METRICS_TAG       "no-metrics"      /**< json tag for no-metrics */
#define NO_RESTAPI_TAG       "no-restapi"      /**< json tag for no-restapi */
#define ENABLE_CLI_TAG       "cli"             /**< json tag to enable/disable CLI */
#define MODE_TAG             "mode"            /**< json tag to set the mode flag */
#define UDS_PATH_TAG         "uds_path"        /**< json tag for UDS to get xsk map fd */
#define XSK_MAP_PIN_PATH_TAG "xsk_pin_path"    /**< json tag for pinned BPF map to get xsk map fd */
#define FIB_RULES_TAG        "l3fwd-fib-rules" /**< json tag to set up static FIB entries */
#define HS_PATTERN_TAG       "hs-patterns"     /**< json tag for Hyperscan patterns */

#define MODE_DROP           "drop"           /**< Drop the received packets */
#define MODE_RX_ONLY        "rx-only"        /**< Alias for MODE_DROP */
#define MODE_LB             "lb"             /**< Loopback mode */
#define MODE_LOOPBACK       "loopback"       /**< Alias for MODE_LB */
#define MODE_TX_ONLY        "tx-only"        /**< Transmit only */
#define MODE_FWD            "fwd"            /**< L2 Forwarding mode */
#define MODE_L3_FWD         "l3fwd"          /**< L3 Forwarding mode */
#define MODE_ACL_STRICT     "acl-strict"     /**< ACL forwarding with permit list mode */
#define MODE_ACL_PERMISSIVE "acl-permissive" /**< ACL forwarding with deny list mode */
#define MODE_TX_ONLY_RX     "tx-only-rx"     /**< Transmit only plus RX enabled */
#define MODE_HYPERSCAN      "hyperscan"      /**< Enable Hyperscan forwarding mode */

typedef enum {
    UNKNOWN_TEST,
    DROP_TEST,
    LOOPBACK_TEST,
    TXONLY_TEST,
    FWD_TEST,
    L3_FWD_TEST,
    ACL_STRICT_TEST,
    ACL_PERMISSIVE_TEST,
    TXONLY_RX_TEST,
    HYPERSCAN_TEST
} test_t;

#define XSKDEV_API_NAME "xskdev"
#define XDPDEV_API_NAME "xdpdev" /* Deprecated */
#define PKTDEV_API_NAME "pktdev"

typedef enum { UNKNOWN_PKT_API, XSKDEV_PKT_API, PKTDEV_PKT_API } pkt_api_t;

struct create_txbuff_thd_priv_t {
    txbuff_t **txbuffs; /**< txbuff_t double pointer */
    pkt_api_t pkt_api;  /**< The packet API mode */
#ifdef ENABLE_HYPERSCAN
    hs_scratch_t *scratch; /**< Scratch per thread for Hyperscan */
#endif
};

/*
 * Statistics structure for ACL. Each such structure will be accessed by a
 * different set of threads, so to prevent false sharing, keep each on a
 * different cache line.
 */
struct acl_fwd_stats {
    uint64_t acl_permit;         /**< number of packets permitted by ACL */
    uint64_t acl_deny;           /**< number of packets denied by ACL */
    uint64_t acl_prefilter_drop; /**< number of packets dropped by ACL prefiltering */
} __cne_cache_aligned;

struct fwd_port {
    jcfg_thd_t *thd; /**< reference to processing thread */
    CNE_STD_C11
    union {
        xskdev_info_t *xsk; /**< XSKDEV information pointer */
        int lport;          /**< PKTDEV lport id */
    };
    pktmbuf_t *rx_mbufs[MAX_BURST_SIZE]; /**< RX mbufs array */
    uint64_t ipackets;                   /**< previous rx packets */
    uint64_t opackets;                   /**< previous tx packets */
    uint64_t ibytes;                     /**< previous rx bytes */
    uint64_t obytes;                     /**< previous tx bytes */
    uint64_t tx_overrun;                 /**< Number of mbufs failing to flush */
    struct acl_fwd_stats acl_stats;      /**< ACL-related stats */
    struct acl_fwd_stats prev_acl_stats; /**< previous values for ACL stats */
};

struct app_options {
    bool no_metrics; /**< Enable metrics*/
    bool no_restapi; /**< Enable REST API*/
    bool cli;        /**< Enable Cli*/
    char *mode;      /**< Application mode*/
    char *pkt_api;   /**< The pkt API mode */
};

struct fwd_info {
    jcfg_info_t *jinfo;        /**< JSON-C configuration */
    uint32_t flags;            /**< Application set of flags */
    test_t test;               /**< Test type to be run */
    volatile int timer_quit;   /**< flags to start and stop the application */
    pthread_barrier_t barrier; /**< Barrier for all threads */
    bool barrier_inited;       /**< True if barrier is inited */
    struct app_options opts;   /**< Application options*/
    pkt_api_t pkt_api;         /**< The packet API mode */
    uds_info_t *xdp_uds;       /**< UDS to get xsk map fd from */
    int burst;                 /**< Burst Size */
    char **fib_rules;          /**< FIB entries */
    uint16_t fib_size;         /**< Number of FIB entries */
    char *xsk_map_path;        /**< xsk_map pin path */
    char **hs_patterns;        /**< Hyperscan information */
    uint16_t hs_pattern_count; /**< Number of Hyperscan information entries */
    char **hs_expressions;     /**< List of parsed hyperscan regex expressions */
    unsigned int *hs_flags;    /**< List of hyperscan flags */
    unsigned int *hs_ids;      /**< List of hyperscan IDs */
#ifdef ENABLE_HYPERSCAN
    hs_database_t *hs_database; /**< Hyperscan database pointer */
    hs_scratch_t *hs_scratch;   /**< Scratch per thread for Hyperscan */
#endif
};

struct thread_func_arg_t {
    struct fwd_info *fwd; /**< global application information pointer */
    jcfg_thd_t *thd;      /**< reference to processing thread */
};

int parse_args(int argc, char **argv, struct fwd_info *fwd);
void thread_func(void *arg);
int enable_metrics(struct fwd_info *fwd);
int enable_uds_info(struct fwd_info *fwd);
void print_port_stats_all(struct fwd_info *fwd);
int acl_fwd_test(jcfg_lport_t *lport, struct fwd_info *fwd);
int acl_init(struct fwd_info *fwd);
int fwd_acl_clear(uds_client_t *c, const char *cmd, const char *params);
int fwd_acl_add_rule(uds_client_t *c, const char *cmd, const char *params);
int fwd_acl_build(uds_client_t *c, const char *cmd, const char *params);
int fwd_acl_read(uds_client_t *c, const char *cmd, const char *params);
int l3fwd_fib_init(struct fwd_info *fwd);
int l3fwd_fib_lookup(uint32_t *ip, struct ether_addr *eaddr, uint16_t *tx_port);

int hsfwd_init(struct fwd_info *fwd);
void hsfwd_finish(struct fwd_info *fwd);
int hsfwd_test(jcfg_lport_t *lport, struct fwd_info *fwd);

#define MAX_STRLEN_SIZE 16

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
    if (type) {
        size_t nlen = strnlen(type, MAX_STRLEN_SIZE);

        if (!strncasecmp(type, MODE_DROP, nlen) || !strncasecmp(type, MODE_RX_ONLY, nlen))
            return DROP_TEST;
        else if (!strncasecmp(type, MODE_LB, nlen) || !strncasecmp(type, MODE_LOOPBACK, nlen))
            return LOOPBACK_TEST;
        else if (!strncasecmp(type, MODE_TX_ONLY, nlen))
            return TXONLY_TEST;
        else if (!strncasecmp(type, MODE_FWD, nlen))
            return FWD_TEST;
        else if (!strncasecmp(type, MODE_L3_FWD, nlen))
            return L3_FWD_TEST;
        else if (!strncasecmp(type, MODE_ACL_STRICT, nlen))
            return ACL_STRICT_TEST;
        else if (!strncasecmp(type, MODE_ACL_PERMISSIVE, nlen))
            return ACL_PERMISSIVE_TEST;
        else if (!strncasecmp(type, MODE_TX_ONLY_RX, nlen))
            return TXONLY_RX_TEST;
        else if (!strncasecmp(type, MODE_HYPERSCAN, nlen) || !strncasecmp(type, "hs", nlen))
            return HYPERSCAN_TEST;
        else {
            cne_printf("[yellow]*** [magenta]Unknown mode[]: '[red]%s[]'\n", type);
            cne_printf("    [magenta]Known modes default[] '[cyan]%s[magenta]'[]:\n", MODE_DROP);
            cne_printf("      '[cyan]%s|%s[]', '[cyan]%s|%s[]', '[cyan]%s[]', ", MODE_DROP,
                       MODE_RX_ONLY, MODE_LB, MODE_LOOPBACK, MODE_TX_ONLY);
            cne_printf("'[cyan]%s[]', '[cyan]%s[]', '[cyan]%s[]', '[cyan]%s[]'\n", MODE_FWD,
                       MODE_ACL_STRICT, MODE_ACL_PERMISSIVE, MODE_HYPERSCAN);
        }
    }

    return UNKNOWN_TEST;
}

/**
 * Routine to convert the pkt_api string to a enum value
 *
 * @param type
 *   The string packet API type used to compare to known modes
 * @return
 *   The index value of the mode or UNKNOW value is returned.
 */
static inline uint8_t
get_pkt_api(const char *type)
{
    int ret = UNKNOWN_PKT_API;

    if (type) {
        size_t nlen = strnlen(type, MAX_STRLEN_SIZE);

        if (!strncasecmp(type, XSKDEV_API_NAME, nlen))
            ret = XSKDEV_PKT_API;
        else if (!strncasecmp(type, PKTDEV_API_NAME, nlen))
            ret = PKTDEV_PKT_API;
        else if (!strncasecmp(type, XDPDEV_API_NAME, nlen)) {
            cne_printf("[yellow]*** [magenta]API [orange]xdpdev [magenta]is deprecated![]\n");
            ret = XSKDEV_PKT_API;
            goto warn;
        } else {
            cne_printf("[yellow]*** [magenta]Unknown API type[] '[red]%s[]'\n", type);
            ret = XSKDEV_PKT_API;
            goto warn;
        }
    }

    return ret;
warn:
    cne_printf("    [magenta]Known API types[] '[cyan]%s[]' [magenta]and[] '[cyan]%s[]' "
               "[magenta], default[] '[cyan]%s[]'\n",
               XSKDEV_API_NAME, PKTDEV_API_NAME, XSKDEV_API_NAME);
    return ret;
}

static inline uint8_t
get_dst_lport(void *data)
{
    struct ether_header *eth    = (struct ether_header *)data;
    struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;

    return dst_addr->ether_addr_octet[DST_LPORT];
}

static inline void
rewrite_dst_mac(void *data, struct ether_addr *dst_mac)
{
    struct ether_header *eth       = (struct ether_header *)data;
    struct ether_addr *ether_dhost = (struct ether_addr *)&eth->ether_dhost;

    memcpy(ether_dhost, dst_mac, ETHER_ADDR_LEN);
}

#define MAC_REWRITE rewrite_dst_mac

#define PKTDEV_USE_NON_AVX 1
#if PKTDEV_USE_NON_AVX
static inline void
swap_mac_addresses(void *data)
{
    struct ether_header *eth    = (struct ether_header *)data;
    struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
    struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
    struct ether_addr tmp;

    tmp       = *src_addr;
    *src_addr = *dst_addr;
    *dst_addr = tmp;
}
#define MAC_SWAP swap_mac_addresses
#else
#define MAC_SWAP pktdev_mac_swap
#endif

#ifdef __cplusplus
}
#endif

#endif /* _MAIN_H_ */
