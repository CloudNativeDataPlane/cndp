/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_H_
#define _TXGEN_H_

#include <stdatomic.h>        // for atomic_compare_exchange_weak, atomic_load_...
#include <stdio.h>            // for NULL, fclose, getline, popen, printf, FILE
#include <stdlib.h>           // for free
#include <stdint.h>           // for uint32_t, uint64_t, uint16_t
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <net/if.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <libgen.h>
#include <bsd/string.h>          // for strlcat
#include <net/ethernet.h>        // for ETHER_CRC_LEN
#include <stdbool.h>             // for bool
#include <strings.h>             // for strcasecmp
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <assert.h>
#include <time.h>
#include <cne.h>
#include <cne_log.h>
#include <cne_tailq.h>
#include <cne_common.h>        // for CNE_MAX_ETHPORTS
#include <cne_per_thread.h>
#include <cne_cycles.h>
#include <cne_prefetch.h>
#include <cne_system.h>
#include <cne_branch_prediction.h>
#include <net/cne_ether.h>
#include <pktdev.h>        // for PKTDEV_FOREACH
#include <cne_ring.h>
#include <mempool.h>
#include <pktmbuf.h>        // for pktmbuf_t
#include <net/cne_ip.h>
#include <net/cne_udp.h>
#include <net/cne_tcp.h>
#include <metrics.h>        // for metrics_info_t
#include <cne_inet.h>
#include <_pcap.h>
#include <cksum.h>
#include <jcfg.h>        // for jcfg_info_t
#include <cli.h>

#include "port-cfg.h"        // for port_info_t
#include "seq.h"
#include "version.h"        // for TXGEN_VERSION
#include "capture.h"        // for capture_t
#include "ether.h"          // for eth_stats_t

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MATRIX_ENTRIES 128
#define MAX_STRING         256
#define Million            (uint64_t)(1000000ULL)

#define iBitsTotal(_x) (uint64_t)(((_x.ipackets * PKT_OVERHEAD_SIZE) + _x.ibytes) * 8)
#define oBitsTotal(_x) (uint64_t)(((_x.opackets * PKT_OVERHEAD_SIZE) + _x.obytes) * 8)

#define _do(_exp) \
    do {          \
        _exp;     \
    } while ((0))

#ifndef PKTDEV_FOREACH
#define PKTDEV_FOREACH(p) for (int _p = 0; _p < txgen.nb_ports; _p++)
#endif

#define forall_ports(_action)        \
    do {                             \
        PKTDEV_FOREACH (pid) {       \
            port_info_t *info;       \
                                     \
            info = &txgen.info[pid]; \
            if (info->lport == NULL) \
                continue;            \
            _action;                 \
        }                            \
    } while ((0))

#define foreach_port(_portlist, _action)                  \
    do {                                                  \
        uint64_t *_pl = (uint64_t *)&_portlist;           \
        uint16_t idx, bit;                                \
                                                          \
        PKTDEV_FOREACH (pid) {                            \
            port_info_t *info;                            \
                                                          \
            idx = (pid / (sizeof(uint64_t) * 8));         \
            bit = (pid - (idx * (sizeof(uint64_t) * 8))); \
            if ((_pl[idx] & (1LL << bit)) == 0)           \
                continue;                                 \
            info = &txgen.info[pid];                      \
            if (info->lport == NULL)                      \
                continue;                                 \
            _action;                                      \
        }                                                 \
    } while ((0))

enum {
    COLUMN_WIDTH_0 = 22,
    COLUMN_WIDTH_1 = 22,
    COLUMN_WIDTH_3 = 22,

    /* Row locations for start of data */
    PORT_STATE_ROWS = 1,
    LINK_STATE_ROWS = 4,
    PKT_SIZE_ROWS   = 10,
    PKT_TOTALS_ROWS = 7,
    IP_ADDR_ROWS    = 12,

    PORT_STATE_ROW = 2,
    LINK_STATE_ROW = (PORT_STATE_ROW + PORT_STATE_ROWS),
    PKT_SIZE_ROW   = (LINK_STATE_ROW + LINK_STATE_ROWS),
    PKT_TOTALS_ROW = (PKT_SIZE_ROW + PKT_SIZE_ROWS),
    IP_ADDR_ROW    = (PKT_TOTALS_ROW + PKT_TOTALS_ROWS),

    DEFAULT_NETMASK     = 0xFFFFFF00,
    DEFAULT_IP_ADDR     = (192 << 24) | (168 << 16),
    DEFAULT_TX_COUNT    = 0, /* Forever */
    DEFAULT_TX_RATE     = 100,
    DEFAULT_PRIME_COUNT = 1,
    DEFAULT_SRC_PORT    = 1234,
    DEFAULT_DST_PORT    = 5678,
    DEFAULT_TTL         = 4,
    DEFAULT_PKT_NUMBER  = 0x012345678,
    DEFAULT_ACK_NUMBER  = 0x012345690,
    DEFAULT_WND_SIZE    = 8192,
    MAX_ETHER_TYPE_SIZE = 0x600,

    INTER_FRAME_GAP       = 12, /**< in bytes */
    START_FRAME_DELIMITER = 1,
    PKT_PREAMBLE_SIZE     = 7, /**< in bytes */
    PKT_OVERHEAD_SIZE =
        (INTER_FRAME_GAP + START_FRAME_DELIMITER + PKT_PREAMBLE_SIZE + ETHER_CRC_LEN),

    PCAP_PAGE_SIZE = 25, /**< Size of the PCAP display page */
};

#define CNE_ETHER_MIN_LEN 64
#define CNE_ETHER_MAX_LEN 1518
#define MIN_PKT_SIZE      (CNE_ETHER_MIN_LEN - ETHER_CRC_LEN)
#define MAX_PKT_SIZE      (CNE_ETHER_MAX_LEN - ETHER_CRC_LEN)

typedef pktmbuf_t pktmbuf_t;

struct app_options {
    bool no_metrics; /**< Enable metrics*/
    bool no_restapi; /**< Enable REST API*/
    bool cli;        /**< Enable Cli*/
    char *mode;      /**< Application mode*/
};

/* Ethernet addresses of lports */
typedef struct txgen_s {
    jcfg_info_t *jinfo;                 /**< JSON-C configuration */
    uint32_t flags;                     /**< Flag values */
    uint16_t ident;                     /**< IPv4 ident value */
    uint16_t last_row;                  /**< last static row of the screen */
    uint16_t eth_min_pkt;               /* Minimum Ethernet packet size without CRC */
    uint16_t eth_max_pkt;               /* Max packet size, could be jumbo or not */
    uint64_t hz;                        /**< Number of events per seconds */
    port_info_t info[CNE_MAX_ETHPORTS]; /**< Port information */
    eth_stats_t cumm_rate_totals;       /**< lport rates total values */
    struct app_options opts;
    uint64_t max_total_ipackets; /**< Total Max seen input packet rate */
    uint64_t max_total_opackets; /**< Total Max seen output packet rate */
    uint64_t max_total_ibytes;   /**< Total Max seen input byte rate */
    uint64_t max_total_obytes;   /**< Total Max seen output byte rate */
    capture_t captures[CNE_MAX_ETHPORTS];
} txgen_t;

enum {                                /* TXGen flags bits, skip the first 16 bits */
       DO_TX_SETUP       = (1 << 16), /**< Do the TX setup of packets */
       DO_TX_FLUSH       = (1 << 17), /**< Do a TX Flush by sending all of the pkts in the queue */
       PRINT_LABELS_FLAG = (1 << 18), /**< Print constant labels on stats display */
       PROMISCUOUS_ON_FLAG = (1 << 19), /**< Enable promiscuous mode */
       PCAP_PAGE_FLAG      = (1 << 20), /**< Display the PCAP page */
       UPDATE_DISPLAY_FLAG = (1 << 31)
};

extern txgen_t txgen;

void txgen_page_display(void);

void txgen_packet_ctor(port_info_t *info);
void txgen_packet_rate(port_info_t *info);

void txgen_launch_one_lcore(void *arg);
void txgen_stats(void *arg);
uint64_t txgen_wire_size(port_info_t *info);
void txgen_input_start(void);

static __inline__ void
txgen_set_port_flags(port_info_t *info, uint32_t flags)
{
    _Bool result;
    uint32_t val = atomic_load_explicit(&info->port_flags, memory_order_relaxed);
    do {
        result = atomic_compare_exchange_weak(&(info->port_flags), &val, (val | flags));
    } while (result == 0);
}

static __inline__ void
txgen_clr_port_flags(port_info_t *info, uint32_t flags)
{
    _Bool result;
    uint32_t val = atomic_load_explicit(&info->port_flags, memory_order_relaxed);
    do {
        result = atomic_compare_exchange_weak(&(info->port_flags), &val, (val & ~flags));
    } while (result == 0);
}

static __inline__ int
txgen_tst_port_flags(port_info_t *info, uint32_t flags)
{
    if (atomic_load(&info->port_flags) & flags)
        return 1;
    return 0;
}

/* onOff values */
enum { DISABLE_STATE = 0, ENABLE_STATE = 1 };

static __inline__ uint32_t
estate(const char *state)
{
    return (!strcasecmp(state, "on") || !strcasecmp(state, "enable") || !strcasecmp(state, "start"))
               ? ENABLE_STATE
               : DISABLE_STATE;
}

/**
 * Function returning string of version number: "- Version:x.y.x (CNDP-x.y.z)"
 * @return
 *     string
 */
static inline const char *
txgen_version(void)
{
    static char pkt_version[64];

    if (pkt_version[0] != 0)
        return pkt_version;

    strlcat(pkt_version, TXGEN_VERSION, sizeof(pkt_version));
    return pkt_version;
}

/**
 *
 * do_command - Internal function to execute a shell command and grab the output.
 *
 * DESCRIPTION
 * Internal function to execute a shell command and grab the output from the
 * command.
 *
 * RETURNS: Number of lines read.
 *
 * SEE ALSO:
 */
static __inline__ int
do_command(const char *cmd, int (*display)(char *, int))
{
    FILE *f;
    int i;
    char *line       = NULL;
    size_t line_size = 0;

    f = popen(cmd, "r");
    if (f == NULL) {
        cne_printf("Unable to run '%s' command", cmd);
        return -1;
    }

    i = 0;
    while (getline(&line, &line_size, f) > 0)
        i = display(line, i);

    if (f)
        fclose(f);
    if (line)
        free(line);

    return i;
}

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_H_ */
