/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _PORT_CFG_H_
#define _PORT_CFG_H_

/**
 * @file
 */

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <cne_version.h>
#include <jcfg.h>

#include "seq.h"
#include "stats.h"
#include "ether.h"
#include "netdev_funcs.h"
#include "pcap.h"

#ifdef __cplusplus
extern "C" {
#endif

#define USER_PATTERN_SIZE 16

typedef struct port_sizes_s {
    uint64_t _64;        /**< Number of 64 byte packets */
    uint64_t _65_127;    /**< Number of 65-127 byte packets */
    uint64_t _128_255;   /**< Number of 128-255 byte packets */
    uint64_t _256_511;   /**< Number of 256-511 byte packets */
    uint64_t _512_1023;  /**< Number of 512-1023 byte packets */
    uint64_t _1024_1518; /**< Number of 1024-1518 byte packets */
    uint64_t broadcast;  /**< Number of broadcast packets */
    uint64_t multicast;  /**< Number of multicast packets */
    uint64_t jumbo;      /**< Number of Jumbo frames */
    uint64_t runt;       /**< Number of Runt frames */
    uint64_t unknown;    /**< Number of unknown sizes */
} port_sizes_t;

struct mbuf_table {
    uint16_t len;
    pktmbuf_t *m_table[DEFAULT_BURST_SIZE];
};

enum { /* Per lport flag bits */
       /* Supported packet modes non-exclusive */
       CAPTURE_PKTS = (1 << 5), /**< Capture received packets */

       /* Sending flags */
       SENDING_PACKETS = (1 << 0), /**< sending packets on this lport */
       SEND_FOREVER    = (1 << 1), /**< Send packets forever */

       /* Exclusive Packet sending modes */
       SEND_PCAP_PKTS = (1 << 12), /**< Send a pcap file of packets */

       RUNNING_FLAG = (1 << 8),
};

#define EXCLUSIVE_MODES SEND_PCAP_PKTS

typedef enum {
    ZERO_FILL_PATTERN = 1,
    ABC_FILL_PATTERN,
    USER_FILL_PATTERN,
    NO_FILL_PATTERN,
} fill_t;

typedef struct port_info_s {
    jcfg_lport_t *lport;                   /**< Configuration lport information */
    uint32_t flags;                        /**< Flags used to control txgen port */
    uint16_t tx_burst;                     /**< Number of TX burst packets */
    double tx_rate;                        /**< Percentage rate for tx packets with fractions */
    atomic_uint_least32_t port_flags;      /**< Special send flags */
    atomic_int_least64_t transmit_count;   /**< Packets to transmit loaded into current_tx_count */
    atomic_int_least64_t current_tx_count; /**< Current number of packets to send */
    uint64_t tx_cycles;                    /**< Number cycles between TX bursts */
    uint64_t tx_pps;                       /**< Transmit packets per seconds */
    uint64_t delta;                        /**< Delta value for latency testing */
    uint64_t tx_count;                     /**< Total count of tx attempts */
    uint64_t tx_next_cycle;                /**< Next cycle counter value to send next burst */

    /* Packet buffer space for traffic generator, shared for all packets per lport */
    pthread_mutex_t port_lock;            /**< Used to sync up packet constructor between cores */
    pkt_seq_t pkt;                        /**< Packet information */
    pkt_stats_t stats;                    /**< Statistics for a number of stats */
    port_sizes_t sizes;                   /**< Stats for the different packets sizes */
    eth_stats_t curr_stats;               /**< current lport statistics */
    eth_stats_t prev_stats;               /**< previous lport statistics */
    eth_stats_t rate_stats;               /**< current packet rate statistics */
    eth_stats_t base_stats;               /**< base lport statistics */
    uint64_t max_ipackets;                /**< Max seen input packet rate */
    uint64_t max_opackets;                /**< Max seen output packet rate */
    uint64_t max_missed;                  /**< Max missed packets seen */
    struct netdev_link link;              /**< Link Information like speed and duplex */
    struct mbuf_table tx_mbufs;           /**< mbuf holder for transmit packets */
    pktmbuf_t *pcap_mp;                   /**< Pool pointer for port PCAP TX mbufs */
    struct pktdev_info dev_info;          /**< info + driver name */
    fill_t fill_pattern_type;             /**< Type of pattern to fill with */
    char user_pattern[USER_PATTERN_SIZE]; /**< User set pattern values */

    pcap_info_t *pcap;    /**< PCAP information header */
    uint64_t pcap_cycles; /**< number of cycles for pcap sending */

    int32_t pcap_result;             /**< PCAP result of filter compile */
    struct bpf_program pcap_program; /**< PCAP filter program structure */
} port_info_t;

/**
 * Atomically subtract a 64-bit value from the tx counter.
 *
 * @param v
 *   A pointer to the atomic tx counter.
 * @param burst
 *   The value to be subtracted from the counter for tx burst size.
 * @return
 *   The number of packets to burst out
 */
static inline uint64_t
pkt_atomic64_tx_count(atomic_int_least64_t *v, int64_t burst)
{
    _Bool success;
    int64_t tmp2;

    int64_t tmp1 = atomic_load_explicit(v, memory_order_relaxed);
    do {
        if (tmp1 == 0)
            return 0;
        tmp2    = likely(tmp1 > burst) ? burst : tmp1;
        success = atomic_compare_exchange_weak(v, &tmp1, tmp1 - tmp2);
    } while (success == 0);

    return tmp2;
}

#ifdef __cplusplus
}
#endif

#endif /* _PORT_CFG_H_ */
