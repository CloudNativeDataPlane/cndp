/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_STATS_H_
#define _TXGEN_STATS_H_

#include <stdint.h>        // for uint64_t
#ifdef __cplusplus
extern "C" {
#endif

typedef struct pkt_stats_s {
    uint64_t arp_pkts;     /**< Number of ARP packets received */
    uint64_t echo_pkts;    /**< Number of ICMP echo requests received */
    uint64_t ip_pkts;      /**< Number of IPv4 packets received */
    uint64_t ipv6_pkts;    /**< Number of IPv6 packets received */
    uint64_t vlan_pkts;    /**< Number of VLAN packets received */
    uint64_t dropped_pkts; /**< Hyperscan dropped packets */
    uint64_t unknown_pkts; /**< Number of Unknown packets */
    uint64_t tx_failed;    /**< Transmits that failed to send */
    uint64_t imissed;      /**< Number of RX missed packets */
} pkt_stats_t;

struct port_info_s;

/**
 * Determine the link status a lport. The status information is put in the info structure.
 *
 * @param info
 *   The port information structure pointer to get link status from
 * @param wait
 *   A wait to determine if the routine should wait for link status to be up.
 */
void txgen_get_link_status(struct port_info_s *info, int wait);

/**
 * Gather stats for each lportid
 *
 * @param lportid
 *   The lport ID index to gather stats from
 */
void txgen_process_stats(int lportid);

/**
 * Display the lport statistics, if enabled.
 */
void txgen_page_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_STATS_H_ */
