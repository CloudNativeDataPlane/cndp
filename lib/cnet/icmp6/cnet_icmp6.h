/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __CNET_ICMP6_H
#define __CNET_ICMP6_H

/**
 * @file
 * CNET ICMP6 routines and constants.
 */

#include <stdint.h>        // for uint32_t

#include "cnet_const.h"        // for bool_t
#include "cnet_pcb.h"          // for pcb_hd

#ifdef __cplusplus
extern "C" {
#endif

/* ICMP6 parameters for Send and Receive buffer sizes. */
#define MAX_ICMP6_RCV_SIZE (1024 * 1024)
#define MAX_ICMP6_SND_SIZE MAX_ICMP6_RCV_SIZE

struct icmp6_entry {
    struct pcb_hd icmp6_hd; /**< Head of the pcb list for ICMP6 */
    bool cksum_on;          /**< Turn ICMP6 checksum on/off */
    uint32_t rcv_size;      /**< ICMP6 Receive Size */
    uint32_t snd_size;      /**< ICMP6 Send Size */
};

/**
 * Process the IPv6 ICMPv6 checksum.
 *
 * The IPv6 header should not contains options. The layer 4 checksum
 * must be set to 0 in the packet by the caller.
 *
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
static inline uint16_t
cne_ipv6_icmpv6_cksum(const struct cne_ipv6_hdr *ipv6_hdr, const void *icmp6_hdr)
{
    return cne_ipv6_udptcp_cksum(ipv6_hdr, icmp6_hdr);
}

static inline uint16_t
cne_ipv6_icmpv6_cksum_verify(const struct cne_ipv6_hdr *ipv6_hdr, const void *icmp6_hdr)
{
    uint16_t checksum = cne_ipv6_icmpv6_cksum(ipv6_hdr, icmp6_hdr);

    if (checksum == 0xffff)
        return 0;

    return -1;
}

#ifdef __cplusplus
}
#endif

#endif /* __CNET_ICMP6_H */
