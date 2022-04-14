/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_PKT_H
#define __CNET_PKT_H

/**
 * @file
 * CNET packet support routines.
 */

#include <cne_ether.h>
#include <net/cne_udp.h>
#include <net/cne_tcp.h>
#include <net/cne_icmp.h>
#include <cnet_ether.h>
#include <cnet_ip_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The UDP/IP Pseudo header */
struct udp_ipv4 {
    struct ipv4_overlay ip; /* IPv4 overlay header */
    struct cne_udp_hdr udp; /* UDP header for protocol */
} __cne_packed;

/* The UDP/IP Pseudo header */
struct tcp_ipv4 {
    struct ipv4_overlay ip; /* IPv4 overlay header */
    struct cne_tcp_hdr tcp; /* tcp header for protocol */
} __cne_packed;

struct pkt_hdr {
    struct cne_ether_hdr eth; /**< Ethernet header */
    union {
        struct cne_ipv4_hdr ipv4; /**< IPv4 Header */
        struct cne_ipv6_hdr ipv6; /**< IPv6 Header */
        struct tcp_ipv4 tip;      /**< TCP + IPv4 Headers */
        struct udp_ipv4 uip;      /**< UDP + IPv4 Headers */
        uint64_t pad[8];          /**< Length of structures */
    } u;
} __cne_packed;

#ifdef __cplusplus
}
#endif

#endif /* __CNET_PKT_H */
