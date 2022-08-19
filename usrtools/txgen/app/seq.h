/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_SEQ_H_
#define _TXGEN_SEQ_H_

#include <cne_common.h>
#include <net/cne_ether.h>
#include <cne_inet.h>

#ifdef __cplusplus
extern "C" {
#endif

__extension__ typedef void *MARKER[0]; /**< generic marker for a point in a structure */

typedef struct pkt_seq_s {
    /* Packet type and information */
    struct ether_addr eth_dst_addr; /**< Destination Ethernet address */
    struct ether_addr eth_src_addr; /**< Source Ethernet address */

    struct in_addr ip_src_addr; /**< Source IPv4 address */
    struct in_addr ip_dst_addr; /**< Destination IPv4 address */
    uint32_t ip_mask;           /**< IPv4 Netmask value */

    uint16_t sport;          /**< Source lport value */
    uint16_t dport;          /**< Destination lport value */
    uint16_t ethType;        /**< IPv4 or IPv6 */
    uint16_t ipProto;        /**< TCP or UDP or ICMP */
    uint16_t ether_hdr_size; /**< Size of Ethernet header in packet for VLAN ID */

    uint16_t pktSize; /**< Size of packet in bytes not counting FCS */
    uint8_t ttl;      /**< TTL value for IPv4 headers */

    pkt_hdr_t hdr __cne_cache_aligned; /**< Packet header data */
    uint8_t pad[DEFAULT_MBUF_SIZE - sizeof(pkt_hdr_t)];
} pkt_seq_t __cne_cache_aligned;

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_SEQ_H_ */
