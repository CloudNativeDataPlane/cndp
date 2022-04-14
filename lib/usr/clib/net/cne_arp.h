/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 * Copyright (c) 2013 6WIND S.A.
 */

#ifndef _CNE_ARP_H_
#define _CNE_ARP_H_

/**
 * @file
 *
 * ARP-related defines
 */

// IWYU pragma: no_forward_declare cne_mempool

#include <stdint.h>              // for uint16_t, uint32_t, uint8_t
#include <cne_ether.h>           // for ether_addr
#include <net/ethernet.h>        // for ether_addr

#include "mempool.h"        // for cne_mempool
#include "pktmbuf.h"        // for pktmbuf_info_t, pktmbuf_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ARP header IPv4 payload.
 */
struct cne_arp_ipv4 {
    struct ether_addr arp_sha; /**< sender hardware address */
    uint32_t arp_sip;          /**< sender IP address */
    struct ether_addr arp_tha; /**< target hardware address */
    uint32_t arp_tip;          /**< target IP address */
} __cne_packed __cne_aligned(2);

/**
 * ARP header.
 */
struct cne_arp_hdr {
    uint16_t arp_hardware;  /* format of hardware address */
#define CNE_ARP_HRD_ETHER 1 /* ARP Ethernet address format */

    uint16_t arp_protocol;      /* format of protocol address */
    uint8_t arp_hlen;           /* length of hardware address */
    uint8_t arp_plen;           /* length of protocol address */
    uint16_t arp_opcode;        /* ARP opcode (command) */
#define CNE_ARP_OP_REQUEST    1 /* request to resolve address */
#define CNE_ARP_OP_REPLY      2 /* response to previous request */
#define CNE_ARP_OP_REVREQUEST 3 /* request proto addr given hardware */
#define CNE_ARP_OP_REVREPLY   4 /* response giving protocol address */
#define CNE_ARP_OP_INVREQUEST 8 /* request to identify peer */
#define CNE_ARP_OP_INVREPLY   9 /* response identifying peer */

    struct cne_arp_ipv4 arp_data;
} __cne_packed __cne_aligned(2);
/**
 * Make a RARP packet based on MAC addr.
 *
 * @param pi
 *   Pointer to the pktmbuf information structure.
 * @param mac
 *   Pointer to the MAC addr
 *
 * @return
 *   - RARP packet pointer on success, or NULL on error
 */
pktmbuf_t *cne_net_make_rarp_packet(pktmbuf_info_t *pi, const struct ether_addr *mac);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_ARP_H_ */
