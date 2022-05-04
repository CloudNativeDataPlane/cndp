/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_ETH_H
#define __CNET_ETH_H

/**
 * @file
 * CNET Ethernet support routines.
 */

#include <mempool.h>             // for mempool_t
#include <endian.h>              // for htole64
#include <net/ethernet.h>        // for ether_addr
#include <stdint.h>              // for uint64_t, uint16_t, uint8_t

#include "cnet_const.h"        // for iofunc_t
#include "cne_inet.h"          // for _in_addr
#include "cnet_netif.h"        // for netif

#ifdef __cplusplus
extern "C" {
#endif

#define IPV4_ADDR_SIZE 4

#define CNET_MAX_QIDS 16
struct eth_port_data {
    uint16_t pid;
    uint16_t nb_qids;
    uint16_t qids[CNET_MAX_QIDS];
};

struct eth_stats {
    uint64_t input_cnt;
    uint64_t lookup_ok;
    uint64_t lookup_failed;
    uint64_t raw_output;
    uint64_t eth_pkt_len;
    uint64_t ipv4_output;
};

static inline int
cnet_eth_compare(struct ether_addr *c1, struct ether_addr *c2)
{
    uint64_t p1 = *(uint64_t *)c1;
    uint64_t p2 = *(uint64_t *)c2;

    p1 &= htole64(0xFFFFFFFFFFFF0000L);
    p2 &= htole64(0xFFFFFFFFFFFF0000L);

    return p1 == p2;
}

static inline void
cnet_eth_set_broadcast(struct ether_addr *ea)
{
    uint16_t *p = (uint16_t *)&ea->ether_addr_octet;

    p[0] = 0xFFFF;
    p[1] = 0xFFFF;
    p[2] = 0xFFFF;
}

static inline void
cnet_eth_set_multicast(struct ether_addr *ea, struct in_addr *ip)
{
    ea->ether_addr_octet[0] = 0x01;
    ea->ether_addr_octet[1] = 0x00;
    ea->ether_addr_octet[2] = 0x5e;
    ea->ether_addr_octet[3] = (ip->s_addr >> 24) & 0xFF;
    ea->ether_addr_octet[4] = (ip->s_addr >> 16) & 0xFF;
    ea->ether_addr_octet[5] = (ip->s_addr >> 8) & 0xFF;
}

#ifdef __cplusplus
}
#endif

#endif /* __CNET_ETH_H */
