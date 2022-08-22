/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include "ether.h"

#include <netinet/in.h>        // for htons

#include "seq.h"                  // for pkt_seq_t
#include "port-cfg.h"             // for port_info_t
#include "cne_common.h"           // for __cne_unused
#include <net/cne_ether.h>        // for ether_addr_copy, cne_ether_hdr

/**
 *
 * txgen_ether_hdr_ctor - Ethernet header constructor routine.
 *
 * DESCRIPTION
 * Construct the ethernet header for a given packet buffer.
 *
 * RETURNS: Pointer to memory after the ethernet header.
 *
 * SEE ALSO:
 */
char *
txgen_ether_hdr_ctor(port_info_t *info __cne_unused, pkt_seq_t *pkt, struct cne_ether_hdr *eth)
{
    /* src and dest addr */
    ether_addr_copy(&pkt->eth_src_addr, &eth->s_addr);
    ether_addr_copy(&pkt->eth_dst_addr, &eth->d_addr);

    /* normal ethernet header */
    eth->ether_type     = htons(pkt->ethType);
    pkt->ether_hdr_size = sizeof(struct cne_ether_hdr);

    return (char *)(eth + 1);
}
