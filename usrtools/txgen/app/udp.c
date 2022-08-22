/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <netinet/in.h>        // for htons, htonl, in_addr
#include <stdint.h>            // for uint16_t

#include "udp.h"
#include "cne_inet.h"
#include "cne_common.h"         // for __cne_unused
#include "net/cne_ip.h"         // for cne_ipv4_hdr, cne_ipv4_udptcp_cksum
#include "net/cne_udp.h"        // for cne_udp_hdr

/**
 *
 * txgen_udp_hdr_ctor - UDP header constructor routine.
 *
 * DESCRIPTION
 * Construct the UDP header in a packer buffer.
 *
 * RETURNS: next header location
 *
 * SEE ALSO:
 */
void *
txgen_udp_hdr_ctor(pkt_seq_t *pkt, void *hdr, int type __cne_unused)
{
    uint16_t tlen;

    struct cne_ipv4_hdr *ipv4 = hdr;
    struct cne_udp_hdr *udp   = (struct cne_udp_hdr *)&ipv4[1];

    /* Create the UDP header */
    ipv4->src_addr = htonl(pkt->ip_src_addr.s_addr);
    ipv4->dst_addr = htonl(pkt->ip_dst_addr.s_addr);

    tlen                = pkt->pktSize - pkt->ether_hdr_size;
    ipv4->total_length  = htons(tlen);
    ipv4->next_proto_id = pkt->ipProto;

    tlen           = pkt->pktSize - (pkt->ether_hdr_size + sizeof(struct cne_ipv4_hdr));
    udp->dgram_len = htons(tlen);
    udp->src_port  = htons(pkt->sport);
    udp->dst_port  = htons(pkt->dport);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = cne_ipv4_udptcp_cksum(ipv4, (const void *)udp);
    if (udp->dgram_cksum == 0)
        udp->dgram_cksum = 0xFFFF;

    /* Return the original pointer for IP ctor */
    return hdr;
}
