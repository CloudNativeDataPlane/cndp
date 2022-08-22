/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <netinet/in.h>        // for htonl, htons, in_addr
#include <string.h>            // for memset

#include "txgen.h"        // for txgen, txgen_t
#include "ipv4.h"
#include "cne_inet.h"          // for IPv4_VERSION
#include "net/cne_ip.h"        // for cne_ipv4_hdr, cne_ipv4_cksum

/**
 *
 * txgen_ipv4_ctor - Construct the IPv4 header for a packet
 *
 * DESCRIPTION
 * Constructor for the IPv4 header for a given packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
txgen_ipv4_ctor(pkt_seq_t *pkt, void *hdr)
{
    struct cne_ipv4_hdr *ip = hdr;
    uint16_t tlen;

    /* IPv4 Header constructor */
    tlen = pkt->pktSize - pkt->ether_hdr_size;

    /* Zero out the header space */
    memset((char *)ip, 0, sizeof(struct cne_ipv4_hdr));

    ip->version_ihl = (IPv4_VERSION << 4) | (sizeof(struct cne_ipv4_hdr) / 4);

    ip->total_length    = htons(tlen);
    ip->time_to_live    = pkt->ttl;
    ip->type_of_service = 0;

    txgen.ident += 27; /* bump by a prime number */
    ip->packet_id       = htons(txgen.ident);
    ip->fragment_offset = 0;
    ip->next_proto_id   = pkt->ipProto;
    ip->src_addr        = htonl(pkt->ip_src_addr.s_addr);
    ip->dst_addr        = htonl(pkt->ip_dst_addr.s_addr);
    ip->hdr_checksum    = 0;
    ip->hdr_checksum    = cne_ipv4_cksum((const struct cne_ipv4_hdr *)ip);
}
