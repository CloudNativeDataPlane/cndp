/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <netinet/in.h>        // for htonl, htons, in_addr
#include <string.h>            // for memset

#include "txgen.h"        // for txgen, txgen_t
#include "ipv6.h"
#include "cne_inet.h"             // for IPv6_VERSION
#include "net/cne_ip.h"           // for cne_ipv6_hdr, cne_ipv6_cksum
#include "net/cne_inet6.h"        // for inet6_addr_copy_octs2octs

/**
 *
 * txgen_ipv6_ctor - Construct the IPv6 header for a packet
 *
 * DESCRIPTION
 * Constructor for the IPv6 header for a given packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
txgen_ipv6_ctor(pkt_seq_t *pkt, void *hdr)
{
    struct cne_ipv6_hdr *ip = hdr;
    uint16_t tlen;

    /* IPv6 Header constructor */
    tlen = pkt->pktSize - pkt->ether_hdr_size;

    /* Zero out the header space */
    memset((char *)ip, 0, sizeof(struct cne_ipv6_hdr));

    ip6_flow_hdr(ip, 0, 0); /* Fill the IPv6 version, Traffic Class and Flow Label */

    ip->payload_len = htons(tlen);
    ip->hop_limits  = pkt->ttl;

    txgen.ident += 27;        /* bump by a prime number */
    ip->proto = pkt->ipProto; /* Next Header */

    inet6_addr_ntoh((struct in6_addr *)&ip->src_addr, &pkt->ip6_src_addr);
    inet6_addr_ntoh((struct in6_addr *)&ip->dst_addr, &pkt->ip6_dst_addr);
}
