/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation.
 */

#include <netinet/in.h>        // for htons, htonl, in_addr
#include <stdint.h>            // for uint16_t

#include "udp.h"
#include "cne_inet.h"
#include "cne_common.h"         // for __cne_unused
#include "net/cne_ip.h"         // for cne_ipv4_hdr, cne_ipv4_udptcp_cksum
#include "net/cne_udp.h"        // for cne_udp_hdr

static inline struct cne_udp_hdr *
txgen_init_udp_hdr(struct cne_udp_hdr *udp, pkt_seq_t *pkt, uint16_t ip_hdr_sz)
{
    uint16_t tlen;

    tlen           = pkt->pktSize - (pkt->ether_hdr_size + ip_hdr_sz);
    udp->dgram_len = htons(tlen);
    udp->src_port  = htons(pkt->sport);
    udp->dst_port  = htons(pkt->dport);

    udp->dgram_cksum = 0;

    return udp;
}

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
    struct cne_udp_hdr *udp = NULL;

    tlen = pkt->pktSize - pkt->ether_hdr_size;
    if (likely(pkt->ethType == CNE_ETHER_TYPE_IPV4)) {
        struct cne_ipv4_hdr *ipv4 = hdr;
        udp                       = (struct cne_udp_hdr *)&ipv4[1];

        /* Create the UDP header */
        ipv4->src_addr = htonl(pkt->ip_src_addr.s_addr);
        ipv4->dst_addr = htonl(pkt->ip_dst_addr.s_addr);

        ipv4->total_length  = htons(tlen);
        ipv4->next_proto_id = pkt->ipProto;

        udp              = txgen_init_udp_hdr(udp, pkt, sizeof(struct cne_ipv4_hdr));
        udp->dgram_cksum = cne_ipv4_udptcp_cksum(ipv4, (const void *)udp);

    } else if (pkt->ethType == CNE_ETHER_TYPE_IPV6) {
        struct cne_ipv6_hdr *ipv6 = hdr;
        udp                       = (struct cne_udp_hdr *)&ipv6[1];

        /* Create the UDP header */

        inet6_addr_ntoh((struct in6_addr *)&ipv6->src_addr, &pkt->ip6_src_addr);
        inet6_addr_ntoh((struct in6_addr *)&ipv6->dst_addr, &pkt->ip6_dst_addr);

        ipv6->payload_len = htons(tlen);
        ipv6->proto       = pkt->ipProto;

        udp              = txgen_init_udp_hdr(udp, pkt, sizeof(struct cne_ipv6_hdr));
        udp->dgram_cksum = cne_ipv6_udptcp_cksum(ipv6, (const void *)udp);
    }

    if (udp && udp->dgram_cksum == 0)
        udp->dgram_cksum = 0xFFFF;

    /* Return the original pointer for IP ctor */
    return hdr;
}
