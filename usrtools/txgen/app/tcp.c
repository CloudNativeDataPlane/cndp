/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation.
 */

#include <netinet/in.h>        // for htonl, htons, in_addr
#include <stdint.h>            // for uint16_t, uint32_t

#include "txgen.h"        // for DEFAULT_ACK_NUMBER, DEFAULT_PKT_NUMBER, DEF...
#include "tcp.h"
#include "cne_inet.h"           // for TCP_ACK_FLAG
#include "cne_common.h"         // for __cne_unused
#include "net/cne_ip.h"         // for cne_ipv4_hdr, cne_ipv4_udptcp_cksum
#include "net/cne_tcp.h"        // for cne_tcp_hdr
#include "net/cne_inet6.h"

static inline struct cne_tcp_hdr *
txgen_init_tcp_hdr(struct cne_tcp_hdr *tcp, pkt_seq_t *pkt)
{
    tcp->src_port  = htons(pkt->sport);
    tcp->dst_port  = htons(pkt->dport);
    tcp->sent_seq  = htonl(DEFAULT_PKT_NUMBER);
    tcp->recv_ack  = htonl(DEFAULT_ACK_NUMBER);
    tcp->data_off  = ((sizeof(struct cne_tcp_hdr) / sizeof(uint32_t)) << 4); /* Offset in words */
    tcp->tcp_flags = TCP_ACK_FLAG;                                           /* ACK */
    tcp->rx_win    = htons(DEFAULT_WND_SIZE);
    tcp->tcp_urp   = 0;

    tcp->cksum = 0;

    return tcp;
}

/**
 *
 * txgen_tcp_hdr_ctor - TCP header constructor routine.
 *
 * DESCRIPTION
 * Construct a TCP header in the packet buffer provided.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void *
txgen_tcp_hdr_ctor(pkt_seq_t *pkt, void *hdr, int type __cne_unused)
{
    uint16_t tlen;
    struct cne_tcp_hdr *tcp;

    tlen = pkt->pktSize - pkt->ether_hdr_size;
    if (likely(pkt->ethType == CNE_ETHER_TYPE_IPV4)) {
        struct cne_ipv4_hdr *ipv4 = (struct cne_ipv4_hdr *)hdr;
        tcp                       = (struct cne_tcp_hdr *)&ipv4[1];

        /* Create the TCP header */
        ipv4->src_addr = htonl(pkt->ip_src_addr.s_addr);
        ipv4->dst_addr = htonl(pkt->ip_dst_addr.s_addr);

        ipv4->total_length  = htons(tlen);
        ipv4->next_proto_id = pkt->ipProto;

        tcp = txgen_init_tcp_hdr(tcp, pkt);

        tcp->cksum = cne_ipv4_udptcp_cksum(ipv4, (const void *)tcp);

    }
#if CNET_ENABLE_IP6
    else if (pkt->ethType == CNE_ETHER_TYPE_IPV6) {
        struct cne_ipv6_hdr *ipv6 = (struct cne_ipv6_hdr *)hdr;
        tcp                       = (struct cne_tcp_hdr *)&ipv6[1];

        /* Create the TCP header */

        inet6_addr_ntoh((struct in6_addr *)&ipv6->src_addr, &pkt->ip6_src_addr);
        inet6_addr_ntoh((struct in6_addr *)&ipv6->dst_addr, &pkt->ip6_dst_addr);

        ipv6->payload_len = htons(tlen);
        ipv6->proto       = pkt->ipProto;

        tcp = txgen_init_tcp_hdr(tcp, pkt);

        tcp->cksum = cne_ipv6_udptcp_cksum(ipv6, (const void *)tcp);
    }
#endif

    /* In this case we return the original value to allow IP ctor to work */
    return hdr;
}
