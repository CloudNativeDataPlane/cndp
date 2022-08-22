/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <netinet/in.h>        // for htonl, htons, in_addr
#include <stdint.h>            // for uint16_t, uint32_t

#include "txgen.h"        // for DEFAULT_ACK_NUMBER, DEFAULT_PKT_NUMBER, DEF...
#include "tcp.h"
#include "cne_inet.h"           // for TCP_ACK_FLAG
#include "cne_common.h"         // for __cne_unused
#include "net/cne_ip.h"         // for cne_ipv4_hdr, cne_ipv4_udptcp_cksum
#include "net/cne_tcp.h"        // for cne_tcp_hdr

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

    struct cne_ipv4_hdr *ipv4 = (struct cne_ipv4_hdr *)hdr;
    struct cne_tcp_hdr *tcp   = (struct cne_tcp_hdr *)&ipv4[1];

    /* Create the TCP header */
    ipv4->src_addr = htonl(pkt->ip_src_addr.s_addr);
    ipv4->dst_addr = htonl(pkt->ip_dst_addr.s_addr);

    tlen                = pkt->pktSize - pkt->ether_hdr_size;
    ipv4->total_length  = htons(tlen);
    ipv4->next_proto_id = pkt->ipProto;

    tcp->src_port  = htons(pkt->sport);
    tcp->dst_port  = htons(pkt->dport);
    tcp->sent_seq  = htonl(DEFAULT_PKT_NUMBER);
    tcp->recv_ack  = htonl(DEFAULT_ACK_NUMBER);
    tcp->data_off  = ((sizeof(struct cne_tcp_hdr) / sizeof(uint32_t)) << 4); /* Offset in words */
    tcp->tcp_flags = TCP_ACK_FLAG;                                           /* ACK */
    tcp->rx_win    = htons(DEFAULT_WND_SIZE);
    tcp->tcp_urp   = 0;

    tcp->cksum = 0;
    tcp->cksum = cne_ipv4_udptcp_cksum(ipv4, (const void *)tcp);

    /* In this case we return the original value to allow IP ctor to work */
    return hdr;
}
