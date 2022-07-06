/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <arpa/inet.h>               // for inet_ntop
#include <sys/socket.h>              // for AF_INET
#include <cne_fib.h>                 // for cne_fib_create, cne_fib_add, cne_...
#include <cne_graph.h>               // for cne_node_register, CNE_NODE_REGISTER
#include <cne_graph_worker.h>        // for cne_node, cne_node_enqueue_x1
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <net/cne_udp.h>             // for cne_udp_hdr
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_mtod_offset
#include <net/cne_ether.h>           // for cne_ether_hdr
#include <cne_system.h>              // for cne_max_numa_nodes
#include <errno.h>                   // for errno
#include <netinet/in.h>              // for in_addr, INET6_ADDRSTRLEN, htonl
#include <stddef.h>                  // for offsetof
#include <stdint.h>                  // for uint16_t, uint32_t, uint8_t
#include <string.h>                  // for memcpy, NULL
#include <cnet_route.h>              // for
#include <cnet_route4.h>             // for
#include <pktdev.h>
#include <cnet_pcb.h>
#include <cnet_netif.h>
#include <cnet_arp.h>
#include <cnet_udp.h>
#include <cnet_ipv4.h>
#include <cnet_meta.h>
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>

#include <cnet_node_names.h>
#include "ip4_node_api.h"                 // for CNE_NODE_IP4_OUTPUT_NEXT_PKT_DROP
#include "ip4_output_priv.h"              // for CNE_NODE_IP4_OUTPUT_NEXT_PKT_DROP
#include "cne_branch_prediction.h"        // for likely, unlikely
#include "cne_common.h"                   // for CNE_BUILD_BUG_ON, CNE_PRIORITY_LAST
#include "cne_log.h"                      // for CNE_LOG_DEBUG, CNE_LOG_ERR
#include "cnet_fib_info.h"

static struct ip4_output_node_main *ip4_output_nm;

struct ip4_output_node_ctx {
    uint16_t next_index;
};
#define IP4_OUTPUT_NODE_LAST_NEXT(ctx) (((struct ip4_output_node_ctx *)ctx)->next_index)

static inline uint16_t
ip4_output_header(struct cne_node *node __cne_unused, pktmbuf_t *m, uint16_t nxt)
{
    struct cnet *cnet = this_cnet;
    struct pcb_entry *pcb;
    struct cne_ipv4_hdr *ip;
    struct cne_ether_hdr *eth;
    struct rt4_entry *rt4;
    struct arp_entry *arp;
    struct cnet_metadata *md;
    struct netif *nif;
    uint32_t ipaddr;
    void *l4;

    pcb = m->userptr;

    md = pktmbuf_metadata(m);
    if (!md)
        return nxt;

    m->l3_len = sizeof(struct cne_ipv4_hdr);

    l4 = pktmbuf_mtod(m, void *);
    ip = (struct cne_ipv4_hdr *)pktmbuf_prepend(m, m->l3_len);
    if (!ip)
        return nxt;

    ip->version_ihl     = (IPv4_VERSION << 4) | (sizeof(struct cne_ipv4_hdr) / 4);
    ip->type_of_service = pcb->tos;
    ip->total_length    = htobe16(pktmbuf_data_len(m));
    ip->fragment_offset = 0;
    ip->time_to_live    = pcb->ttl;
    ip->next_proto_id   = pcb->ip_proto;
    ip->hdr_checksum    = 0;
    ip->dst_addr        = md->faddr.cin_addr.s_addr;
    ip->src_addr        = md->laddr.cin_addr.s_addr;

    ipaddr = be32toh(ip->src_addr);

    if (likely(fib_info_lookup(cnet->rt4_finfo, &ipaddr, (void **)&rt4, 1) > 0)) {
        m->l2_len = sizeof(struct cne_ether_hdr);
        eth       = (struct cne_ether_hdr *)pktmbuf_prepend(m, sizeof(struct cne_ether_hdr));
        if (!eth)
            return nxt;

        nif = cnet_netif_from_index(rt4->netif_idx);

        ether_addr_copy(&nif->mac, &eth->s_addr);
        eth->ether_type = htobe16(CNE_ETHER_TYPE_IPV4);
        ip->packet_id   = htobe16(nif->ip_ident);
        nif->ip_ident += ip->total_length;

        ip->hdr_checksum = cne_ipv4_cksum(ip);

        /* Do the UDP/TCP checksum if enabled */
        if (pcb->ip_proto == IPPROTO_UDP) {
            if (pcb->opt_flag & UDP_CHKSUM_FLAG) {
                struct cne_udp_hdr *udp = l4;

                udp->dgram_cksum = cne_ipv4_udptcp_cksum(ip, l4);
            }
        } else if (pcb->ip_proto == IPPROTO_TCP) {
            struct cne_tcp_hdr *tcp = l4;

            tcp->cksum = cne_ipv4_udptcp_cksum(ip, l4);
        } else
            return nxt;

        nxt    = IP4_OUTPUT_NEXT_ARP_REQUEST;
        ipaddr = be32toh(ip->dst_addr);
        if (likely(fib_info_lookup(cnet->arp_finfo, &ipaddr, (void **)&arp, 1) > 0)) {
            ether_addr_copy(&arp->ha, &eth->d_addr);

            nxt = rt4->netif_idx + IP4_OUTPUT_NEXT_MAX;
        }
    }

    return nxt;
}

static uint16_t
ip4_output_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                        uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    cne_edge_t next0, next1, next2, next3;
    cne_edge_t next_index;
    void **to_next, **from;
    uint16_t last_spec = 0;
    uint16_t n_left_from;
    uint16_t held = 0, hdr_len = 0;

    /* Speculative next */
    next_index = IP4_OUTPUT_NODE_LAST_NEXT(node->ctx);

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    hdr_len = (sizeof(struct cne_ipv4_hdr) + sizeof(struct cne_ether_hdr));
    if (n_left_from >= 4) {
        for (int i = 0; i < 4; i++)
            cne_prefetch0(pktmbuf_mtod_offset(pkts[i], void *, -hdr_len));
    }

    /* Get stream for the speculated next node */
    to_next = cne_node_next_stream_get(graph, node, next_index, nb_objs);
    while (n_left_from >= 4) {
        /* Prefetch next-next mbufs */
        if (likely(n_left_from > 11)) {
            cne_prefetch0(pkts[8]);
            cne_prefetch0(pkts[9]);
            cne_prefetch0(pkts[10]);
            cne_prefetch0(pkts[11]);
        }

        /* Prefetch next mbuf data */
        if (likely(n_left_from > 7)) {
            cne_prefetch0(pktmbuf_mtod_offset(pkts[4], void *, -hdr_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[5], void *, -hdr_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[6], void *, -hdr_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[7], void *, -hdr_len));
        }

        mbuf0 = pkts[0];
        mbuf1 = pkts[1];
        mbuf2 = pkts[2];
        mbuf3 = pkts[3];

        pkts += 4;
        n_left_from -= 4;

        next0 = ip4_output_header(node, mbuf0, IP4_OUTPUT_NEXT_PKT_DROP);
        next1 = ip4_output_header(node, mbuf1, IP4_OUTPUT_NEXT_PKT_DROP);
        next2 = ip4_output_header(node, mbuf2, IP4_OUTPUT_NEXT_PKT_DROP);
        next3 = ip4_output_header(node, mbuf3, IP4_OUTPUT_NEXT_PKT_DROP);

        /* Enqueue four to next node */
        cne_edge_t fix_spec = (next_index ^ next0) | (next_index ^ next1) | (next_index ^ next2) |
                              (next_index ^ next3);

        if (unlikely(fix_spec)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            /* Next0 */
            if (next_index == next0) {
                to_next[0] = from[0];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next0, from[0]);

            /* Next1 */
            if (next_index == next1) {
                to_next[0] = from[1];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next1, from[1]);

            /* Next2 */
            if (next_index == next2) {
                to_next[0] = from[2];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next2, from[2]);

            /* Next3 */
            if (next_index == next3) {
                to_next[0] = from[3];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next3, from[3]);

            from += 4;

        } else
            last_spec += 4;
    }

    while (n_left_from > 0) {
        mbuf0 = pkts[0];

        pkts += 1;
        n_left_from -= 1;

        next0 = ip4_output_header(node, mbuf0, IP4_OUTPUT_NEXT_PKT_DROP);

        if (unlikely(next_index ^ next0)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            cne_node_enqueue_x1(graph, node, next0, from[0]);
            from += 1;
        } else
            last_spec += 1;
    }

    /* !!! Home run !!! */
    if (likely(last_spec == nb_objs)) {
        cne_node_next_stream_move(graph, node, next_index);
        return nb_objs;
    }

    held += last_spec;

    /* Copy things successfully speculated till now */
    memcpy(to_next, from, last_spec * sizeof(from[0]));
    cne_node_next_stream_put(graph, node, next_index, held);

    /* Save the last next used */
    IP4_OUTPUT_NODE_LAST_NEXT(node->ctx) = next_index;

    return nb_objs;
}

int
ip4_output_set_next(uint16_t port_id, uint16_t next_index)
{
    if (ip4_output_nm == NULL) {
        ip4_output_nm = calloc(1, sizeof(struct ip4_output_node_main));
        if (ip4_output_nm == NULL)
            return -ENOMEM;
    }
    ip4_output_nm->next_index[port_id] = next_index;

    return 0;
}

static struct cne_node_register ip4_output_node = {
    .process = ip4_output_node_process,
    .name    = IP4_OUTPUT_NODE_NAME,

    .nb_edges = IP4_OUTPUT_NEXT_MAX,
    .next_nodes =
        {
            [IP4_OUTPUT_NEXT_PKT_DROP]    = PKT_DROP_NODE_NAME,    /* Drop packet node */
            [IP4_OUTPUT_NEXT_ARP_REQUEST] = ARP_REQUEST_NODE_NAME, /* TX output nodes go here */
        },
};

struct cne_node_register *
ip4_output_node_get(void)
{
    return &ip4_output_node;
}

CNE_NODE_REGISTER(ip4_output_node);
