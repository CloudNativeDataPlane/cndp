/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

#include <cne_ether.h>         // for ether_addr_copy, cne_ether_hdr, ether_ad...
#include <cnet.h>              // for cnet_add_instance, cnet, per_thread_cnet
#include <cnet_stk.h>          // for proto_in_ifunc
#include <cnet_inet.h>         // for inet_ntop4, CIN_ADDR
#include <cnet_drv.h>          // for drv_entry
#include <cnet_route.h>        // for
#include <cnet_arp.h>          // for arp_entry
#include <cnet_netif.h>        // for netif, cnet_ipv4_compare
#include <netinet/in.h>        // for ntohs
#include <stddef.h>            // for NULL

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_common.h>              // for __cne_unused
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <net/cne_tcp.h>             // for cne_tcp_hdr
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <cne_vec.h>                 // for vec_len, vec_ptr_at_index, vec_next_mbuf_pre...
#include <cnet_ipv4.h>               // for IPv4_VER_LEN_VALUE
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cnet_tcp.h>

#include <cnet_node_names.h>
#include "tcp_output_priv.h"

static inline uint16_t
tcp_output_header(pktmbuf_t *m, uint16_t nxt)
{
    struct pcb_entry *pcb;
    struct cne_tcp_hdr *tcp;
    int16_t len;

    pcb = m->userptr;

    /* Build the TCP header */
    len       = sizeof(struct cne_tcp_hdr);
    m->l4_len = len;
    tcp       = pktmbuf_adjust(m, struct cne_tcp_hdr *, -len);
    if (!tcp)
        return TCP_OUTPUT_NEXT_PKT_DROP;
    m->tx_offload = 0;
    m->l4_len     = sizeof(struct cne_tcp_hdr);

    memset(tcp, 0, sizeof(struct cne_tcp_hdr));
    tcp->dst_port = CIN_PORT(&pcb->key.faddr);
    tcp->src_port = CIN_PORT(&pcb->key.laddr);

    nxt = TCP_OUTPUT_NEXT_IP4_OUTPUT;

    return nxt;
}

static uint16_t
tcp_output_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                        uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    cne_edge_t next0, next1, next2, next3;
    cne_edge_t next_index;
    void **to_next, **from;
    uint16_t last_spec = 0;
    uint16_t n_left_from;
    uint16_t held = 0;

    next_index = TCP_OUTPUT_NEXT_IP4_OUTPUT;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        for (int i = 0; i < 4; i++)
            cne_prefetch0(pktmbuf_mtod_offset(pkts[i], void *, sizeof(struct cne_ether_hdr)));
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
            cne_prefetch0(pktmbuf_mtod_offset(pkts[4], void *, pkts[4]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[5], void *, pkts[5]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[6], void *, pkts[6]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[7], void *, pkts[7]->l2_len));
        }

        mbuf0 = pkts[0];
        mbuf1 = pkts[1];
        mbuf2 = pkts[2];
        mbuf3 = pkts[3];

        pkts += 4;
        n_left_from -= 4;

        next0 = tcp_output_header(mbuf0, TCP_OUTPUT_NEXT_PKT_DROP);
        next1 = tcp_output_header(mbuf1, TCP_OUTPUT_NEXT_PKT_DROP);
        next2 = tcp_output_header(mbuf2, TCP_OUTPUT_NEXT_PKT_DROP);
        next3 = tcp_output_header(mbuf3, TCP_OUTPUT_NEXT_PKT_DROP);

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

        next0 = tcp_output_header(mbuf0, TCP_OUTPUT_NEXT_PKT_DROP);

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

    return nb_objs;
}

static int
tcp_output_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node __cne_unused)
{
    return 0;
}

static struct cne_node_register tcp_output_node_base = {
    .process = tcp_output_node_process,
    .name    = TCP_OUTPUT_NODE_NAME,

    .init = tcp_output_node_init,

    .nb_edges = TCP_OUTPUT_NEXT_MAX,
    .next_nodes =
        {
            [TCP_OUTPUT_NEXT_PKT_DROP]   = PKT_DROP_NODE_NAME,
            [TCP_OUTPUT_NEXT_IP4_OUTPUT] = IP4_OUTPUT_NODE_NAME,
        },
};

CNE_NODE_REGISTER(tcp_output_node_base);
