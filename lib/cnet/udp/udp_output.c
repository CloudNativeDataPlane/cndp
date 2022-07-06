/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

#include <net/cne_ether.h>        // for ether_addr_copy, cne_ether_hdr, ether_ad...
#include <cnet.h>                 // for cnet_add_instance, cnet, per_thread_cnet
#include <cnet_stk.h>             // for proto_in_ifunc
#include <cne_inet.h>             // for inet_ntop4, CIN_ADDR
#include <cnet_drv.h>             // for drv_entry
#include <cnet_route.h>           // for
#include <cnet_arp.h>             // for arp_entry
#include <cnet_netif.h>           // for netif, cnet_ipv4_compare
#include <netinet/in.h>           // for ntohs
#include <stddef.h>               // for NULL

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_common.h>              // for __cne_unused
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <net/cne_udp.h>
#include <cne_log.h>          // for CNE_LOG, CNE_LOG_DEBUG
#include <cnet_ipv4.h>        // for IPv4_VER_LEN_VALUE
#include <mempool.h>          // for mempool_t
#include <pktdev.h>           // for pktdev_rx_burst
#include <pktmbuf.h>          // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cnet_udp.h>
#include <cnet_meta.h>

#include <cnet_node_names.h>
#include "udp_output_priv.h"

static inline uint16_t
udp_output_header(pktmbuf_t *m, uint16_t nxt)
{
    struct cne_udp_hdr *udp;
    struct cnet_metadata *md;
    int16_t len;

    md = pktmbuf_metadata(m);
    if (!md)
        return UDP_OUTPUT_NEXT_PKT_DROP;

    /* Build the UDP header */
    len           = sizeof(struct cne_udp_hdr);
    m->l4_len     = len;
    m->tx_offload = 0;

    udp = pktmbuf_adjust(m, struct cne_udp_hdr *, -len);
    if (!udp)
        return UDP_OUTPUT_NEXT_PKT_DROP;
    udp->dgram_len   = htobe16(pktmbuf_data_len(m));
    udp->dst_port    = CIN_PORT(&md->faddr);
    udp->src_port    = CIN_PORT(&md->laddr);
    udp->dgram_cksum = 0;

    nxt = UDP_OUTPUT_NEXT_IP4_OUTPUT;

    return nxt;
}

static uint16_t
udp_output_node_do(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    cne_edge_t next0, next1, next2, next3;
    cne_edge_t next_index;
    void **to_next, **from;
    uint16_t last_spec = 0;
    uint16_t n_left_from;
    uint16_t held = 0;

    next_index = UDP_OUTPUT_NEXT_IP4_OUTPUT;

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

        next0 = udp_output_header(mbuf0, UDP_OUTPUT_NEXT_PKT_DROP);
        next1 = udp_output_header(mbuf1, UDP_OUTPUT_NEXT_PKT_DROP);
        next2 = udp_output_header(mbuf2, UDP_OUTPUT_NEXT_PKT_DROP);
        next3 = udp_output_header(mbuf3, UDP_OUTPUT_NEXT_PKT_DROP);

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

        next0 = udp_output_header(mbuf0, UDP_OUTPUT_NEXT_PKT_DROP);

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

static uint16_t
udp_output_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                        uint16_t nb_objs)
{
    return udp_output_node_do(graph, node, objs, nb_objs);
}

static struct cne_node_register udp_output_node_base = {
    .process = udp_output_node_process,
    .flags   = CNE_NODE_INPUT_F,
    .name    = UDP_OUTPUT_NODE_NAME,

    .nb_edges = UDP_OUTPUT_NEXT_MAX,
    .next_nodes =
        {
            [UDP_OUTPUT_NEXT_PKT_DROP]   = PKT_DROP_NODE_NAME,
            [UDP_OUTPUT_NEXT_IP4_OUTPUT] = IP4_OUTPUT_NODE_NAME,
        },
};

CNE_NODE_REGISTER(udp_output_node_base);
