/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <cnet.h>                 // for cnet_add_instance, cnet, per_thread_cnet
#include <cnet_stk.h>             // for proto_in_ifunc
#include <net/cne_ether.h>        // for ether_addr_copy, cne_ether_hdr, ether_ad...
#include <netinet/in.h>           // for ntohs
#include <stddef.h>               // for NULL

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <icmp6.h>
#include <nd6.h>
#include <cnet_meta.h>
#include <mempool.h>        // for mempool_t
#include <cnet_icmp6.h>
#include <pktdev.h>         // for pktdev_rx_burst
#include <pktmbuf.h>        // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>

#include "icmp6_input_priv.h"
#include <cnet_node_names.h>

static inline uint16_t
icmp6_input_lookup(struct cne_graph *graph, struct cne_node *node, pktmbuf_t *m, struct pcb_hd *hd)
{
    struct cnet *cnet = this_cnet;
    icmp6ip_t *iip;
    struct pcb_key key = {0};
    struct pcb_entry *pcb;
    struct cnet_metadata *md;
    uint16_t csum, nxt;

    md = pktmbuf_metadata(m);
    if (!md)
        return ICMP6_INPUT_NEXT_PKT_DROP;

    /* Assume we point to the L3 header here */
    iip = pktmbuf_mtod(m, struct icmp6ip_s *);

    /* Convert this into AVX instructions */
    inet6_addr_copy_from_octs(&key.faddr.cin6_addr, iip->ip6.src_addr);
    inet6_addr_copy_from_octs(&key.laddr.cin6_addr, iip->ip6.dst_addr);

    /* Create a 4x PCB lookup routine */
    pcb = cnet_pcb_lookup(hd, &key, BEST_MATCH);
    if (likely(pcb)) {

        csum = cne_ipv6_icmpv6_cksum_verify(&iip->ip6, &iip->icmp6);
        if (csum)
            return ICMP6_INPUT_NEXT_PKT_DROP;
        m->userptr = pcb;
        in_caddr_copy(&md->faddr, &key.faddr); /* Save the foreign address */
        in_caddr_copy(&md->laddr, &key.laddr); /* Save the local address */

        /* skip to the Payload by skipping the L3 + L4 headers */
        pktmbuf_adj_offset(m, m->l3_len + m->l4_len);

        nxt = nd6_recv_requests(graph, node, iip);
        if (nxt != ICMP6_INPUT_NEXT_PKT_DROP)
            return ICMP6_INPUT_NEXT_CHNL_RECV;
    }

    m->userptr = NULL;

    return (cnet->flags & CNET_PUNT_ENABLED) ? ICMP6_INPUT_NEXT_PKT_PUNT
                                             : ICMP6_INPUT_NEXT_PKT_DROP;
}

static uint16_t
icmp6_input_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                         uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    cne_edge_t next0, next1, next2, next3, next_index;
    void **to_next, **from;
    struct pcb_hd *hd  = &this_stk->icmp6->icmp6_hd;
    uint16_t last_spec = 0;
    uint16_t n_left_from;
    uint16_t held = 0;

    next_index = ICMP6_INPUT_NEXT_CHNL_RECV;

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

        next0 = icmp6_input_lookup(graph, node, mbuf0, hd);
        next1 = icmp6_input_lookup(graph, node, mbuf1, hd);
        next2 = icmp6_input_lookup(graph, node, mbuf2, hd);
        next3 = icmp6_input_lookup(graph, node, mbuf3, hd);

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

        next0 = icmp6_input_lookup(graph, node, mbuf0, hd);

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

static struct cne_node_register icmp6_input_node_base = {
    .process = icmp6_input_node_process,
    .name    = ICMP6_INPUT_NODE_NAME,

    .nb_edges = ICMP6_INPUT_NEXT_MAX,
    .next_nodes =
        {
            [ICMP6_INPUT_NEXT_PKT_DROP]  = PKT_DROP_NODE_NAME,
            [ICMP6_INPUT_NEXT_CHNL_RECV] = CHNL_RECV_NODE_NAME,
            [ICMP6_INPUT_NEXT_PKT_PUNT]  = PUNT_KERNEL_NODE_NAME,
        },
};

CNE_NODE_REGISTER(icmp6_input_node_base);
