/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell.
 */

#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_s::(anonymous)
#include <pktmbuf_ptype.h>           // for CNE_PTYPE_L2_MASK, CNE_PTYPE_L3_MASK
#include <cne_graph.h>               // for cne_node_register, CNE_GRAPH_BURS...
#include <cne_graph_worker.h>        // for cne_node_enqueue_x1, cne_node_nex...
#include <stdint.h>                  // for uint8_t, uint16_t, uint32_t
#include <string.h>                  // for memcpy

#include "pkt_cls_priv.h"                 // for PKT_CLS_NEXT_IP4_LOOKUP, PKT_CLS_...
#include "node_private.h"                 // for OBJS_PER_CLINE
#include "cne_branch_prediction.h"        // for likely, unlikely
#include "cne_common.h"                   // for CNE_PRIORITY_LAST, __cne_cache_al...
#include "cne_prefetch.h"                 // for cne_prefetch0

/* Next node for each ptype, default is '0' is "pkt_drop" */
static const uint8_t p_nxt[256] __cne_cache_aligned = {
    [CNE_PTYPE_L3_IPV4] = PKT_CLS_NEXT_IP4_LOOKUP,

    [CNE_PTYPE_L3_IPV4_EXT] = PKT_CLS_NEXT_IP4_LOOKUP,

    [CNE_PTYPE_L3_IPV4_EXT_UNKNOWN] = PKT_CLS_NEXT_IP4_LOOKUP,

    [CNE_PTYPE_L3_IPV4 | CNE_PTYPE_L2_ETHER] = PKT_CLS_NEXT_IP4_LOOKUP,

    [CNE_PTYPE_L3_IPV4_EXT | CNE_PTYPE_L2_ETHER] = PKT_CLS_NEXT_IP4_LOOKUP,

    [CNE_PTYPE_L3_IPV4_EXT_UNKNOWN | CNE_PTYPE_L2_ETHER] = PKT_CLS_NEXT_IP4_LOOKUP,
};

static uint16_t
pkt_cls_node_process(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    uint8_t l0, l1, l2, l3, last_type;
    uint16_t next_index, n_left_from;
    uint16_t held = 0, last_spec = 0;
    struct pkt_cls_node_ctx *ctx;
    void **to_next, **from;
    uint32_t i;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    for (i = OBJS_PER_CLINE; i < CNE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)
        cne_prefetch0(&objs[i]);

    for (i = 0; i < 4 && i < n_left_from; i++)
        cne_prefetch0(pkts[i]);

    ctx        = (struct pkt_cls_node_ctx *)node->ctx;
    last_type  = ctx->l2l3_type;
    next_index = p_nxt[last_type];

    /* Get stream for the speculated next node */
    to_next = cne_node_next_stream_get(graph, node, next_index, nb_objs);
    while (n_left_from >= 4) {
        if (likely(n_left_from > 7)) {
            cne_prefetch0(pkts[4]);
            cne_prefetch0(pkts[5]);
            cne_prefetch0(pkts[6]);
            cne_prefetch0(pkts[7]);
        }

        mbuf0 = pkts[0];
        mbuf1 = pkts[1];
        mbuf2 = pkts[2];
        mbuf3 = pkts[3];
        pkts += 4;
        n_left_from -= 4;

        l0 = mbuf0->packet_type & (CNE_PTYPE_L2_MASK | CNE_PTYPE_L3_MASK);
        l1 = mbuf1->packet_type & (CNE_PTYPE_L2_MASK | CNE_PTYPE_L3_MASK);
        l2 = mbuf2->packet_type & (CNE_PTYPE_L2_MASK | CNE_PTYPE_L3_MASK);
        l3 = mbuf3->packet_type & (CNE_PTYPE_L2_MASK | CNE_PTYPE_L3_MASK);

        /* Check if they are destined to same
         * next node based on l2l3 packet type.
         */
        uint8_t fix_spec =
            (last_type ^ l0) | (last_type ^ l1) | (last_type ^ l2) | (last_type ^ l3);

        if (unlikely(fix_spec)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            /* l0 */
            if (p_nxt[l0] == next_index) {
                to_next[0] = from[0];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, p_nxt[l0], from[0]);

            /* l1 */
            if (p_nxt[l1] == next_index) {
                to_next[0] = from[1];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, p_nxt[l1], from[1]);

            /* l2 */
            if (p_nxt[l2] == next_index) {
                to_next[0] = from[2];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, p_nxt[l2], from[2]);

            /* l3 */
            if (p_nxt[l3] == next_index) {
                to_next[0] = from[3];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, p_nxt[l3], from[3]);

            /* Update speculated ptype */
            if ((last_type != l3) && (l2 == l3) && (next_index != p_nxt[l3])) {
                /* Put the current stream for
                 * speculated ltype.
                 */
                cne_node_next_stream_put(graph, node, next_index, held);

                held = 0;

                /* Get next stream for new ltype */
                next_index = p_nxt[l3];
                last_type  = l3;
                to_next    = cne_node_next_stream_get(graph, node, next_index, nb_objs);
            } else if (next_index == p_nxt[l3])
                last_type = l3;

            from += 4;
        } else
            last_spec += 4;
    }

    while (n_left_from > 0) {
        mbuf0 = pkts[0];

        pkts += 1;
        n_left_from -= 1;

        l0 = mbuf0->packet_type & (CNE_PTYPE_L2_MASK | CNE_PTYPE_L3_MASK);
        if (unlikely((l0 != last_type) && (p_nxt[l0] != next_index))) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            cne_node_enqueue_x1(graph, node, p_nxt[l0], from[0]);
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

    ctx->l2l3_type = last_type;
    return nb_objs;
}

/* Packet Classification Node */
struct cne_node_register pkt_cls_node = {
    .process = pkt_cls_node_process,
    .name    = "pkt_cls",

    .nb_edges = PKT_CLS_NEXT_MAX,
    .next_nodes =
        {
            /* Pkt drop node starts at '0' */
            [PKT_CLS_NEXT_PKT_DROP]   = "pkt_drop",
            [PKT_CLS_NEXT_IP4_LOOKUP] = "ip4_lookup",
        },
};
CNE_NODE_REGISTER(pkt_cls_node);
