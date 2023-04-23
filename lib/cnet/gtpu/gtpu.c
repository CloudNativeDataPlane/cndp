/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation.
 * Copyright (c) 2020 Marvell.
 */

#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_s::(anonymous)
#include <pktmbuf_ptype.h>           // for CNE_PTYPE_L2_MASK, CNE_PTYPE_L3_MASK
#include <cne_graph.h>               // for cne_node_register, CNE_GRAPH_BURS...
#include <cne_graph_worker.h>        // for cne_node_enqueue_x1, cne_node_nex...
#include <stdint.h>                  // for uint8_t, uint16_t, uint32_t
#include <string.h>                  // for memcpy

#include <cnet_node_names.h>
#include "gtpu_priv.h"                    // for GTPU_NEXT_IP4_LOOKUP
#include "cne_branch_prediction.h"        // for likely, unlikely
#include "cne_common.h"                   // for CNE_PRIORITY_LAST, __cne_cache_al...
#include "cne_prefetch.h"                 // for cne_prefetch0

static uint8_t p_nxt[16] = {[CNE_PTYPE_TUNNEL_GTPU >> 12] = GTPU_NEXT_IP4_INPUT};

static uint16_t
gtpu_node_process(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    uint8_t next0, next1, next2, next3, last_type;
    uint16_t next_index, n_left_from;
    uint16_t held = 0, last_spec = 0;
    struct gtpu_node_ctx *ctx;
    void **to_next, **from;
    uint32_t i;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        for (i = 0; i < 4; i++)
            cne_prefetch0(pkts[i]);
    }

    ctx        = (struct gtpu_node_ctx *)node->ctx;
    last_type  = ctx->last_type;
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

        next0 = (mbuf0->packet_type & CNE_PTYPE_TUNNEL_MASK) >> 12;
        next1 = (mbuf1->packet_type & CNE_PTYPE_TUNNEL_MASK) >> 12;
        next2 = (mbuf2->packet_type & CNE_PTYPE_TUNNEL_MASK) >> 12;
        next3 = (mbuf3->packet_type & CNE_PTYPE_TUNNEL_MASK) >> 12;

        /* TODO: need to parse the GTPU header and decap packet for IPv4/UDP */

        /* Check if they are destined to same
         * next node based on l2l3 packet type.
         */
        uint8_t fix_spec =
            (last_type ^ next0) | (last_type ^ next1) | (last_type ^ next2) | (last_type ^ next3);

        if (unlikely(fix_spec)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            if (next0 == next_index) {
                to_next[0] = from[0];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, p_nxt[next0], from[0]);

            if (next1 == next_index) {
                to_next[0] = from[1];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, p_nxt[next1], from[1]);

            if (next2 == next_index) {
                to_next[0] = from[2];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, p_nxt[next2], from[2]);

            if (next3 == next_index) {
                to_next[0] = from[3];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, p_nxt[next3], from[3]);

            /* Update speculated ptype */
            if ((last_type != next3) && (next2 == next3) && (next_index != p_nxt[next3])) {
                /* Put the current stream for
                 * speculated ltype.
                 */
                cne_node_next_stream_put(graph, node, next_index, held);

                held = 0;

                /* Get next stream for new ltype */
                next_index = p_nxt[next3];
                last_type  = next3;
                to_next    = cne_node_next_stream_get(graph, node, next_index, nb_objs);
            } else if (next_index == p_nxt[next3])
                last_type = next3;

            from += 4;
        } else
            last_spec += 4;
    }

    while (n_left_from > 0) {
        mbuf0 = pkts[0];

        pkts += 1;
        n_left_from -= 1;

        next0 = (mbuf0->packet_type & CNE_PTYPE_TUNNEL_MASK) >> 12;

        /* TODO: need to parse the GTPU header and decap packet for IPv4/UDP */

        if (unlikely((next0 != last_type) && (p_nxt[next0] != next_index))) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            cne_node_enqueue_x1(graph, node, p_nxt[next0], from[0]);
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

    ctx->last_type = last_type;
    return nb_objs;
}

/* Packet Classification Node */
struct cne_node_register gtpu_node = {
    .process = gtpu_node_process,
    .name    = GTPU_INPUT_NODE_NAME,

    .nb_edges = GTPU_NEXT_MAX,
    .next_nodes =
        {
            /* Pkt drop node starts at '0' */
            [GTPU_NEXT_PKT_DROP]  = PKT_DROP_NODE_NAME,
            [GTPU_NEXT_IP4_INPUT] = IP4_INPUT_NODE_NAME,
#if CNET_ENABLE_IP6
            [GTPU_NEXT_IP6_INPUT] = IP6_INPUT_NODE_NAME,
#endif
        },
};
CNE_NODE_REGISTER(gtpu_node);
