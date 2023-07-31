/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation.
 * Copyright (c) 2020 Marvell.
 * Copyright (c) Red Hat Inc.
 */

#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_s::(anonymous)
#include <pktmbuf_ptype.h>           // for CNE_PTYPE_L2_MASK, CNE_PTYPE_L3_MASK
#include <cne_graph.h>               // for cne_node_register, CNE_GRAPH_BURS...
#include <cne_graph_worker.h>        // for cne_node_enqueue_x1, cne_node_nex...
#include <stdint.h>                  // for uint8_t, uint16_t, uint32_t
#include <string.h>                  // for memcpy

#include <cnet_node_names.h>
#include "ptype_priv.h"                   // for PTYPE_NEXT_IP4_LOOKUP, PTYPE_...
#include "cne_branch_prediction.h"        // for likely, unlikely
#include "cne_common.h"                   // for CNE_PRIORITY_LAST, __cne_cache_al...
#include "cne_prefetch.h"                 // for cne_prefetch0

#define _PTYPE_MASK \
    (CNE_PTYPE_L2_MASK | CNE_PTYPE_L3_MASK | CNE_PTYPE_L4_MASK | CNE_PTYPE_TUNNEL_MASK)

#define _L2_L3_IPV4         (CNE_PTYPE_L2_ETHER | CNE_PTYPE_L3_IPV4)
#define _L2_L3_IPV4_EXT     (CNE_PTYPE_L2_ETHER | CNE_PTYPE_L3_IPV4_EXT)
#define _L2_L3_IPV4_EXT_UNK (CNE_PTYPE_L2_ETHER | CNE_PTYPE_L3_IPV4_EXT_UNKNOWN)

#define _L2_L3_IPV6         (CNE_PTYPE_L2_ETHER | CNE_PTYPE_L3_IPV6)
#define _L2_L3_IPV6_EXT     (CNE_PTYPE_L2_ETHER | CNE_PTYPE_L3_IPV6_EXT)
#define _L2_L3_IPV6_EXT_UNK (CNE_PTYPE_L2_ETHER | CNE_PTYPE_L3_IPV6_EXT_UNKNOWN)

/* Next node for each ptype, default is '0' is "pkt_drop" */
static const uint8_t p_nxt[_PTYPE_MASK + 1] __cne_cache_aligned = {
    [CNE_PTYPE_L2_ETHER_ARP]                                 = PTYPE_NEXT_FRAME_PUNT,
    [_L2_L3_IPV4]                                            = PTYPE_NEXT_IP4_INPUT,
    [_L2_L3_IPV4_EXT]                                        = PTYPE_NEXT_PKT_PUNT,
    [_L2_L3_IPV4 | CNE_PTYPE_L4_UDP]                         = PTYPE_NEXT_IP4_INPUT,
    [_L2_L3_IPV4 | CNE_PTYPE_L4_TCP]                         = PTYPE_NEXT_IP4_INPUT,
    [_L2_L3_IPV4_EXT | CNE_PTYPE_L4_UDP]                     = PTYPE_NEXT_IP4_INPUT,
    [_L2_L3_IPV4_EXT_UNK | CNE_PTYPE_L4_UDP]                 = PTYPE_NEXT_IP4_INPUT,
    [_L2_L3_IPV4 | CNE_PTYPE_L4_UDP | CNE_PTYPE_TUNNEL_GTPU] = PTYPE_NEXT_GTPU_INPUT,
#if CNET_ENABLE_IP6
    [_L2_L3_IPV6 | CNE_PTYPE_L4_UDP]                         = PTYPE_NEXT_IP6_INPUT,
    [_L2_L3_IPV6 | CNE_PTYPE_L4_TCP]                         = PTYPE_NEXT_IP6_INPUT,
    [_L2_L3_IPV6_EXT | CNE_PTYPE_L4_UDP]                     = PTYPE_NEXT_IP6_INPUT,
    [_L2_L3_IPV6_EXT_UNK | CNE_PTYPE_L4_UDP]                 = PTYPE_NEXT_IP6_INPUT,
    [_L2_L3_IPV6 | CNE_PTYPE_L4_UDP | CNE_PTYPE_TUNNEL_GTPU] = PTYPE_NEXT_GTPU_INPUT,
#endif
};

static uint16_t
ptype_node_process(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    uint16_t l0, l1, l2, l3, last_type;
    uint16_t next_index, n_left_from;
    uint16_t held = 0, last_spec = 0;
    struct ptype_node_ctx *ctx;
    void **to_next, **from;
    uint32_t ptype_mask = _PTYPE_MASK;
    uint32_t i;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        for (i = 0; i < 4; i++)
            cne_prefetch0(pktmbuf_mtod(pkts[i], void *));
    }

    ctx        = (struct ptype_node_ctx *)node->ctx;
    last_type  = ctx->last_type;
    next_index = p_nxt[last_type];

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
            cne_prefetch0(pktmbuf_mtod(pkts[4], void *));
            cne_prefetch0(pktmbuf_mtod(pkts[5], void *));
            cne_prefetch0(pktmbuf_mtod(pkts[6], void *));
            cne_prefetch0(pktmbuf_mtod(pkts[7], void *));
        }

        mbuf0 = pkts[0];
        mbuf1 = pkts[1];
        mbuf2 = pkts[2];
        mbuf3 = pkts[3];
        pkts += 4;

        n_left_from -= 4;

        /* GTP-U detection and next node to gtpu_input */
        l0 = mbuf0->packet_type & ptype_mask;
        l1 = mbuf1->packet_type & ptype_mask;
        l2 = mbuf2->packet_type & ptype_mask;
        l3 = mbuf3->packet_type & ptype_mask;

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

        l0 = mbuf0->packet_type & ptype_mask;

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

    ctx->last_type = last_type;

    return nb_objs;
}

/* Packet Classification Node */
struct cne_node_register ptype_node = {
    .process = ptype_node_process,
    .name    = PTYPE_NODE_NAME,

    .nb_edges = PTYPE_NEXT_MAX,
    .next_nodes =
        {
            /* Pkt drop node starts at '0' */
            [PTYPE_NEXT_PKT_DROP]   = PKT_DROP_NODE_NAME,
            [PTYPE_NEXT_PKT_PUNT]   = PUNT_KERNEL_NODE_NAME,
            [PTYPE_NEXT_FRAME_PUNT] = PUNT_ETHER_NODE_NAME,
            [PTYPE_NEXT_IP4_INPUT]  = IP4_INPUT_NODE_NAME,
#if CNET_ENABLE_IP6
            [PTYPE_NEXT_IP6_INPUT] = IP6_INPUT_NODE_NAME,
#endif
            [PTYPE_NEXT_GTPU_INPUT] = GTPU_INPUT_NODE_NAME,
        },
};
CNE_NODE_REGISTER(ptype_node);
