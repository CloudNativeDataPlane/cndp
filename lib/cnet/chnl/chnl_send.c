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
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <cnet_ipv4.h>               // for IPv4_VER_LEN_VALUE
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cnet_pcb.h>

#include <cnet_node_names.h>
#include "chnl_send_priv.h"

#define CHNL_SEND_NODE_LAST_NEXT(ctx) (((struct chnl_send_node_ctx *)ctx)->last_next)

static uint8_t p_nxt[256] = {
    [IPPROTO_UDP] = CHNL_SEND_NEXT_UDP_OUTPUT,
#if CNET_ENABLE_TCP
    [IPPROTO_TCP] = CHNL_SEND_NEXT_TCP_OUTPUT,
#endif
};

static uint16_t
chnl_send_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                       uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    cne_edge_t next0, next1, next2, next3;
    cne_edge_t next_index;
    void **to_next, **from;
    uint16_t last_spec = 0;
    uint16_t n_left_from;
    uint16_t held = 0;

    if (!objs || nb_objs == 0)
        return 0;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;
    next_index  = CHNL_SEND_NODE_LAST_NEXT(node->ctx);

    if (n_left_from >= 4) {
        for (int i = 0; i < 4; i++)
            cne_prefetch0(pktmbuf_mtod(pkts[i], void *));
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

        next0 = p_nxt[((struct pcb_entry *)mbuf0->userptr)->ip_proto];
        next1 = p_nxt[((struct pcb_entry *)mbuf1->userptr)->ip_proto];
        next2 = p_nxt[((struct pcb_entry *)mbuf2->userptr)->ip_proto];
        next3 = p_nxt[((struct pcb_entry *)mbuf3->userptr)->ip_proto];

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

            if (next0 == next_index) {
                to_next[0] = from[0];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next0, from[0]);

            if (next1 == next_index) {
                to_next[0] = from[1];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next1, from[1]);

            if (next2 == next_index) {
                to_next[0] = from[2];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next2, from[2]);

            if (next3 == next_index) {
                to_next[0] = from[3];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next3, from[3]);

            /* Update speculated ptype */
            if ((next_index != next3) && (next2 == next3)) {
                /* Put the current stream for
                 * speculated ltype.
                 */
                cne_node_next_stream_put(graph, node, next_index, held);

                held = 0;

                /* Get next stream for new ltype */
                next_index = next3;
                to_next    = cne_node_next_stream_get(graph, node, next_index, nb_objs);
            }

            from += 4;
        } else
            last_spec += 4;
    }

    while (n_left_from > 0) {
        mbuf0 = pkts[0];

        pkts += 1;
        n_left_from -= 1;

        next0 = p_nxt[((struct pcb_entry *)mbuf0->userptr)->ip_proto];

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

    /* Save the last next index value */
    CHNL_SEND_NODE_LAST_NEXT(node->ctx) = next_index;

    return nb_objs;
}

static int
chnl_send_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node __cne_unused)
{
    return 0;
}

static struct cne_node_register chnl_send_node_base = {
    .process = chnl_send_node_process,
    .flags   = CNE_NODE_INPUT_F,
    .name    = CHNL_SEND_NODE_NAME,

    .init = chnl_send_node_init,

    .nb_edges = CHNL_SEND_NEXT_MAX,
    .next_nodes =
        {
            [CHNL_SEND_NEXT_PKT_DROP]   = PKT_DROP_NODE_NAME,
            [CHNL_SEND_NEXT_UDP_OUTPUT] = UDP_OUTPUT_NODE_NAME,
#if CNET_ENABLE_TCP
            [CHNL_SEND_NEXT_TCP_OUTPUT] = TCP_OUTPUT_NODE_NAME,
#endif
        },
};

struct cne_node_register *
chnl_send_node_get(void)
{
    return &chnl_send_node_base;
}

CNE_NODE_REGISTER(chnl_send_node_base);
