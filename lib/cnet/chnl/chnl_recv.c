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
#include "chnl_priv.h"
#include <cnet_chnl.h>        // for cnet_chnl_get

#include <cnet_node_names.h>
#include "chnl_recv_priv.h"

static uint16_t
chnl_recv_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                       uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    cne_edge_t next0, next1, next2, next3, next_index;
    void **to_next, **from;
    uint16_t last_spec = 0, n_left_from, held = 0;

    next_index = CHNL_RECV_NEXT_PKT_CALLBACK;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        cne_prefetch0(pkts[0]);
        cne_prefetch0(pkts[1]);
        cne_prefetch0(pkts[2]);
        cne_prefetch0(pkts[3]);
    }

    /* Get stream for the speculated next node */
    to_next = cne_node_next_stream_get(graph, node, next_index, nb_objs);
    while (n_left_from > 4) {
        /* Prefetch next-next mbufs */
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

        next0 = (mbuf0->userptr) ? CHNL_RECV_NEXT_PKT_CALLBACK : CHNL_RECV_NEXT_PKT_DROP;
        next1 = (mbuf1->userptr) ? CHNL_RECV_NEXT_PKT_CALLBACK : CHNL_RECV_NEXT_PKT_DROP;
        next2 = (mbuf2->userptr) ? CHNL_RECV_NEXT_PKT_CALLBACK : CHNL_RECV_NEXT_PKT_DROP;
        next3 = (mbuf3->userptr) ? CHNL_RECV_NEXT_PKT_CALLBACK : CHNL_RECV_NEXT_PKT_DROP;

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

        next0 = (mbuf0->userptr) ? CHNL_RECV_NEXT_PKT_CALLBACK : CHNL_RECV_NEXT_PKT_DROP;

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

static struct cne_node_register chnl_recv_node_base = {
    .process = chnl_recv_node_process,
    .name    = CHNL_RECV_NODE_NAME,

    .nb_edges = CHNL_RECV_NEXT_MAX,
    .next_nodes =
        {
            [CHNL_RECV_NEXT_PKT_DROP]     = PKT_DROP_NODE_NAME,
            [CHNL_RECV_NEXT_PKT_CALLBACK] = CHNL_CALLBACK_NODE_NAME,
        },
};

CNE_NODE_REGISTER(chnl_recv_node_base);
