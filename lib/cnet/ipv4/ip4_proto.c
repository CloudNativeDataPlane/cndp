/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */

#include <arpa/inet.h>               // for inet_ntop
#include <sys/socket.h>              // for AF_INET
#include <cne_fib.h>                 // for cne_fib_create, cne_fib_add, cne_...
#include <cne_graph.h>               // for cne_node_register, CNE_NODE_REGISTER
#include <cne_graph_worker.h>        // for cne_node, cne_node_enqueue_x1
#include <net/cne_ip.h>              // for cne_ipv4_hdr
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

#include <cnet_node_names.h>
#include "ip4_proto_priv.h"               // for
#include "cne_branch_prediction.h"        // for likely, unlikely
#include "cne_common.h"                   // for CNE_BUILD_BUG_ON, CNE_PRIORITY_LAST
#include "cne_log.h"                      // for CNE_LOG_DEBUG, CNE_LOG_ERR, CNE_INFO

static uint8_t proto_nxt[256] __cne_cache_aligned;

static uint16_t
ip4_proto_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                       uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    cne_edge_t next0, next1, next2, next3;
    cne_edge_t next_index;
    struct cne_ipv4_hdr *ip4[4];
    void **to_next, **from;
    uint16_t last_spec = 0;
    uint16_t n_left_from;
    uint16_t held = 0;
    int i;

    /* Speculative next */
    next_index = CNE_NODE_IP4_INPUT_PROTO_DROP;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        for (i = 0; i < 4; i++)
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

        ip4[0] = pktmbuf_mtod(mbuf0, struct cne_ipv4_hdr *);
        ip4[1] = pktmbuf_mtod(mbuf1, struct cne_ipv4_hdr *);
        ip4[2] = pktmbuf_mtod(mbuf2, struct cne_ipv4_hdr *);
        ip4[3] = pktmbuf_mtod(mbuf3, struct cne_ipv4_hdr *);

        next0 = proto_nxt[ip4[0]->next_proto_id];
        next1 = proto_nxt[ip4[1]->next_proto_id];
        next2 = proto_nxt[ip4[2]->next_proto_id];
        next3 = proto_nxt[ip4[3]->next_proto_id];

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

        ip4[0] = pktmbuf_mtod(mbuf0, struct cne_ipv4_hdr *);
        next0  = proto_nxt[ip4[0]->next_proto_id];

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
ip4_proto_node_init(const struct cne_graph *graph, struct cne_node *node)
{
    CNE_SET_USED(graph);
    CNE_SET_USED(node);

    memset(proto_nxt, CNE_NODE_IP4_INPUT_PROTO_DROP, sizeof(proto_nxt));

    proto_nxt[IPPROTO_UDP] = CNE_NODE_IP4_INPUT_PROTO_UDP;
#if CNET_ENABLE_TCP
    proto_nxt[IPPROTO_TCP] = CNE_NODE_IP4_INPUT_PROTO_TCP;
#endif

    return 0;
}

static struct cne_node_register ip4_proto_node = {
    .process = ip4_proto_node_process,
    .name    = IP4_PROTO_NODE_NAME,

    .init = ip4_proto_node_init,

    .nb_edges = CNE_NODE_IP4_INPUT_PROTO_MAX,
    .next_nodes =
        {
            [CNE_NODE_IP4_INPUT_PROTO_DROP] = PKT_DROP_NODE_NAME,
            [CNE_NODE_IP4_INPUT_PROTO_UDP]  = UDP_INPUT_NODE_NAME,
#if CNET_ENABLE_TCP
            [CNE_NODE_IP4_INPUT_PROTO_TCP] = TCP_INPUT_NODE_NAME,
#endif
        },
};

CNE_NODE_REGISTER(ip4_proto_node);
