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
#include <sys/types.h>
#include <sys/socket.h>

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_common.h>              // for __cne_unused
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <cne_vec.h>                 // for vec_len, vec_ptr_at_index, vec_next_mbuf_pre...
#include <cnet_ipv4.h>               // for IPv4_VER_LEN_VALUE
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cne_vec.h>
#include <cnet_fib_info.h>
#include <cnet_eth.h>
#include <net/cne_udp.h>

#include <cnet_node_names.h>
#include "arp_request_priv.h"

static __cne_always_inline cne_edge_t
arp_request_process_mbuf(struct cne_node *node, pktmbuf_t *mbuf)
{
    arp_request_node_ctx_t *ctx = (arp_request_node_ctx_t *)node->ctx;

    if (ctx->s >= 0) {
        struct cne_ipv4_hdr *ip4;
        char *buf;
        size_t len;
        struct sockaddr_in sin = {0};

        ip4 = pktmbuf_mtod_offset(mbuf, struct cne_ipv4_hdr *, mbuf->l2_len);
        buf = (char *)ip4;
        len = pktmbuf_data_len(mbuf);

        sin.sin_family      = AF_INET;
        sin.sin_port        = 0;
        sin.sin_addr.s_addr = ip4->dst_addr;

        if (sendto(ctx->s, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            CNE_WARN("Unable to send packets: %s\n", strerror(errno));
    }
    return ARP_REQUEST_NEXT_PKT_DROP;
}

static uint16_t
arp_request_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                         uint16_t nb_objs)
{
    void **to_next, **from;
    cne_edge_t next_index;
    cne_edge_t next0, next1, next2, next3;
    uint16_t n_left_from;
    uint16_t held      = 0;
    uint16_t last_spec = 0;
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    int k;

    /* Speculative next */
    next_index = ARP_REQUEST_NEXT_PKT_DROP;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    for (k = 0; k < 4 && k < n_left_from; k++)
        cne_prefetch0(pktmbuf_mtod_offset(pkts[k], void *, sizeof(struct cne_ether_hdr)));

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

        next0 = arp_request_process_mbuf(node, mbuf0);
        next1 = arp_request_process_mbuf(node, mbuf1);
        next2 = arp_request_process_mbuf(node, mbuf2);
        next3 = arp_request_process_mbuf(node, mbuf3);

        /* Enqueue four to next node */
        cne_edge_t fix_spec = (next_index == next0) | (next_index == next1) |
                              (next_index == next2) | (next_index == next3);

        if (unlikely(fix_spec == 0)) {
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

        pkts++;
        n_left_from--;

        next0 = arp_request_process_mbuf(node, mbuf0);

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
arp_request_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    arp_request_node_ctx_t *ctx = (arp_request_node_ctx_t *)node->ctx;

    ctx->s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ctx->s < 0)
        CNE_ERR_RET("Unable to open RAW socket\n");

    return 0;
}

static struct cne_node_register arp_request_node_base = {
    .process = arp_request_node_process,
    .name    = ARP_REQUEST_NODE_NAME,

    .init = arp_request_node_init,

    .nb_edges = ARP_REQUEST_NEXT_MAX,
    .next_nodes =
        {
            [ARP_REQUEST_NEXT_PKT_DROP] = PKT_DROP_NODE_NAME,
        },
};

struct cne_node_register *
arp_request_node_get(void)
{
    return &arp_request_node_base;
}

CNE_NODE_REGISTER(arp_request_node_base);
