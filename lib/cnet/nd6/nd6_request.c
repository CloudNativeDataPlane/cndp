/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <net/cne_ether.h>        // for ether_addr_copy, cne_ether_hdr, ether_ad...
#include <cnet.h>                 // for cnet_add_instance, cnet, per_thread_cnet
#include <cnet_stk.h>             // for proto_in_ifunc
#include <cnet_route.h>           // for
#include <netinet/in.h>           // for ntohs
#include <stddef.h>               // for NULL
#include <sys/types.h>
#include <sys/socket.h>

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_common.h>              // for __cne_unused
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <cnet_ipv6.h>               // for IPv6_VER_LEN_VALUE
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cne_vec.h>

#include <cnet_node_names.h>
#include "nd6_request_priv.h"
#include "nd6.h"

static __cne_always_inline cne_edge_t
nd6_request_process_mbuf(struct cne_graph *graph, struct cne_node *node, pktmbuf_t *mbuf)
{
    nd6_request_node_ctx_t *ctx = (nd6_request_node_ctx_t *)node->ctx;

    struct cne_ipv6_hdr *ip6;
    char *buf;
    size_t len;
    struct sockaddr_in6 sin6 = {0};

    ip6 = pktmbuf_mtod_offset(mbuf, struct cne_ipv6_hdr *, mbuf->l2_len);
    buf = (char *)ip6;
    len = pktmbuf_data_len(mbuf);

    /* Send out ND6 solicitation message for resolving destination ip6 addr */
    nd6_send_ns(graph, node, (struct in6_addr *)ip6->src_addr, (struct in6_addr *)ip6->dst_addr,
                false);

    /* Now send out the ip6 data packet itself to kernel */
    if (ctx->s6 >= 0) {
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port   = 0;
        inet6_addr_copy(&sin6.sin6_addr, (struct in6_addr *)ip6->dst_addr);

        if (sendto(ctx->s6, buf, len, 0, (struct sockaddr *)&sin6, sizeof(sin6)) < 0)
            CNE_WARN("Unable to send packets: %s\n", strerror(errno));
    }

    return ND6_REQUEST_NEXT_PKT_DROP;
}

static uint16_t
nd6_request_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
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
    next_index = ND6_REQUEST_NEXT_PKT_DROP;

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

        next0 = nd6_request_process_mbuf(graph, node, mbuf0);
        next1 = nd6_request_process_mbuf(graph, node, mbuf1);
        next2 = nd6_request_process_mbuf(graph, node, mbuf2);
        next3 = nd6_request_process_mbuf(graph, node, mbuf3);

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

        next0 = nd6_request_process_mbuf(graph, node, mbuf0);

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
nd6_request_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    nd6_request_node_ctx_t *ctx = (nd6_request_node_ctx_t *)node->ctx;

    ctx->s6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (ctx->s6 < 0) {
        int errnum = errno;

        if (errnum == EPROTONOSUPPORT)
            ctx->s6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

        if (ctx->s6 < 0)
            CNE_ERR_RET("Unable to open ICMPv6 socket\n");
    }

    return 0;
}

static void
nd6_request_node_fini(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    nd6_request_node_ctx_t *ctx = (nd6_request_node_ctx_t *)node->ctx;

    if (ctx->s6 >= 0)
        close(ctx->s6);
    ctx->s6 = -1;
}

static struct cne_node_register nd6_request_node_base = {
    .process = nd6_request_node_process,
    .name    = ND6_REQUEST_NODE_NAME,

    .init = nd6_request_node_init,
    .fini = nd6_request_node_fini,

    .nb_edges = ND6_REQUEST_NEXT_MAX,
    .next_nodes =
        {
            [ND6_REQUEST_NEXT_PKT_DROP] = PKT_DROP_NODE_NAME,
        },
};

struct cne_node_register *
nd6_request_node_get(void)
{
    return &nd6_request_node_base;
}

CNE_NODE_REGISTER(nd6_request_node_base);
