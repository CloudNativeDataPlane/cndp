/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <arpa/inet.h>               // for inet_ntop
#include <sys/socket.h>              // for AF_INET
#include <cne_fib.h>                 // for cne_fib_create, cne_fib_add, cne_...
#include <cne_graph.h>               // for cne_node_register, CNE_NODE_REGISTER
#include <cne_graph_worker.h>        // for cne_node, cne_node_enqueue_x1
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_mtod_offset
#include <net/cne_ether.h>           // for cne_ether_hdr
#include <cne_system.h>              // for cne_max_numa_nodes
#include <errno.h>                   // for errno
#include <netinet/in.h>              // for in_addr, INET6_ADDRSTRLEN, htonl
#include <stddef.h>                  // for offsetof
#include <stdint.h>                  // for uint16_t, uint32_t, uint8_t
#include <string.h>                  // for memcpy, NULL
#include <cnet_route.h>              // for
#include <cnet_route6.h>             // for
#include <cnet_meta.h>               // for

#include <cnet_node_names.h>
#include "ip6_node_api.h"                 // for
#include "ip6_input_priv.h"               // for CNE_NODE_IP6_INPUT_NEXT_PKT_DROP
#include "cne_branch_prediction.h"        // for likely, unlikely
#include "cne_common.h"                   // for CNE_BUILD_BUG_ON, CNE_PRIORITY_LAST
#include "cne_log.h"                      // for CNE_LOG_DEBUG, CNE_LOG_ERR, CNE_INFO
#include "cnet_fib_info.h"
#include "net/cne_inet6.h"        // for inet6_addr_copy

static inline void
ipv6_save_metadata(pktmbuf_t *mbuf, struct cne_ipv6_hdr *hdr)
{
    struct cnet_metadata *md;

    md = pktmbuf_metadata(mbuf);
    if (!md)
        CNE_RET("failed to get metadata pointer\n");

    md->faddr.cin_family = AF_INET6;
    md->faddr.cin_len    = sizeof(struct in6_addr);

    inet6_addr_copy_from_octs(&md->faddr.cin6_addr, hdr->src_addr);

    md->laddr.cin_family = AF_INET6;
    md->laddr.cin_len    = sizeof(struct in6_addr);

    inet6_addr_copy_from_octs(&md->laddr.cin6_addr, hdr->dst_addr);
}

static uint16_t
ip6_input_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                       uint16_t nb_objs)
{
    struct cnet *cnet = this_cnet;
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    cne_edge_t next0, next1, next2, next3;
    cne_edge_t next_index;
    void **to_next, **from;
    fib_info_t *fi;
    uint16_t last_spec = 0;
    uint16_t n_left_from;
    uint16_t held = 0;
    struct cne_ipv6_hdr *ip6[4];
    uint64_t dst[4]                         = {0};
    uint8_t dip[4][CNE_FIB6_IPV6_ADDR_SIZE] = {0};

    /* Speculative next */
    next_index = CNE_NODE_IP6_INPUT_NEXT_FORWARD;

    fi          = cnet->rt6_finfo;
    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        for (int i = 0; i < 4; i++)
            cne_prefetch0(pktmbuf_mtod(pkts[i], void *));
    }

    /* Get stream for the speculated next node */
    to_next = cne_node_next_stream_get(graph, node, next_index, nb_objs);
    while (n_left_from >= 4) {
        /* Prefetch next-next mbuf headers */
        if (likely(n_left_from > 11)) {
            cne_prefetch0(pkts[8]);
            cne_prefetch0(pkts[9]);
            cne_prefetch0(pkts[10]);
            cne_prefetch0(pkts[11]);
        }

        /* Prefetch next mbuf packet data */
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

        next0 = next1 = next2 = next3 = CNE_NODE_IP6_INPUT_NEXT_PKT_DROP;

        memset(dip[0], 0, CNE_FIB6_IPV6_ADDR_SIZE);
        memset(dip[1], 0, CNE_FIB6_IPV6_ADDR_SIZE);
        memset(dip[2], 0, CNE_FIB6_IPV6_ADDR_SIZE);
        memset(dip[3], 0, CNE_FIB6_IPV6_ADDR_SIZE);

        /* Extract DIP from mbufs plus validate the IP header checksum. */
        ip6[0] = pktmbuf_mtod(mbuf0, struct cne_ipv6_hdr *);
        ip6[1] = pktmbuf_mtod(mbuf1, struct cne_ipv6_hdr *);
        ip6[2] = pktmbuf_mtod(mbuf2, struct cne_ipv6_hdr *);
        ip6[3] = pktmbuf_mtod(mbuf3, struct cne_ipv6_hdr *);

        /* Adjust the data length for an IPv6 packet to the size given in the header. */
        pktmbuf_data_len(mbuf0) = be16toh(ip6[0]->payload_len);
        pktmbuf_data_len(mbuf1) = be16toh(ip6[1]->payload_len);
        pktmbuf_data_len(mbuf2) = be16toh(ip6[2]->payload_len);
        pktmbuf_data_len(mbuf3) = be16toh(ip6[3]->payload_len);

        /*
         * When the total length exceeds mbuf size, the size check/checksum below will
         * detect the invalid size/packet which will be dropped as 'dip[n]' is zero.
         */
        if (likely(pktmbuf_data_len(mbuf0) < pktmbuf_buf_len(mbuf0)))
            memcpy(dip[0], ip6[0]->dst_addr, CNE_FIB6_IPV6_ADDR_SIZE);

        if (likely(pktmbuf_data_len(mbuf1) < pktmbuf_buf_len(mbuf1)))
            memcpy(dip[1], ip6[1]->dst_addr, CNE_FIB6_IPV6_ADDR_SIZE);

        if (likely(pktmbuf_data_len(mbuf2) < pktmbuf_buf_len(mbuf2)))
            memcpy(dip[2], ip6[2]->dst_addr, CNE_FIB6_IPV6_ADDR_SIZE);

        if (likely(pktmbuf_data_len(mbuf3) < pktmbuf_buf_len(mbuf3)))
            memcpy(dip[3], ip6[3]->dst_addr, CNE_FIB6_IPV6_ADDR_SIZE);

        ipv6_save_metadata(mbuf0, ip6[0]);
        ipv6_save_metadata(mbuf1, ip6[1]);
        ipv6_save_metadata(mbuf2, ip6[2]);
        ipv6_save_metadata(mbuf3, ip6[3]);

        /* Perform FIB lookup to get NH and next node */
        if (likely(fib6_info_lookup_index(fi, dip, dst, 4) > 0)) {
            /* Extract next node id and NH */
            next0 = (dst[0] >> RT6_NEXT_INDEX_SHIFT);
            next1 = (dst[1] >> RT6_NEXT_INDEX_SHIFT);
            next2 = (dst[2] >> RT6_NEXT_INDEX_SHIFT);
            next3 = (dst[3] >> RT6_NEXT_INDEX_SHIFT);
        }

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

        /* Set defaults and the pointer to the IPv6 header. */
        next0 = CNE_NODE_IP6_INPUT_NEXT_PKT_DROP;
        memset(dip[0], 0, CNE_FIB6_IPV6_ADDR_SIZE);
        ip6[0] = pktmbuf_mtod(mbuf0, struct cne_ipv6_hdr *);

        /* Adjust the data length for an IPv6 packet to the size given in the header */
        pktmbuf_data_len(mbuf0) = be16toh(ip6[0]->payload_len);

        /*
         * When the total length exceeds mbuf size, the size check/checksum below will
         * detect the invalid size/packet which will be dropped as 'dip[n]' is zero.
         */
        if (likely(pktmbuf_data_len(mbuf0) < pktmbuf_buf_len(mbuf0)))
            memcpy(dip[0], ip6[0]->dst_addr, CNE_FIB6_IPV6_ADDR_SIZE);

        ipv6_save_metadata(mbuf0, ip6[0]);

        if (likely(fib6_info_lookup_index(fi, dip, dst, 1) > 0))
            next0 = (dst[0] >> RT6_NEXT_INDEX_SHIFT); /* Extract next node id and NH */

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

int
cne_node_ip6_add_input(struct cne_fib6 *fib, const uint8_t ip[CNE_FIB6_IPV6_ADDR_SIZE],
                       uint8_t depth, uint32_t hop)
{
    uint64_t nh = hop;

    nh |=
        (uint64_t)(((depth == 32) ? CNE_NODE_IP6_INPUT_NEXT_PROTO : CNE_NODE_IP6_INPUT_NEXT_FORWARD)
                   << RT6_NEXT_INDEX_SHIFT);

    return cne_fib6_add(fib, ip, depth, nh);
}

static struct cne_node_register ip6_input_node = {
    .process = ip6_input_node_process,
    .name    = IP6_INPUT_NODE_NAME,

    .nb_edges = CNE_NODE_IP6_INPUT_NEXT_MAX,
    .next_nodes =
        {
            [CNE_NODE_IP6_INPUT_NEXT_PKT_DROP] = PKT_DROP_NODE_NAME,
            [CNE_NODE_IP6_INPUT_NEXT_FORWARD]  = IP6_FORWARD_NODE_NAME,
            [CNE_NODE_IP6_INPUT_NEXT_PROTO]    = IP6_PROTO_NODE_NAME,
        },
};

CNE_NODE_REGISTER(ip6_input_node);
