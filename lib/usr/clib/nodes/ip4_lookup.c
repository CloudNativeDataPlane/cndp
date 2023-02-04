/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
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

#include "node_ip4_api.h"                 // for CNE_NODE_IP4_LOOKUP_NEXT_PKT_DROP
#include "node_private.h"                 // for node_mbuf_priv1, node_mbuf_priv1:...
#include "cne_branch_prediction.h"        // for likely, unlikely
#include "cne_common.h"                   // for CNE_BUILD_BUG_ON, CNE_PRIORITY_LAST
#include "cne_log.h"                      // for CNE_LOG_DEBUG, CNE_LOG_ERR, CNE_INFO

#define IPV4_L3FWD_FIB_MAX_RULES    1024
#define IPV4_L3FWD_FIB_NUMBER_TBL8S (1 << 8)

/* IP4 Lookup global data struct */
struct ip4_lookup_node_main {
    struct cne_fib *fib_tbl[8];
};

struct ip4_lookup_node_ctx {
    struct cne_fib *fib; /**< FIB table */
    int mbuf_priv1_off;  /**< Dynamic offset to mbuf priv1 */
};

int node_mbuf_priv1_dynfield_offset = -1;

static struct ip4_lookup_node_main ip4_lookup_nm;

#define IP4_LOOKUP_NODE_FIB(ctx) (((struct ip4_lookup_node_ctx *)ctx)->fib)

#define IP4_LOOKUP_NODE_PRIV1_OFF(ctx) (((struct ip4_lookup_node_ctx *)ctx)->mbuf_priv1_off)

static uint16_t
ip4_lookup_node_process_vec(struct cne_graph *graph, struct cne_node *node, void **objs,
                            uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    struct cne_fib *fib = IP4_LOOKUP_NODE_FIB(node->ctx);
    const int dyn       = IP4_LOOKUP_NODE_PRIV1_OFF(node->ctx);
    cne_edge_t next0, next1, next2, next3, next_index;
    struct cne_ipv4_hdr *ipv4_hdr;
    void **to_next, **from;
    uint16_t last_spec = 0;
    uint16_t n_left_from;
    uint16_t held = 0;
    uint32_t drop_nh;
    uint64_t dst[4];
    uint32_t dip[4];
    int rc, i;

    /* Speculative next */
    next_index = CNE_NODE_IP4_LOOKUP_NEXT_REWRITE;

    /* Drop node */
    drop_nh = ((uint32_t)CNE_NODE_IP4_LOOKUP_NEXT_PKT_DROP) << 16;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        for (i = 0; i < 4; i++)
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
            cne_prefetch0(pktmbuf_mtod_offset(pkts[4], void *, sizeof(struct cne_ether_hdr)));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[5], void *, sizeof(struct cne_ether_hdr)));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[6], void *, sizeof(struct cne_ether_hdr)));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[7], void *, sizeof(struct cne_ether_hdr)));
        }

        mbuf0 = pkts[0];
        mbuf1 = pkts[1];
        mbuf2 = pkts[2];
        mbuf3 = pkts[3];

        pkts += 4;
        n_left_from -= 4;

        /* Extract DIP of mbuf0 */
        ipv4_hdr = pktmbuf_mtod_offset(mbuf0, struct cne_ipv4_hdr *, sizeof(struct cne_ether_hdr));
        dip[0]   = ntohl(ipv4_hdr->dst_addr);

        /* Extract cksum, ttl as ipv4 hdr is in cache */
        node_mbuf_priv1(mbuf0, dyn)->cksum = ipv4_hdr->hdr_checksum;
        node_mbuf_priv1(mbuf0, dyn)->ttl   = ipv4_hdr->time_to_live;

        /* Extract DIP of mbuf1 */
        ipv4_hdr = pktmbuf_mtod_offset(mbuf1, struct cne_ipv4_hdr *, sizeof(struct cne_ether_hdr));
        dip[1]   = ntohl(ipv4_hdr->dst_addr);

        /* Extract cksum, ttl as ipv4 hdr is in cache */
        node_mbuf_priv1(mbuf1, dyn)->cksum = ipv4_hdr->hdr_checksum;
        node_mbuf_priv1(mbuf1, dyn)->ttl   = ipv4_hdr->time_to_live;

        /* Extract DIP of mbuf2 */
        ipv4_hdr = pktmbuf_mtod_offset(mbuf2, struct cne_ipv4_hdr *, sizeof(struct cne_ether_hdr));
        dip[2]   = ntohl(ipv4_hdr->dst_addr);

        /* Extract cksum, ttl as ipv4 hdr is in cache */
        node_mbuf_priv1(mbuf2, dyn)->cksum = ipv4_hdr->hdr_checksum;
        node_mbuf_priv1(mbuf2, dyn)->ttl   = ipv4_hdr->time_to_live;

        /* Extract DIP of mbuf3 */
        ipv4_hdr = pktmbuf_mtod_offset(mbuf3, struct cne_ipv4_hdr *, sizeof(struct cne_ether_hdr));
        dip[3]   = ntohl(ipv4_hdr->dst_addr);

        /* Extract cksum, ttl as ipv4 hdr is in cache */
        node_mbuf_priv1(mbuf3, dyn)->cksum = ipv4_hdr->hdr_checksum;
        node_mbuf_priv1(mbuf3, dyn)->ttl   = ipv4_hdr->time_to_live;

        /* Perform FIB lookup to get NH and next node */
        cne_fib_lookup_bulk(fib, dip, dst, 4);

        /* Extract next node id and NH */
        node_mbuf_priv1(mbuf0, dyn)->nh = dst[0] & 0xFFFF;
        next0                           = (dst[0] >> 16);

        node_mbuf_priv1(mbuf1, dyn)->nh = dst[1] & 0xFFFF;
        next1                           = (dst[1] >> 16);

        node_mbuf_priv1(mbuf2, dyn)->nh = dst[2] & 0xFFFF;
        next2                           = (dst[2] >> 16);

        node_mbuf_priv1(mbuf3, dyn)->nh = dst[3] & 0xFFFF;
        next3                           = (dst[3] >> 16);

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
        uint64_t next_hop;
        uint32_t ip;

        mbuf0 = pkts[0];

        pkts += 1;
        n_left_from -= 1;

        /* Extract DIP of mbuf0 */
        ipv4_hdr = pktmbuf_mtod_offset(mbuf0, struct cne_ipv4_hdr *, sizeof(struct cne_ether_hdr));

        /* Extract cksum, ttl as ipv4 hdr is in cache */
        node_mbuf_priv1(mbuf0, dyn)->cksum = ipv4_hdr->hdr_checksum;
        node_mbuf_priv1(mbuf0, dyn)->ttl   = ipv4_hdr->time_to_live;

        ip       = ntohl(ipv4_hdr->dst_addr);
        rc       = cne_fib_lookup_bulk(fib, &ip, &next_hop, 1);
        next_hop = (rc == 0) ? next_hop : drop_nh;

        node_mbuf_priv1(mbuf0, dyn)->nh = next_hop & 0xFFFF;
        next0                           = (next_hop >> 16);

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
cne_node_ip4_route_add(uint32_t ip, uint8_t depth, uint16_t next_hop,
                       enum cne_node_ip4_lookup_next next_node)
{
    char abuf[INET6_ADDRSTRLEN] = {0};
    struct in_addr in;
    uint8_t socket;
    uint32_t val;
    int ret;

    in.s_addr = htonl(ip);
    inet_ntop(AF_INET, &in, abuf, sizeof(abuf));

    /* Embedded next node id into 24 bit next hop */
    val = ((next_node << 16) | next_hop) & ((1ull << 24) - 1);
    node_dbg("ip4_lookup", "FIB: Adding route %s / %d nh (0x%x)", abuf, depth, val);

    for (socket = 0; socket < cne_max_numa_nodes(); socket++) {
        if (!ip4_lookup_nm.fib_tbl[socket])
            continue;

        ret = cne_fib_add(ip4_lookup_nm.fib_tbl[socket], ip, depth, val);
        if (ret < 0) {
            node_err("ip4_lookup",
                     "Unable to add entry %s / %d nh (%x) to FIB table on sock %d, rc=%d\n", abuf,
                     depth, val, socket, ret);
            return ret;
        }
    }

    return 0;
}

static int
setup_fib(struct ip4_lookup_node_main *nm, int socket)
{
    struct cne_fib_conf config_ipv4;

    /* One FIB table per socket */
    if (nm->fib_tbl[socket])
        return 0;

    /* create the FIB table */
    config_ipv4.type             = CNE_FIB_DIR24_8;
    config_ipv4.default_nh       = ((uint32_t)CNE_NODE_IP4_LOOKUP_NEXT_PKT_DROP) << 16;
    config_ipv4.max_routes       = IPV4_L3FWD_FIB_MAX_RULES;
    config_ipv4.dir24_8.nh_sz    = CNE_FIB_DIR24_8_4B;
    config_ipv4.dir24_8.num_tbl8 = IPV4_L3FWD_FIB_NUMBER_TBL8S;
    nm->fib_tbl[socket]          = cne_fib_create("fib", &config_ipv4);
    if (nm->fib_tbl[socket] == NULL)
        return -errno;

    return 0;
}

static int
ip4_lookup_node_init(const struct cne_graph *graph, struct cne_node *node)
{
    static uint8_t init_once;
    int rc;

    CNE_SET_USED(graph);
    CNE_BUILD_BUG_ON(sizeof(struct ip4_lookup_node_ctx) > CNE_NODE_CTX_SZ);

    if (!init_once) {
        node_mbuf_priv1_dynfield_offset = offsetof(pktmbuf_t, udata64);

        /* Setup FIB tables for all sockets */
        for (int socket = 0; socket < cne_max_numa_nodes(); socket++) {
            rc = setup_fib(&ip4_lookup_nm, socket);
            if (rc) {
                node_err("ip4_lookup", "Failed to setup fib tbl for sock %u, rc=%d", socket, rc);
                return rc;
            }
        }
        init_once = 1;
    }

    /* Update socket's FIB and mbuf dyn priv1 offset in node ctx */
    IP4_LOOKUP_NODE_FIB(node->ctx)       = ip4_lookup_nm.fib_tbl[0];
    IP4_LOOKUP_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_offset;

    node_dbg("ip4_lookup", "Initialized ip4_lookup node");

    return 0;
}

static struct cne_node_register ip4_lookup_node = {
    .process = ip4_lookup_node_process_vec,
    .name    = "ip4_lookup",

    .init = ip4_lookup_node_init,

    .nb_edges = CNE_NODE_IP4_LOOKUP_NEXT_MAX,
    .next_nodes =
        {
            [CNE_NODE_IP4_LOOKUP_NEXT_REWRITE]  = "ip4_rewrite",
            [CNE_NODE_IP4_LOOKUP_NEXT_PKT_DROP] = "pkt_drop",
        },
};

CNE_NODE_REGISTER(ip4_lookup_node);
