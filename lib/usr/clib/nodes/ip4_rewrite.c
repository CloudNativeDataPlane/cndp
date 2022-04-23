/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <cne_graph.h>               // for cne_node_register, CNE_NODE_REGISTER
#include <cne_graph_worker.h>        // for cne_node_enqueue_x1, cne_node_nex...
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_mtod
#include <cne_vect.h>                // for cne_xmm_t
#include <net/cne_ether.h>           // for cne_ether_hdr
#include <errno.h>                   // for EINVAL, ENOMEM
#include <netinet/in.h>              // for htons
#include <stdbool.h>                 // for true, bool
#include <stddef.h>                  // for offsetof
#include <stdint.h>                  // for uint16_t, uint8_t, uint32_t, uint...
#include <stdlib.h>                  // for calloc
#include <string.h>                  // for memcpy, NULL

#include "node_ip4_api.h"                 // for cne_node_ip4_rewrite_add
#include "ip4_rewrite_priv.h"             // for ip4_rewrite_nh_header, ip4_rewrit...
#include "node_private.h"                 // for node_mbuf_priv1, node_mbuf_priv1:...
#include "cne_branch_prediction.h"        // for likely, unlikely
#include "cne_common.h"                   // for CNE_BUILD_BUG_ON, CNE_PRIORITY_LAST
#include "cne_log.h"                      // for CNE_LOG_DEBUG
#include "cne_prefetch.h"                 // for cne_prefetch0

struct ip4_rewrite_node_ctx {
    /* Dynamic offset to mbuf priv1 */
    int mbuf_priv1_off;
    /* Cached next index */
    uint16_t next_index;
};

static struct ip4_rewrite_node_main *ip4_rewrite_nm;

#define IP4_REWRITE_NODE_LAST_NEXT(ctx) (((struct ip4_rewrite_node_ctx *)ctx)->next_index)

#define IP4_REWRITE_NODE_PRIV1_OFF(ctx) (((struct ip4_rewrite_node_ctx *)ctx)->mbuf_priv1_off)

static uint16_t
ip4_rewrite_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                         uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    struct ip4_rewrite_nh_header *nh = ip4_rewrite_nm->nh;
    const int dyn                    = IP4_REWRITE_NODE_PRIV1_OFF(node->ctx);
    uint16_t next0, next1, next2, next3, next_index;
    struct cne_ipv4_hdr *ip0, *ip1, *ip2, *ip3;
    uint16_t n_left_from, held = 0, last_spec = 0;
    void *d0, *d1, *d2, *d3;
    void **to_next, **from;
    cne_xmm_t priv01;
    cne_xmm_t priv23;
    int i;

    /* Speculative next as last next */
    next_index = IP4_REWRITE_NODE_LAST_NEXT(node->ctx);
    cne_prefetch0(nh);

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    for (i = 0; i < 4 && i < n_left_from; i++)
        cne_prefetch0(pkts[i]);

    /* Get stream for the speculated next node */
    to_next = cne_node_next_stream_get(graph, node, next_index, nb_objs);

    /* Update Ethernet header of pkts */
    while (n_left_from >= 4) {
        if (likely(n_left_from > 7)) {
            /* Prefetch only next-mbuf struct and priv area.
             * Data need not be prefetched as we only write.
             */
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
        priv01.u64[0] = node_mbuf_priv1(mbuf0, dyn)->u;
        priv01.u64[1] = node_mbuf_priv1(mbuf1, dyn)->u;
        priv23.u64[0] = node_mbuf_priv1(mbuf2, dyn)->u;
        priv23.u64[1] = node_mbuf_priv1(mbuf3, dyn)->u;

        /* Increment checksum by one. */
        priv01.u32[1] += htons(0x0100);
        priv01.u32[3] += htons(0x0100);
        priv23.u32[1] += htons(0x0100);
        priv23.u32[3] += htons(0x0100);

        /* Update ttl,cksum rewrite ethernet hdr on mbuf0 */
        d0 = pktmbuf_mtod(mbuf0, void *);
        memcpy(d0, nh[priv01.u16[0]].rewrite_data, nh[priv01.u16[0]].rewrite_len);

        next0             = nh[priv01.u16[0]].tx_node;
        ip0               = (struct cne_ipv4_hdr *)((uint8_t *)d0 + sizeof(struct cne_ether_hdr));
        ip0->time_to_live = priv01.u16[1] - 1;
        ip0->hdr_checksum = priv01.u16[2] + priv01.u16[3];

        /* Update ttl,cksum rewrite ethernet hdr on mbuf1 */
        d1 = pktmbuf_mtod(mbuf1, void *);
        memcpy(d1, nh[priv01.u16[4]].rewrite_data, nh[priv01.u16[4]].rewrite_len);

        next1             = nh[priv01.u16[4]].tx_node;
        ip1               = (struct cne_ipv4_hdr *)((uint8_t *)d1 + sizeof(struct cne_ether_hdr));
        ip1->time_to_live = priv01.u16[5] - 1;
        ip1->hdr_checksum = priv01.u16[6] + priv01.u16[7];

        /* Update ttl,cksum rewrite ethernet hdr on mbuf2 */
        d2 = pktmbuf_mtod(mbuf2, void *);
        memcpy(d2, nh[priv23.u16[0]].rewrite_data, nh[priv23.u16[0]].rewrite_len);
        next2             = nh[priv23.u16[0]].tx_node;
        ip2               = (struct cne_ipv4_hdr *)((uint8_t *)d2 + sizeof(struct cne_ether_hdr));
        ip2->time_to_live = priv23.u16[1] - 1;
        ip2->hdr_checksum = priv23.u16[2] + priv23.u16[3];

        /* Update ttl,cksum rewrite ethernet hdr on mbuf3 */
        d3 = pktmbuf_mtod(mbuf3, void *);
        memcpy(d3, nh[priv23.u16[4]].rewrite_data, nh[priv23.u16[4]].rewrite_len);

        next3             = nh[priv23.u16[4]].tx_node;
        ip3               = (struct cne_ipv4_hdr *)((uint8_t *)d3 + sizeof(struct cne_ether_hdr));
        ip3->time_to_live = priv23.u16[5] - 1;
        ip3->hdr_checksum = priv23.u16[6] + priv23.u16[7];

        /* Enqueue four to next node */
        cne_edge_t fix_spec =
            ((next_index == next0) && (next0 == next1) && (next1 == next2) && (next2 == next3));

        if (unlikely(fix_spec == 0)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            /* next0 */
            if (next_index == next0) {
                to_next[0] = from[0];
                to_next++;
                held++;
            } else {
                cne_node_enqueue_x1(graph, node, next0, from[0]);
            }

            /* next1 */
            if (next_index == next1) {
                to_next[0] = from[1];
                to_next++;
                held++;
            } else {
                cne_node_enqueue_x1(graph, node, next1, from[1]);
            }

            /* next2 */
            if (next_index == next2) {
                to_next[0] = from[2];
                to_next++;
                held++;
            } else {
                cne_node_enqueue_x1(graph, node, next2, from[2]);
            }

            /* next3 */
            if (next_index == next3) {
                to_next[0] = from[3];
                to_next++;
                held++;
            } else {
                cne_node_enqueue_x1(graph, node, next3, from[3]);
            }

            from += 4;

            /* Change speculation if last two are same */
            if ((next_index != next3) && (next2 == next3)) {
                /* Put the current speculated node */
                cne_node_next_stream_put(graph, node, next_index, held);
                held = 0;

                /* Get next speculated stream */
                next_index = next3;
                to_next    = cne_node_next_stream_get(graph, node, next_index, nb_objs);
            }
        } else {
            last_spec += 4;
        }
    }

    while (n_left_from > 0) {
        uint16_t chksum;

        mbuf0 = pkts[0];

        pkts += 1;
        n_left_from -= 1;

        d0 = pktmbuf_mtod(mbuf0, void *);
        memcpy(d0, nh[node_mbuf_priv1(mbuf0, dyn)->nh].rewrite_data,
               nh[node_mbuf_priv1(mbuf0, dyn)->nh].rewrite_len);

        next0  = nh[node_mbuf_priv1(mbuf0, dyn)->nh].tx_node;
        ip0    = (struct cne_ipv4_hdr *)((uint8_t *)d0 + sizeof(struct cne_ether_hdr));
        chksum = node_mbuf_priv1(mbuf0, dyn)->cksum + htons(0x0100);
        chksum += chksum >= 0xffff;
        ip0->hdr_checksum = chksum;
        ip0->time_to_live = node_mbuf_priv1(mbuf0, dyn)->ttl - 1;

        if (unlikely(next_index ^ next0)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            cne_node_enqueue_x1(graph, node, next0, from[0]);
            from += 1;
        } else {
            last_spec += 1;
        }
    }

    /* !!! Home run !!! */
    if (likely(last_spec == nb_objs)) {
        cne_node_next_stream_move(graph, node, next_index);
        return nb_objs;
    }

    held += last_spec;
    memcpy(to_next, from, last_spec * sizeof(from[0]));
    cne_node_next_stream_put(graph, node, next_index, held);
    /* Save the last next used */
    IP4_REWRITE_NODE_LAST_NEXT(node->ctx) = next_index;

    return nb_objs;
}

static int
ip4_rewrite_node_init(const struct cne_graph *graph, struct cne_node *node __cne_unused)
{
    static bool init_once;

    CNE_SET_USED(graph);
    CNE_BUILD_BUG_ON(sizeof(struct ip4_rewrite_node_ctx) > CNE_NODE_CTX_SZ);

    if (!init_once) {
        node_mbuf_priv1_dynfield_offset = offsetof(pktmbuf_t, udata64);
        init_once                       = true;
    }
    IP4_REWRITE_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_offset;

    node_dbg("ip4_rewrite", "Initialized ip4_rewrite node initialized");

    return 0;
}

int
ip4_rewrite_set_next(uint16_t port_id, uint16_t next_index)
{
    if (ip4_rewrite_nm == NULL) {
        ip4_rewrite_nm = calloc(1, sizeof(struct ip4_rewrite_node_main));
        if (ip4_rewrite_nm == NULL)
            return -ENOMEM;
    }
    ip4_rewrite_nm->next_index[port_id] = next_index;

    return 0;
}

int
cne_node_ip4_rewrite_add(uint16_t next_hop, uint8_t *rewrite_data, uint8_t rewrite_len,
                         uint16_t dst_port)
{
    struct ip4_rewrite_nh_header *nh;

    if (next_hop >= CNE_GRAPH_IP4_REWRITE_MAX_NH)
        return -EINVAL;

    if (rewrite_len > CNE_GRAPH_IP4_REWRITE_MAX_LEN)
        return -EINVAL;

    if (ip4_rewrite_nm == NULL) {
        ip4_rewrite_nm = calloc(1, sizeof(struct ip4_rewrite_node_main));
        if (ip4_rewrite_nm == NULL)
            return -ENOMEM;
    }

    /* Check if dst port doesn't exist as edge */
    if (!ip4_rewrite_nm->next_index[dst_port])
        return -EINVAL;

    /* Update next hop */
    nh = &ip4_rewrite_nm->nh[next_hop];

    memcpy(nh->rewrite_data, rewrite_data, rewrite_len);
    nh->tx_node     = ip4_rewrite_nm->next_index[dst_port];
    nh->rewrite_len = rewrite_len;
    nh->enabled     = true;

    return 0;
}

static struct cne_node_register ip4_rewrite_node = {
    .process = ip4_rewrite_node_process,
    .name    = "ip4_rewrite",
    /* Default edge i.e '0' is pkt drop */
    .nb_edges = 1,
    .next_nodes =
        {
            [0] = "pkt_drop",
        },
    .init = ip4_rewrite_node_init,
};

struct cne_node_register *
ip4_rewrite_node_get(void)
{
    return &ip4_rewrite_node;
}

CNE_NODE_REGISTER(ip4_rewrite_node);
