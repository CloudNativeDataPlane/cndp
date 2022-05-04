/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <pktdev.h>                  // for pktdev_rx_burst
#include <cne_graph.h>               // for cne_node_register, CNE_GRAPH_BURST_SIZE
#include <cne_graph_worker.h>        // for cne_node, cne_node_next_stream_move
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_mtod, pktmbuf_s::(a...
#include <pktmbuf_ptype.h>           // for CNE_PTYPE_L3_IPV4_EXT_UNKNOWN, CNE_PTY...
#include <net/cne_ether.h>           // for cne_ether_hdr
#include <net/ethernet.h>            // for ETHERTYPE_IP, ETHERTYPE_IPV6
#include <netinet/in.h>              // for htons
#include <stdint.h>                  // for uint16_t, uint32_t
#include <string.h>                  // for memcpy, NULL

#include "pktdev_rx_priv.h"        // for pktdev_rx_node_ctx_t, pktdev_rx_node_e...
#include "node_private.h"          // for node_info
#include "cne_common.h"            // for CNE_SET_USED, __cne_always_inline, CNE...
#include "cne_log.h"               // for CNE_LOG_INFO, CNE_VERIFY
#include "cne_prefetch.h"          // for cne_prefetch0

static struct pktdev_rx_node_main pktdev_rx_main;

static inline uint32_t
l3_ptype(uint16_t etype, uint32_t ptype)
{
    ptype = ptype & ~CNE_PTYPE_L3_MASK;
    if (etype == htons(ETHERTYPE_IP))
        ptype |= CNE_PTYPE_L3_IPV4_EXT_UNKNOWN;
    else if (etype == htons(ETHERTYPE_IPV6))
        ptype |= CNE_PTYPE_L3_IPV6_EXT_UNKNOWN;
    return ptype;
}

/* Callback for soft ptype parsing */
static uint16_t
eth_pkt_parse_cb(uint16_t port, pktmbuf_t **mbufs, uint16_t nb_pkts, uint16_t max_pkts,
                 void *user_param)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3;
    struct cne_ether_hdr *eth_hdr;
    uint16_t etype, n_left;
    pktmbuf_t **pkts;

    CNE_SET_USED(port);
    CNE_SET_USED(max_pkts);
    CNE_SET_USED(user_param);

    pkts   = mbufs;
    n_left = nb_pkts;
    while (n_left >= 12) {

        /* Prefetch next-next pktmbufs */
        cne_prefetch0(pkts[8]);
        cne_prefetch0(pkts[9]);
        cne_prefetch0(pkts[10]);
        cne_prefetch0(pkts[11]);

        /* Prefetch next pktmbuf data */
        cne_prefetch0(pktmbuf_mtod(pkts[4], struct cne_ether_hdr *));
        cne_prefetch0(pktmbuf_mtod(pkts[5], struct cne_ether_hdr *));
        cne_prefetch0(pktmbuf_mtod(pkts[6], struct cne_ether_hdr *));
        cne_prefetch0(pktmbuf_mtod(pkts[7], struct cne_ether_hdr *));

        mbuf0 = pkts[0];
        mbuf1 = pkts[1];
        mbuf2 = pkts[2];
        mbuf3 = pkts[3];
        pkts += 4;
        n_left -= 4;

        /* Extract ptype of mbuf0 */
        eth_hdr            = pktmbuf_mtod(mbuf0, struct cne_ether_hdr *);
        etype              = eth_hdr->ether_type;
        mbuf0->packet_type = l3_ptype(etype, 0);

        /* Extract ptype of mbuf1 */
        eth_hdr            = pktmbuf_mtod(mbuf1, struct cne_ether_hdr *);
        etype              = eth_hdr->ether_type;
        mbuf1->packet_type = l3_ptype(etype, 0);

        /* Extract ptype of mbuf2 */
        eth_hdr            = pktmbuf_mtod(mbuf2, struct cne_ether_hdr *);
        etype              = eth_hdr->ether_type;
        mbuf2->packet_type = l3_ptype(etype, 0);

        /* Extract ptype of mbuf3 */
        eth_hdr            = pktmbuf_mtod(mbuf3, struct cne_ether_hdr *);
        etype              = eth_hdr->ether_type;
        mbuf3->packet_type = l3_ptype(etype, 0);
    }

    while (n_left > 0) {
        mbuf0 = pkts[0];

        pkts += 1;
        n_left -= 1;

        /* Extract ptype of mbuf0 */
        eth_hdr            = pktmbuf_mtod(mbuf0, struct cne_ether_hdr *);
        etype              = eth_hdr->ether_type;
        mbuf0->packet_type = l3_ptype(etype, 0);
    }

    return nb_pkts;
}

static __cne_always_inline uint16_t
pktdev_rx_node_process_inline(struct cne_graph *graph, struct cne_node *node,
                              pktdev_rx_node_ctx_t *ctx)
{
    uint16_t count, next_index;
    uint16_t port;

    port       = ctx->port_id;
    next_index = ctx->cls_next;

    /* Get pkts from port */
    count = pktdev_rx_burst(port, (pktmbuf_t **)node->objs, CNE_GRAPH_BURST_SIZE);

    if (count) {
        eth_pkt_parse_cb(port, (pktmbuf_t **)node->objs, count, count, NULL);
        node->idx = count;

        /* Enqueue to next node */
        cne_node_next_stream_move(graph, node, next_index);
    }
    return count;
}

static __cne_always_inline uint16_t
pktdev_rx_node_process(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t cnt)
{
    pktdev_rx_node_ctx_t *ctx = (pktdev_rx_node_ctx_t *)node->ctx;
    uint16_t n_pkts           = 0;

    CNE_SET_USED(objs);
    CNE_SET_USED(cnt);

    n_pkts = pktdev_rx_node_process_inline(graph, node, ctx);
    return n_pkts;
}

#define MAX_PTYPES 16
static int
pktdev_ptype_setup(uint16_t port)
{
    node_info("pktdev_rx", "Enabling ptype callback for required ptypes on port %u", port);

    return 0;
}

static int
pktdev_rx_node_init(const struct cne_graph *graph, struct cne_node *node)
{
    pktdev_rx_node_ctx_t *ctx   = (pktdev_rx_node_ctx_t *)node->ctx;
    pktdev_rx_node_elem_t *elem = pktdev_rx_main.head;

    CNE_SET_USED(graph);

    while (elem) {
        if (elem->nid == node->id) {
            /* Update node specific context */
            memcpy(ctx, &elem->ctx, sizeof(pktdev_rx_node_ctx_t));
            break;
        }
        elem = elem->next;
    }

    CNE_VERIFY(elem != NULL);

    ctx->cls_next = PKTDEV_RX_NEXT_PKT_CLS;

    /* Check and setup ptype */
    return pktdev_ptype_setup(ctx->port_id);
}

struct pktdev_rx_node_main *
pktdev_rx_get_node_data_get(void)
{
    return &pktdev_rx_main;
}

static struct cne_node_register pktdev_rx_node_base = {
    .process = pktdev_rx_node_process,
    .flags   = CNE_NODE_SOURCE_F,
    .name    = "pktdev_rx",

    .init = pktdev_rx_node_init,

    .nb_edges = PKTDEV_RX_NEXT_MAX,
    .next_nodes =
        {
            /* Default pkt classification node */
            [PKTDEV_RX_NEXT_PKT_CLS]    = "pkt_cls",
            [PKTDEV_RX_NEXT_IP4_LOOKUP] = "ip4_lookup",
        },
};

struct cne_node_register *
pktdev_rx_node_get(void)
{
    return &pktdev_rx_node_base;
}

CNE_NODE_REGISTER(pktdev_rx_node_base);
