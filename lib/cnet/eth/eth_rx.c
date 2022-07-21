/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
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
#include <cnet_eth.h>
#include <net/cne_net.h>

#include <cnet_node_names.h>
#include "eth_rx_priv.h"

static struct eth_rx_node_main eth_rx_main;

static __cne_always_inline void
mbuf_update(pktmbuf_t *m, uint16_t lpid)
{
    struct cne_net_hdr_lens hdr_lens;
    struct cne_ether_hdr *eth_hdr;

    m->packet_type = cne_get_ptype(m, &hdr_lens, CNE_PTYPE_ALL_MASK);

    m->ol_flags = 0;

    eth_hdr = pktmbuf_mtod(m, struct cne_ether_hdr *);

    if (eth_hdr->ether_type == __ETHER_TYPE_IPV6)
        m->ol_flags |= CNE_MBUF_TYPE_IPv6;

    if (ether_addr_is_broadcast(&eth_hdr->d_addr))
        m->ol_flags |= CNE_MBUF_TYPE_BCAST;
    else if (ether_addr_is_multicast(&eth_hdr->d_addr))
        m->ol_flags |= CNE_MBUF_TYPE_MCAST;

    m->tx_offload = 0;
    m->l2_len     = hdr_lens.l2_len;
    m->l3_len     = hdr_lens.l3_len;
    m->l4_len     = hdr_lens.l4_len;
    m->lport      = lpid;

    /* Skip past the L2 header */
    pktmbuf_adj_offset(m, m->l2_len);
}

static uint16_t
eth_pkt_parse(eth_rx_node_ctx_t *ctx, pktmbuf_t **mbufs, uint16_t nb_pkts)
{
    uint16_t n_left, lpid;
    pktmbuf_t **pkts;

    pkts   = mbufs;
    n_left = nb_pkts;
    lpid   = ctx->port_id;

    /* Prefetch next-next pktmbufs */
    if (n_left >= 4) {
        cne_prefetch0(pktmbuf_mtod(pkts[0], void *));
        cne_prefetch0(pktmbuf_mtod(pkts[1], void *));
        cne_prefetch0(pktmbuf_mtod(pkts[2], void *));
        cne_prefetch0(pktmbuf_mtod(pkts[3], void *));
    }

    while (n_left >= 4) {
        /* Prefetch next-next pktmbufs */
        if (likely(n_left >= 8)) {
            cne_prefetch0(pktmbuf_mtod(pkts[4], void *));
            cne_prefetch0(pktmbuf_mtod(pkts[5], void *));
            cne_prefetch0(pktmbuf_mtod(pkts[6], void *));
            cne_prefetch0(pktmbuf_mtod(pkts[7], void *));
        }

        /* Extract ptype of mbuf0, mbuf1, mbuf2, mbuf3 */
        mbuf_update(pkts[0], lpid);
        mbuf_update(pkts[1], lpid);
        mbuf_update(pkts[2], lpid);
        mbuf_update(pkts[3], lpid);

        pkts += 4;
        n_left -= 4;
    }

    while (n_left > 0) {
        mbuf_update(pkts[0], lpid);
        pkts++;
        n_left--;
    }

    return nb_pkts;
}

static uint16_t
eth_rx_node_do(struct cne_graph *graph, struct cne_node *node, eth_rx_node_ctx_t *ctx)
{
    uint16_t count;
    uint16_t nb_pkts;

    /* Get pkts from port */
    nb_pkts = (node->size >= CNE_GRAPH_BURST_SIZE) ? CNE_GRAPH_BURST_SIZE : node->size;
    count   = pktdev_rx_burst(ctx->port_id, (pktmbuf_t **)node->objs, nb_pkts);
    if (count == PKTDEV_ADMIN_STATE_DOWN)
        return count;

    if (count) {
        eth_pkt_parse(ctx, (pktmbuf_t **)node->objs, count);
        node->idx = count;

        /* Enqueue to next node */
        cne_node_next_stream_move(graph, node, ETH_RX_NEXT_PTYPE);
    }
    return count;
}

static uint16_t
eth_rx_node_process(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t cnt)
{
    eth_rx_node_ctx_t *ctx = (eth_rx_node_ctx_t *)node->ctx;

    CNE_SET_USED(objs);
    CNE_SET_USED(cnt);

    return eth_rx_node_do(graph, node, ctx);
}

static int
eth_rx_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    eth_rx_node_ctx_t *ctx   = (eth_rx_node_ctx_t *)node->ctx;
    eth_rx_node_elem_t *elem = eth_rx_main.head;

    CNE_BUILD_BUG_ON(sizeof(eth_rx_node_ctx_t) > CNE_NODE_CTX_SZ);

    while (elem) {
        if (elem->nid == node->id) {
            /* Update node specific context */
            memcpy(ctx, &elem->ctx, sizeof(eth_rx_node_ctx_t));
            break;
        }
        elem = elem->next;
    }

    return 0;
}

struct eth_rx_node_main *
eth_rx_get_node_data_get(void)
{
    return &eth_rx_main;
}

static struct cne_node_register eth_rx_node_base = {
    .process = eth_rx_node_process,
    .flags   = CNE_NODE_SOURCE_F,
    .name    = ETH_RX_NODE_NAME,

    .init = eth_rx_node_init,

    .nb_edges = ETH_RX_NEXT_MAX,
    .next_nodes =
        {
            [ETH_RX_NEXT_PTYPE] = PTYPE_NODE_NAME,
        },
};

struct cne_node_register *
eth_rx_node_get(void)
{
    return &eth_rx_node_base;
}

CNE_NODE_REGISTER(eth_rx_node_base);
