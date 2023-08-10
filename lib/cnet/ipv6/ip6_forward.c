/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <cne_graph.h>               // for cne_node_register, CNE_NODE_REGISTER
#include <cne_graph_worker.h>        // for cne_node_enqueue_x1, cne_node_nex...
#include <net/cne_ip.h>              // for cne_ipv6_hdr
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

#include <cne_common.h>                   // for CNE_BUILD_BUG_ON, CNE_PRIORITY_LAST
#include <cne_log.h>                      // for CNE_LOG_DEBUG
#include <cne_prefetch.h>                 // for cne_prefetch0
#include <cne_branch_prediction.h>        // for likely, unlikely
#include <cne_hash.h>                     // for

#include <cnet_const.h>        // for
#include <cnet_stk.h>
#include <cnet_netif.h>
#include <cnet_route.h>
#include <cnet_route6.h>
#include <cnet_ipv6.h>           // for
#include <net/ethernet.h>        // for ether_addr
#include <net/cne_udp.h>         // for
#include <cne_inet.h>            // for _in_addr
#include <cnet_nd6.h>            // for cne_arp

#include <cnet_node_names.h>
#include "ip6_node_api.h"        // for cne_node_ip6_forward_add
#include "ip6_forward_priv.h"
#include "cnet_fib_info.h"
#include "nd6.h"

struct ip6_forward_node_ctx {
    uint16_t next_index; /* Cached next index */
};

static struct ip6_forward_node_main *ip6_forward_nm;

#define IP6_FORWARD_NODE_LAST_NEXT(ctx) (((struct ip6_forward_node_ctx *)ctx)->next_index)

static uint16_t
ip6_forward_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                         uint16_t nb_objs)
{
    struct cnet *cnet = this_cnet;
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    uint16_t n0, n1, n2, n3, n_index;
    struct cne_ipv6_hdr *hdr[4];
    uint16_t n_left_from, held = 0, last_spec = 0;
    void **to_next, **from;
    struct netif *nif;
    fib_info_t *fi;
    struct cne_ether_hdr *eth[4];

    struct nd6_cache_entry *nd6[4];
    uint8_t ip6[4][IPV6_ADDR_LEN] = {0};

    /* Speculative next as last next */
    n_index = IP6_FORWARD_NODE_LAST_NEXT(node->ctx);

    fi          = cnet->arp_finfo;
    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        cne_prefetch0(pktmbuf_mtod(pkts[0], void *));
        cne_prefetch0(pktmbuf_mtod(pkts[1], void *));
        cne_prefetch0(pktmbuf_mtod(pkts[2], void *));
        cne_prefetch0(pktmbuf_mtod(pkts[3], void *));
    }

    /* Get stream for the speculated next node */
    to_next = cne_node_next_stream_get(graph, node, n_index, nb_objs);

    /* Update Ethernet header of pkts */
    while (n_left_from >= 4) {
        if (likely(n_left_from >= 12)) {
            /* Prefetch only next-mbuf struct and priv area.
             * Data need not be prefetched as we only write.
             */
            cne_prefetch0(pkts[8]);
            cne_prefetch0(pkts[9]);
            cne_prefetch0(pkts[10]);
            cne_prefetch0(pkts[11]);

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

        hdr[0] = pktmbuf_mtod(mbuf0, struct cne_ipv6_hdr *);
        memcpy(ip6[0], hdr[0]->dst_addr, IPV6_ADDR_LEN);
        eth[0] = pktmbuf_adjust(mbuf0, struct cne_ether_hdr *, -mbuf0->l2_len);

        hdr[1] = pktmbuf_mtod(mbuf1, struct cne_ipv6_hdr *);
        memcpy(ip6[1], hdr[1]->dst_addr, IPV6_ADDR_LEN);
        eth[1] = pktmbuf_adjust(mbuf1, struct cne_ether_hdr *, -mbuf1->l2_len);

        hdr[2] = pktmbuf_mtod(mbuf2, struct cne_ipv6_hdr *);
        memcpy(ip6[2], hdr[2]->dst_addr, IPV6_ADDR_LEN);
        eth[2] = pktmbuf_adjust(mbuf2, struct cne_ether_hdr *, -mbuf2->l2_len);

        hdr[3] = pktmbuf_mtod(mbuf3, struct cne_ipv6_hdr *);
        memcpy(ip6[3], hdr[3]->dst_addr, IPV6_ADDR_LEN);
        eth[3] = pktmbuf_adjust(mbuf3, struct cne_ether_hdr *, -mbuf3->l2_len);

        n0 = n1 = n2 = n3 = NODE_IP6_FORWARD_ND6_REQUEST;

        if (unlikely(fib6_info_lookup(fi, ip6, (void **)nd6, 4) > 0)) {
            struct netif *nif;

            if (likely(nd6[0])) {
                nif = cnet_netif_from_index(nd6[0]->netif_idx);
                ether_addr_copy(&nif->mac, &eth[0]->s_addr);
                ether_addr_copy(&nd6[0]->ll_addr, &eth[0]->d_addr);
                n0 = nd6[0]->netif_idx + NODE_IP6_FORWARD_OUTPUT_OFFSET;
            }

            if (likely(nd6[1])) {
                nif = cnet_netif_from_index(nd6[1]->netif_idx);
                ether_addr_copy(&nif->mac, &eth[1]->s_addr);
                ether_addr_copy(&nd6[1]->ll_addr, &eth[1]->d_addr);
                n1 = nd6[1]->netif_idx + NODE_IP6_FORWARD_OUTPUT_OFFSET;
            }

            if (likely(nd6[2])) {
                nif = cnet_netif_from_index(nd6[2]->netif_idx);
                ether_addr_copy(&nif->mac, &eth[2]->s_addr);
                ether_addr_copy(&nd6[2]->ll_addr, &eth[2]->d_addr);
                n2 = nd6[2]->netif_idx + NODE_IP6_FORWARD_OUTPUT_OFFSET;
            }

            if (likely(nd6[3])) {
                nif = cnet_netif_from_index(nd6[3]->netif_idx);
                ether_addr_copy(&nif->mac, &eth[3]->s_addr);
                ether_addr_copy(&nd6[3]->ll_addr, &eth[3]->d_addr);
                n3 = nd6[3]->netif_idx + NODE_IP6_FORWARD_OUTPUT_OFFSET;
            }
        }

        /* Enqueue four to next node */
        cne_edge_t fix_spec =
            ((n_index ^ n0) && (n_index ^ n1) && (n_index ^ n2) && (n_index ^ n3));

        if (unlikely(fix_spec)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            /* n0 */
            if (n_index == n0) {
                to_next[0] = from[0];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, n0, from[0]);

            /* n1 */
            if (n_index == n1) {
                to_next[0] = from[1];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, n1, from[1]);

            /* n2 */
            if (n_index == n2) {
                to_next[0] = from[2];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, n2, from[2]);

            /* n3 */
            if (n_index == n3) {
                to_next[0] = from[3];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, n3, from[3]);

            /* Change speculation if last two are same */
            if ((n_index != n3) && (n2 == n3) && (n_index != n3)) {
                /* Put the current speculated node */
                cne_node_next_stream_put(graph, node, n_index, held);

                held = 0;

                /* Get next speculated stream */
                n_index = n3;
                to_next = cne_node_next_stream_get(graph, node, n_index, nb_objs);
            } else if (n_index == n3)
                n_index = n3;

            from += 4;
        } else
            last_spec += 4;
    }

    while (n_left_from > 0) {
        mbuf0 = pkts[0];

        pkts += 1;
        n_left_from -= 1;

        hdr[0] = pktmbuf_mtod(mbuf0, struct cne_ipv6_hdr *);
        eth[0] = pktmbuf_adjust(mbuf0, struct cne_ether_hdr *, -mbuf0->l2_len);

        /* Look up the destination IP address in the nd6 hash table */
        memcpy(ip6[0], hdr[0]->dst_addr, IPV6_ADDR_LEN);

        n0 = NODE_IP6_FORWARD_ND6_REQUEST;
        if (unlikely(fib6_info_lookup(fi, ip6, (void **)nd6, 1) > 0)) {
            nif = cnet_netif_from_index(nd6[0]->netif_idx);
            ether_addr_copy(&nif->mac, &eth[0]->s_addr);
            ether_addr_copy(&nd6[0]->ll_addr, &eth[0]->d_addr);
            n0 = nd6[0]->netif_idx + NODE_IP6_FORWARD_OUTPUT_OFFSET;
        }

        if (unlikely(n_index ^ n0)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            cne_node_enqueue_x1(graph, node, n0, from[0]);
            from += 1;
        } else
            last_spec += 1;
    }

    /* !!! Home run !!! */
    if (likely(last_spec == nb_objs)) {
        cne_node_next_stream_move(graph, node, n_index);
        return nb_objs;
    }

    held += last_spec;

    memcpy(to_next, from, last_spec * sizeof(from[0]));
    cne_node_next_stream_put(graph, node, n_index, held);

    /* Save the last next used */
    IP6_FORWARD_NODE_LAST_NEXT(node->ctx) = n_index;

    return nb_objs;
}

static int
ip6_forward_node_init(const struct cne_graph *graph, struct cne_node *node __cne_unused)
{
    CNE_SET_USED(graph);
    CNE_SET_USED(node);
    CNE_BUILD_BUG_ON(sizeof(struct ip6_forward_node_ctx) > CNE_NODE_CTX_SZ);

    return 0;
}

int
ip6_forward_set_next(uint16_t port_id, uint16_t next_index)
{
    if (ip6_forward_nm == NULL) {
        ip6_forward_nm = calloc(1, sizeof(struct ip6_forward_node_main));
        if (ip6_forward_nm == NULL)
            return -ENOMEM;
    }
    ip6_forward_nm->next_index[port_id] = next_index;

    return 0;
}

static struct cne_node_register ip6_forward_node = {
    .process = ip6_forward_node_process,
    .name    = IP6_FORWARD_NODE_NAME,

    .init = ip6_forward_node_init,

    /* Default edge i.e '0' is pkt drop */
    .nb_edges = NODE_IP6_FORWARD_OUTPUT_OFFSET,
    .next_nodes =
        {
            [NODE_IP6_FORWARD_PKT_DROP]    = PKT_DROP_NODE_NAME,
            [NODE_IP6_FORWARD_ND6_REQUEST] = ND6_REQUEST_NODE_NAME,
            /* TX outputs will be placed here */
        },
};

struct cne_node_register *
ip6_forward_node_get(void)
{
    return &ip6_forward_node;
}

CNE_NODE_REGISTER(ip6_forward_node);
