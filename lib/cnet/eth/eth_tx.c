/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2025 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <pktdev.h>                  // for pktdev_tx_burst
#include <cne_graph.h>               // for cne_node_register, CNE_NODE_REGISTER
#include <cne_graph_worker.h>        // for cne_node, cne_graph
#include <pktmbuf.h>                 // for pktmbuf_t
#include <stdint.h>                  // for uint16_t, uint32_t, uint64_t

#include <cnet_eth.h>        // for

#include "cne_common.h"        // for CNE_MAX_ETHPORTS, CNE_PRIORITY_LAST
#include "cne_log.h"           // for CNE_VERIFY

#include <cnet_node_names.h>
#include "eth_tx_priv.h"        // for eth_tx_node_ctx_t, ETH_TX_NEXT_MAX
#include "chnl_callback_priv.h"
#include "cnet_pcb.h"

static struct eth_tx_node_main eth_tx_main;

static inline int
eth_tx_node_pktmbuf_has_userdata(pktmbuf_t *mbuf)
{
    struct pcb_entry *pcb = mbuf->userptr;
    if (unlikely(!pcb))
        return -1;

    if (pcb->ip_proto == IPPROTO_UDP)
        return ETH_TX_NEXT_PKT_CALLBACK;

    if (pcb->ip_proto == IPPROTO_TCP)
        return mbuf->data_len > (mbuf->l2_len + mbuf->l3_len + mbuf->l4_len)
                   ? ETH_TX_NEXT_PKT_CALLBACK
                   : -1;

    return -1;
}

static uint16_t
eth_tx_node_process(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    eth_tx_node_ctx_t *ctx = (eth_tx_node_ctx_t *)node->ctx;
    uint16_t port          = ctx->port; /* Get TX port id */
    uint16_t count         = nb_objs;

    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    int next0, next1, next2, next3;
    void **to_next, **from;
    uint16_t n_left_from;
    uint16_t held = 0;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (nb_objs) {
        do {
            int cnt = pktdev_tx_burst(port, (pktmbuf_t **)objs, nb_objs);
            if (cnt == PKTDEV_ADMIN_STATE_DOWN)
                return cnt;

            objs += cnt;
            nb_objs -= cnt;
        } while (nb_objs);

        struct cne_node *next = __cne_node_next_node_get(node, ETH_TX_NEXT_PKT_CALLBACK);
        chnl_callback_node_set_source(next, CHNL_CALLBACK_SOURCE_ETH_TX);

        if (n_left_from >= 4) {
            for (int i = 0; i < 4; i++)
                cne_prefetch0(pkts[i]);
        }

        /* Get stream for the speculated next node */
        to_next = (void **)calloc(count, sizeof(pktmbuf_t *));
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

            next0 = eth_tx_node_pktmbuf_has_userdata(mbuf0);
            next1 = eth_tx_node_pktmbuf_has_userdata(mbuf1);
            next2 = eth_tx_node_pktmbuf_has_userdata(mbuf2);
            next3 = eth_tx_node_pktmbuf_has_userdata(mbuf3);

            int fix_spec = (ETH_TX_NEXT_PKT_CALLBACK ^ next0) | (ETH_TX_NEXT_PKT_CALLBACK ^ next1) |
                           (ETH_TX_NEXT_PKT_CALLBACK ^ next2) | (ETH_TX_NEXT_PKT_CALLBACK ^ next3);

            if (unlikely(fix_spec)) {
                /* Next0 */
                if (next0 >= 0)
                    to_next[held++] = from[0];

                /* Next1 */
                if (next1 >= 0)
                    to_next[held++] = from[1];

                /* Next2 */
                if (next2 >= 0)
                    to_next[held++] = from[2];

                /* Next3 */
                if (next3 >= 0)
                    to_next[held++] = from[3];
            } else {
                to_next[held]     = from[0];
                to_next[held + 1] = from[1];
                to_next[held + 2] = from[2];
                to_next[held + 3] = from[3];
                held += 4;
            }

            from += 4;
        }

        if (likely(n_left_from > 0))
            cne_prefetch0(pkts[0]);

        while (n_left_from > 0) {
            if (likely(n_left_from > 0))
                cne_prefetch0(pkts[1]);

            mbuf0 = pkts[0];

            pkts += 1;
            n_left_from -= 1;

            next0 = eth_tx_node_pktmbuf_has_userdata(mbuf0);

            if (next0 >= 0)
                to_next[held++] = from[0];

            from += 1;
        }

        /* !!! Home run !!! */
        if (likely(held == count)) {
            cne_node_next_stream_move(graph, node, ETH_TX_NEXT_PKT_CALLBACK);
            free(to_next);
            return count;
        }

        /* Copy things successfully speculated till now */
        void **stream = cne_node_next_stream_get(graph, node, ETH_TX_NEXT_PKT_CALLBACK, held);
        memcpy(stream, to_next, held * sizeof(from[0]));
        cne_node_next_stream_put(graph, node, ETH_TX_NEXT_PKT_CALLBACK, held);
        free(to_next);
    }

    return count;
}

static int
eth_tx_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    eth_tx_node_ctx_t *ctx = (eth_tx_node_ctx_t *)node->ctx;
    uint16_t port_id       = CNE_MAX_ETHPORTS;
    int i;

    CNE_BUILD_BUG_ON(sizeof(eth_tx_node_ctx_t) > CNE_NODE_CTX_SZ);

    /* Find our port id */
    for (i = 0; i < CNE_MAX_ETHPORTS; i++) {
        if (eth_tx_main.nodes[i] == node->id) {
            port_id = i;
            break;
        }
    }
    CNE_VERIFY(port_id < CNE_MAX_ETHPORTS);

    /* Update port and queue */
    ctx->port = port_id;

    return 0;
}

struct eth_tx_node_main *
eth_tx_node_data_get(void)
{
    return &eth_tx_main;
}

static struct cne_node_register eth_tx_node_base = {
    .process  = eth_tx_node_process,
    .name     = ETH_TX_NODE_NAME,
    .init     = eth_tx_node_init,
    .nb_edges = ETH_TX_NEXT_MAX,
    .next_nodes =
        {
            [ETH_TX_NEXT_PKT_CALLBACK] = CHNL_CALLBACK_NODE_NAME,
        },
};

struct cne_node_register *
eth_tx_node_get(void)
{
    return &eth_tx_node_base;
}

CNE_NODE_REGISTER(eth_tx_node_base);
