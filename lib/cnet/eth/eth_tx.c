/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
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

static struct eth_tx_node_main eth_tx_main;

static uint16_t
eth_tx_node_process(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    eth_tx_node_ctx_t *ctx = (eth_tx_node_ctx_t *)node->ctx;
    uint16_t port          = ctx->port; /* Get TX port id */
    uint16_t count         = nb_objs;

    CNE_SET_USED(graph);

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
        cne_node_next_stream_move(graph, node, ETH_TX_NEXT_PKT_CALLBACK);
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
