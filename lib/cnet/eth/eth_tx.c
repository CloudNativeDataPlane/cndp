/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
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
            int cnt;

            cnt = pktdev_tx_burst(port, (pktmbuf_t **)objs, nb_objs);
            if (cnt == PKTDEV_ADMIN_STATE_DOWN)
                return cnt;

            objs += cnt;
            nb_objs -= cnt;
        } while (nb_objs);
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
    .process = eth_tx_node_process,
    .name    = ETH_TX_NODE_NAME,

    .init = eth_tx_node_init,

    .nb_edges   = ETH_TX_NEXT_MAX,
    .next_nodes = {},
};

struct cne_node_register *
eth_tx_node_get(void)
{
    return &eth_tx_node_base;
}

CNE_NODE_REGISTER(eth_tx_node_base);
