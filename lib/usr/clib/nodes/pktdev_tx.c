/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <pktdev.h>                  // for pktdev_tx_burst
#include <cne_graph.h>               // for cne_node_register, CNE_NODE_REGISTER
#include <cne_graph_worker.h>        // for cne_node, cne_graph
#include <pktmbuf.h>                 // for pktmbuf_t
#include <stdint.h>                  // for uint16_t, uint32_t, uint64_t

#include "pktdev_tx_priv.h"        // for pktdev_tx_node_ctx_t, PKTDEV_TX_NEXT_MAX
#include "cne_common.h"            // for CNE_MAX_ETHPORTS, CNE_PRIORITY_LAST
#include "cne_log.h"               // for CNE_VERIFY

static struct pktdev_tx_node_main pktdev_tx_main;

static uint16_t
pktdev_tx_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                       uint16_t nb_objs)
{
    pktdev_tx_node_ctx_t *ctx = (pktdev_tx_node_ctx_t *)node->ctx;
    uint16_t port;
    uint16_t count = 0;

    CNE_SET_USED(graph);

    /* Get Tx port id */
    port = ctx->port;

    do {
        int cnt = pktdev_tx_burst(port, (pktmbuf_t **)objs, nb_objs);
        if (cnt == PKTDEV_ADMIN_STATE_DOWN)
            return cnt;

        objs += cnt;
        nb_objs -= cnt;
        count += cnt;
    } while (nb_objs);

    return count;
}

static int
pktdev_tx_node_init(const struct cne_graph *graph, struct cne_node *node)
{
    pktdev_tx_node_ctx_t *ctx = (pktdev_tx_node_ctx_t *)node->ctx;
    uint64_t port_id          = CNE_MAX_ETHPORTS;
    int i;

    /* Find our port id */
    for (i = 0; i < CNE_MAX_ETHPORTS; i++) {
        if (pktdev_tx_main.nodes[i] == node->id) {
            port_id = i;
            break;
        }
    }
    CNE_VERIFY(port_id < CNE_MAX_ETHPORTS);

    /* Update port and queue */
    ctx->port  = port_id;
    ctx->queue = graph->id;

    return 0;
}

struct pktdev_tx_node_main *
pktdev_tx_node_data_get(void)
{
    return &pktdev_tx_main;
}

static struct cne_node_register pktdev_tx_node_base = {
    .process = pktdev_tx_node_process,
    .name    = "pktdev_tx",

    .init = pktdev_tx_node_init,

    .nb_edges = PKTDEV_TX_NEXT_MAX,
    .next_nodes =
        {
            [PKTDEV_TX_NEXT_PKT_DROP] = "pkt_drop",
        },
};

struct cne_node_register *
pktdev_tx_node_get(void)
{
    return &pktdev_tx_node_base;
}

CNE_NODE_REGISTER(pktdev_tx_node_base);
