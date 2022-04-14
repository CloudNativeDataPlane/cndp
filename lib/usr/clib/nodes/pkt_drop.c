/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <cne_graph.h>        // for cne_node_register, CNE_NODE_REGISTER
#include <pktmbuf.h>          // for pktmbuf_free_bulk, pktmbuf_t
#include <stdint.h>           // for uint16_t

#include "cne_common.h"        // for CNE_SET_USED, CNE_PRIORITY_LAST

struct cne_graph;
struct cne_node;

static uint16_t
pkt_drop_process(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    CNE_SET_USED(node);
    CNE_SET_USED(graph);

    pktmbuf_free_bulk((pktmbuf_t **)objs, nb_objs);

    return nb_objs;
}

static int
pkt_drop_node_init(const struct cne_graph *graph, struct cne_node *node)
{
    CNE_SET_USED(graph);
    CNE_SET_USED(node);

    return 0;
}

static struct cne_node_register pkt_drop_node = {
    .process = pkt_drop_process,
    .name    = "pkt_drop",
    .init    = pkt_drop_node_init,
};

CNE_NODE_REGISTER(pkt_drop_node);
