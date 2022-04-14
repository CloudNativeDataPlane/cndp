/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <cne_graph.h>        // for cne_node_register, CNE_NODE_REGISTER
#include <stdint.h>           // for uint16_t

#include "cne_common.h"        // for CNE_SET_USED, CNE_PRIORITY_LAST

struct cne_graph;
struct cne_node;

static uint16_t
null(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    CNE_SET_USED(node);
    CNE_SET_USED(objs);
    CNE_SET_USED(graph);

    return nb_objs;
}

static struct cne_node_register null_node = {
    .name    = "null",
    .process = null,
};

CNE_NODE_REGISTER(null_node);
