/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <inttypes.h>         // for PRIu32, PRId32, PRIx32, PRId64, PRIx64
#include <stdbool.h>          // for bool
#include <stdint.h>           // for int32_t
#include <stdio.h>            // for FILE, stdout
#include <sys/queue.h>        // for STAILQ_FOREACH

#include "graph_private.h"           // for graph, node, graph_node, graph_dump
#include "cne_graph.h"               // for cne_edge_t, CNE_NODE_INPUT_F, CNE_NODE...
#include "cne_graph_worker.h"        // for cne_node, cne_graph, cne_node::(anonym...
#include "cne_stdio.h"               // for cne_fprintf

void
graph_dump(FILE *f, struct graph *g)
{
    struct graph_node *graph_node;
    cne_edge_t i = 0;

    if (!g)
        return;
    if (!f)
        f = stdout;

    cne_fprintf(f, "graph <%s>\n", g->name);
    cne_fprintf(f, "  id=%" PRIu32 "\n", g->id);
    cne_fprintf(f, "  cir_start=%" PRIu32 "\n", g->cir_start);
    cne_fprintf(f, "  cir_mask=%" PRIu32 "\n", g->cir_mask);
    cne_fprintf(f, "  addr=%p\n", g);
    cne_fprintf(f, "  graph=%p\n", g->graph);
    cne_fprintf(f, "  mem_sz=%zu\n", g->mem_sz);
    cne_fprintf(f, "  node_count=%" PRIu32 "\n", g->node_count);
    cne_fprintf(f, "  src_node_count=%" PRIu32 "\n", g->src_node_count);

    STAILQ_FOREACH (graph_node, &g->node_list, next)
        cne_fprintf(f, "     node[%d] <%s>\n", i++, graph_node->node->name);
}

void
node_dump(FILE *f, struct node *n, bool hdr)
{
    cne_edge_t i;

    if (!n)
        return;
    if (!f)
        f = stdout;

    if (hdr)
        cne_fprintf(f, "[magenta]%-18s %4s %8s %s[]\n", "Node Name", "id", "Flags", "Edges");

    cne_fprintf(f, "[orange]%-18s[] ", n->name);
    cne_fprintf(f, "[cyan]%4d[] ", n->id);
    cne_fprintf(f, "[cyan]%8s[] ",
                (n->flags & CNE_NODE_SOURCE_F)  ? "Source"
                : (n->flags & CNE_NODE_INPUT_F) ? "Input"
                                                : "");
    if (n->nb_edges)
        cne_fprintf(f, "[cyan]%2d[]: ", n->nb_edges);

    for (i = 0; i < n->nb_edges; i++)
        cne_fprintf(f, "[orange]%s[] ", n->next_nodes[i]);
    cne_fprintf(f, "\n");
}

void
cne_graph_obj_dump(FILE *f, struct cne_graph *g, bool all)
{
    cne_node_t count;
    cne_graph_off_t off;
    struct cne_node *n;
    cne_edge_t i;

    if (!g)
        return;
    if (!f)
        f = stdout;

    cne_fprintf(f, "graph <%s> @ %p\n", g->name, g);
    cne_fprintf(f, "  id=%" PRIu32 "\n", g->id);
    cne_fprintf(f, "  head=%" PRId32 "\n", (int32_t)g->head);
    cne_fprintf(f, "  tail=%" PRId32 "\n", (int32_t)g->tail);
    cne_fprintf(f, "  cir_mask=0x%" PRIx32 "\n", g->cir_mask);
    cne_fprintf(f, "  nb_nodes=%" PRId32 "\n", g->nb_nodes);
    cne_fprintf(f, "  fence=0x%" PRIx64 "\n", g->fence);
    cne_fprintf(f, "  nodes_start=0x%" PRIx32 "\n", g->nodes_start);
    cne_fprintf(f, "  cir_start=%p\n", g->cir_start);

    cne_graph_foreach_node(count, off, g, n)
    {
        if (!all && n->idx == 0)
            continue;
        cne_fprintf(f, "     node[%d] <%s>\n", count, n->name);
        cne_fprintf(f, "       fence=0x%" PRIx64 "\n", n->fence);
        cne_fprintf(f, "       objs=%p\n", n->objs);
        cne_fprintf(f, "       process=%p\n", n->process);
        cne_fprintf(f, "       id=0x%" PRIx32 "\n", n->id);
        cne_fprintf(f, "       offset=0x%" PRIx32 "\n", n->off);
        cne_fprintf(f, "       nb_edges=%" PRId32 "\n", n->nb_edges);
        cne_fprintf(f, "       realloc_count=%d\n", n->realloc_count);
        cne_fprintf(f, "       size=%d\n", n->size);
        cne_fprintf(f, "       idx=%d\n", n->idx);
        cne_fprintf(f, "       total_objs=%" PRId64 "\n", n->total_objs);
        cne_fprintf(f, "       total_calls=%" PRId64 "\n", n->total_calls);
        for (i = 0; i < n->nb_edges; i++)
            cne_fprintf(f, "          edge[%d] <%s>\n", i, n->nodes[i]->name);
    }
}
