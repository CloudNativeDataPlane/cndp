/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <cne_common.h>        // for cne_align32pow2, CNE_ALIGN, CNE_C
#include <errno.h>             // for errno, EINVAL, ENOMEM
#include <stdint.h>            // for int32_t
#include <stdlib.h>            // for calloc, free
#include <string.h>            // for memcpy, NULL, memset, size_t, str
#include <sys/queue.h>         // for STAILQ_FOREACH

#include "graph_private.h"                // for graph, graph_node, node, SET_ERR_JMP
#include "cne_branch_prediction.h"        // for unlikely
#include "cne_graph.h"                    // for cne_graph_off_t, cne_node_t, cne_
#include "cne_graph_worker.h"             // for cne_node, cne_graph, __cne_node_s
#include "cne_log.h"                      // for CNE_LOG_ERR

static size_t
graph_fp_mem_calc_size(struct graph *graph)
{
    struct graph_node *graph_node;
    cne_node_t val;
    size_t sz;

    /* Graph header */
    sz = sizeof(struct cne_graph);
    /* Source nodes list */
    sz += sizeof(cne_graph_off_t) * graph->src_node_count;
    /* Circular buffer for pending streams of size number of nodes */
    val              = cne_align32pow2(graph->node_count * sizeof(cne_graph_off_t));
    sz               = CNE_ALIGN((uint32_t)sz, val);
    graph->cir_start = sz;
    graph->cir_mask  = cne_align32pow2(graph->node_count) - 1;
    sz += val;
    /* Fence */
    sz += sizeof(CNE_GRAPH_FENCE);
    sz                 = CNE_ALIGN(sz, CNE_CACHE_LINE_SIZE);
    graph->nodes_start = sz;
    /* For 0..N node objects with fence */
    STAILQ_FOREACH (graph_node, &graph->node_list, next) {
        sz = CNE_ALIGN(sz, CNE_CACHE_LINE_SIZE);
        sz += sizeof(struct cne_node);
        /* Pointer to next nodes(edges) */
        sz += sizeof(struct cne_node *) * graph_node->node->nb_edges;
    }

    graph->mem_sz = sz;

    return sz;
}

static void
graph_header_popluate(struct graph *_graph)
{
    struct cne_graph *graph = _graph->graph;

    graph->tail        = 0;
    graph->head        = (int32_t)-_graph->src_node_count;
    graph->cir_mask    = _graph->cir_mask;
    graph->nb_nodes    = _graph->node_count;
    graph->cir_start   = CNE_PTR_ADD(graph, _graph->cir_start);
    graph->nodes_start = _graph->nodes_start;
    graph->id          = _graph->id;
    memcpy(graph->name, _graph->name, CNE_GRAPH_NAMESIZE);
    graph->fence = CNE_GRAPH_FENCE;
}

static void
graph_nodes_populate(struct graph *_graph)
{
    cne_graph_off_t off     = _graph->nodes_start;
    struct cne_graph *graph = _graph->graph;
    struct graph_node *graph_node;
    cne_edge_t count, nb_edges;
    const char *parent;
    cne_node_t pid;

    STAILQ_FOREACH (graph_node, &_graph->node_list, next) {
        struct cne_node *node = CNE_PTR_ADD(graph, off);
        memset(node, 0, sizeof(*node));
        node->fence   = CNE_GRAPH_FENCE;
        node->off     = off;
        node->process = graph_node->node->process;
        memcpy(node->name, graph_node->node->name, CNE_GRAPH_NAMESIZE);
        pid = graph_node->node->parent_id;
        if (pid != CNE_NODE_ID_INVALID) { /* Cloned node */
            parent = cne_node_id_to_name(pid);
            if (!parent)
                strncpy(node->parent, "?unknown?", CNE_GRAPH_NAMESIZE);
            else
                memcpy(node->parent, parent, CNE_GRAPH_NAMESIZE);
        }
        node->id        = graph_node->node->id;
        node->parent_id = pid;
        nb_edges        = graph_node->node->nb_edges;
        node->nb_edges  = nb_edges;
        off += sizeof(struct cne_node);
        /* Copy the name in first pass to replace with cne_node* later*/
        for (count = 0; count < nb_edges; count++)
            node->nodes[count] =
                (struct cne_node *)&graph_node->adjacency_list[count]->node->name[0];

        off += sizeof(struct cne_node *) * nb_edges;
        off        = CNE_ALIGN(off, CNE_CACHE_LINE_SIZE);
        node->next = off;
        __cne_node_stream_alloc(graph, node);
    }
}

struct cne_node *
graph_node_id_to_ptr(const struct cne_graph *graph, cne_node_t id)
{
    cne_node_t count;
    cne_graph_off_t off;
    struct cne_node *node;

    cne_graph_foreach_node(count, off, graph, node)
    {
        if (unlikely(node->id == id))
            return node;
    }

    return NULL;
}

struct cne_node *
graph_node_name_to_ptr(const struct cne_graph *graph, const char *name)
{
    cne_node_t count;
    cne_graph_off_t off;
    struct cne_node *node;

    cne_graph_foreach_node(count, off, graph, node)
    {
        if (strncmp(name, node->name, CNE_NODE_NAMESIZE) == 0)
            return node;
    }

    return NULL;
}

static int
graph_node_nexts_populate(struct graph *_graph)
{
    cne_node_t count, val;
    cne_graph_off_t off;
    struct cne_node *node;
    const struct cne_graph *graph = _graph->graph;
    const char *name;

    cne_graph_foreach_node(count, off, graph, node)
    {
        for (val = 0; val < node->nb_edges; val++) {
            name             = (const char *)node->nodes[val];
            node->nodes[val] = graph_node_name_to_ptr(graph, name);
            if (node->nodes[val] == NULL)
                SET_ERR_JMP(EINVAL, fail, "%s not found", name);
        }
    }

    return 0;
fail:
    return -errno;
}

static int
graph_src_nodes_populate(struct graph *_graph)
{
    struct cne_graph *graph = _graph->graph;
    struct graph_node *graph_node;
    struct cne_node *node;
    int32_t head = -1;
    const char *name;

    STAILQ_FOREACH (graph_node, &_graph->node_list, next) {
        if (graph_node->node->flags & CNE_NODE_SOURCE_F) {
            name = graph_node->node->name;
            node = graph_node_name_to_ptr(graph, name);
            if (node == NULL)
                SET_ERR_JMP(EINVAL, fail, "%s not found", name);

            __cne_node_stream_alloc(graph, node);
            graph->cir_start[head--] = node->off;
        }
    }

    return 0;
fail:
    return -errno;
}

static int
graph_fp_mem_populate(struct graph *graph)
{
    int rc;

    graph_header_popluate(graph);
    graph_nodes_populate(graph);
    rc = graph_node_nexts_populate(graph);
    rc |= graph_src_nodes_populate(graph);

    return rc;
}

int
graph_fp_mem_create(struct graph *graph)
{
    size_t sz;

    sz           = graph_fp_mem_calc_size(graph);
    graph->graph = calloc(1, sz);
    if (graph->graph == NULL)
        SET_ERR_JMP(ENOMEM, fail, "Memzone %s reserve failed", graph->name);

    return graph_fp_mem_populate(graph);
fail:
    return -errno;
}

static void
graph_nodes_mem_destroy(struct cne_graph *graph)
{
    cne_node_t count;
    cne_graph_off_t off;
    struct cne_node *node;

    if (graph == NULL)
        return;

    cne_graph_foreach_node(count, off, graph, node) free(node->objs);
}

int
graph_fp_mem_destroy(struct graph *graph)
{
    graph_nodes_mem_destroy(graph->graph);
    return 0;
}
