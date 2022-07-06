/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <fnmatch.h>           // for fnmatch
#include <stdbool.h>           // for false, true, bool
#include <cne_common.h>        // for __cne_unused, CNE_MAX, CNE_MIN, __cne_...
#include <bsd/string.h>        // for strlcpy
#include <errno.h>             // for errno, EINVAL, ENOENT, ENOMEM, E2BIG
#include <stdint.h>            // for UINT16_MAX, uint16_t, uint32_t
#include <stdio.h>             // for fprintf, FILE
#include <stdlib.h>            // for NULL, free, calloc, realloc, size_t
#include <string.h>            // for strncmp, strcmp
#include <sys/queue.h>         // for STAILQ_FOREACH, STAILQ_FIRST, STAILQ_I...
#include <cne_spinlock.h>

#include "graph_private.h"           // for graph, graph_node, node, graph::(anony...
#include "cne_graph.h"               // for cne_graph_t, CNE_GRAPH_NAMESIZE, cne_e...
#include "cne_graph_worker.h"        // for cne_node, cne_node::(anonymous), cne_g...
#include "cne_log.h"                 // for CNE_LOG_ERR

static struct graph_head graph_list = STAILQ_HEAD_INITIALIZER(graph_list);
static cne_spinlock_t graph_lock    = CNE_SPINLOCK_INITIALIZER;
static cne_graph_t graph_id;

#define GRAPH_ID_CHECK(id) ID_CHECK(id, graph_id)

/* Private functions */
struct graph_head *
graph_list_head_get(void)
{
    return &graph_list;
}

void
graph_spinlock_lock(void)
{
    cne_spinlock_lock(&graph_lock);
}

void
graph_spinlock_unlock(void)
{
    cne_spinlock_unlock(&graph_lock);
}

static int
graph_node_add(struct graph *graph, struct node *node)
{
    struct graph_node *graph_node;
    size_t sz;

    /* Skip the duplicate nodes */
    STAILQ_FOREACH (graph_node, &graph->node_list, next)
        if (strncmp(node->name, graph_node->node->name, CNE_NODE_NAMESIZE) == 0)
            return 0;

    /* Allocate new graph node object */
    sz         = sizeof(*graph_node) + node->nb_edges * sizeof(struct node *);
    graph_node = calloc(1, sz);

    if (graph_node == NULL)
        SET_ERR_JMP(ENOMEM, free, "Failed to calloc %s object", node->name);

    /* Initialize the graph node */
    graph_node->node = node;

    /* Add to graph node list */
    STAILQ_INSERT_TAIL(&graph->node_list, graph_node, next);

    return 0;
free:
    free(graph_node);
    return -errno;
}

static struct graph_node *
node_to_graph_node(struct graph *graph, struct node *node)
{
    struct graph_node *graph_node;

    STAILQ_FOREACH (graph_node, &graph->node_list, next)
        if (graph_node->node == node)
            return graph_node;

    SET_ERR_JMP(ENODEV, fail, "Found isolated node %s", node->name);

fail:
    return NULL;
}

static int
graph_node_edges_add(struct graph *graph)
{
    struct graph_node *graph_node;
    struct node *adjacency;
    const char *next;
    cne_edge_t i;

    STAILQ_FOREACH (graph_node, &graph->node_list, next) {
        for (i = 0; i < graph_node->node->nb_edges; i++) {
            next      = graph_node->node->next_nodes[i];
            adjacency = node_from_name(next);
            if (adjacency == NULL)
                SET_ERR_JMP(EINVAL, fail, "Node %s not registered", next);
            if (graph_node_add(graph, adjacency))
                goto fail;
        }
    }

    return 0;
fail:
    return -errno;
}

static int
graph_adjacency_list_update(struct graph *graph)
{
    struct graph_node *graph_node, *tmp;
    struct node *adjacency;
    const char *next;
    cne_edge_t i;

    STAILQ_FOREACH (graph_node, &graph->node_list, next) {
        for (i = 0; i < graph_node->node->nb_edges; i++) {
            next      = graph_node->node->next_nodes[i];
            adjacency = node_from_name(next);
            if (adjacency == NULL)
                SET_ERR_JMP(EINVAL, fail, "Node %s not registered", next);
            tmp = node_to_graph_node(graph, adjacency);
            if (tmp == NULL)
                goto fail;
            graph_node->adjacency_list[i] = tmp;
        }
    }

    return 0;
fail:
    return -errno;
}

static int
expand_pattern_to_node(struct graph *graph, const char *pattern)
{
    struct node_head *node_head = node_list_head_get();
    bool found                  = false;
    struct node *node;

    /* Check for pattern match */
    STAILQ_FOREACH (node, node_head, next) {
        if (fnmatch(pattern, node->name, 0) == 0) {
            if (graph_node_add(graph, node))
                goto fail;
            found = true;
        }
    }
    if (found == false)
        SET_ERR_JMP(EFAULT, fail, "Pattern %s node not found", pattern);

    return 0;
fail:
    return -errno;
}

static void
graph_cleanup(struct graph *graph)
{
    struct graph_node *graph_node;

    while (!STAILQ_EMPTY(&graph->node_list)) {
        graph_node = STAILQ_FIRST(&graph->node_list);
        STAILQ_REMOVE_HEAD(&graph->node_list, next);
        free(graph_node);
    }
}

static int
graph_node_init(struct graph *graph)
{
    struct graph_node *graph_node;
    const char *name;
    int rc;

    STAILQ_FOREACH (graph_node, &graph->node_list, next) {
        CNE_DEBUG("Initialize Graph %3d %s\n", graph_node->node->id, graph_node->node->name);
        if (graph_node->node->init) {
            name = graph_node->node->name;
            rc   = graph_node->node->init(graph->graph, graph_node_name_to_ptr(graph->graph, name));
            if (rc)
                SET_ERR_JMP(rc, err, "Node %s init() failed", name);
        }
    }

    return 0;
err:
    return -errno;
}

static void
graph_node_fini(struct graph *graph)
{
    struct graph_node *graph_node;

    STAILQ_FOREACH (graph_node, &graph->node_list, next)
        if (graph_node->node->fini)
            graph_node->node->fini(graph->graph,
                                   graph_node_name_to_ptr(graph->graph, graph_node->node->name));
}

struct cne_graph *
cne_graph_lookup(const char *name)
{
    struct graph *g = NULL;

    STAILQ_FOREACH (g, &graph_list, next) {
        if (!strcmp(g->name, name))
            break;
    }

    return (g) ? g->graph : NULL;
}

cne_graph_t
cne_graph_create(const char *name, const char **patterns)
{
    cne_node_t src_node_count;
    struct graph *graph;
    const char *pattern;

    graph_spinlock_lock();

    /* Check arguments sanity */
    if (patterns == NULL)
        SET_ERR_JMP(EINVAL, fail, "Node list is NULL");

    if (name == NULL)
        SET_ERR_JMP(EINVAL, fail, "Graph name should not be NULL");

    /* Check for existence of duplicate graph */
    STAILQ_FOREACH (graph, &graph_list, next)
        if (strncmp(name, graph->name, CNE_GRAPH_NAMESIZE) == 0)
            SET_ERR_JMP(EEXIST, fail, "Found duplicate graph %s", name);

    /* Create graph object */
    graph = calloc(1, sizeof(*graph));
    if (graph == NULL)
        SET_ERR_JMP(ENOMEM, fail, "Failed to calloc graph object");

    /* Initialize the graph object */
    STAILQ_INIT(&graph->node_list);
    if (strlcpy(graph->name, name, CNE_GRAPH_NAMESIZE) == 0)
        SET_ERR_JMP(E2BIG, free, "Name too big=%s", name);

    /* Expand node pattern and add the nodes to the graph */
    for (uint16_t i = 0; (pattern = patterns[i]) != NULL; i++) {
        if (expand_pattern_to_node(graph, pattern))
            goto graph_cleanup;
    }

    /* Go over all the nodes edges and add them to the graph */
    if (graph_node_edges_add(graph))
        goto graph_cleanup;

    /* Update adjacency list of all nodes in the graph */
    if (graph_adjacency_list_update(graph))
        goto graph_cleanup;

    /* Make sure at least a source node present in the graph */
    src_node_count = graph_src_nodes_count(graph);
    if (src_node_count == 0)
        goto graph_cleanup;

    /* Make sure no node is pointing to source node */
    if (graph_node_has_edge_to_src_node(graph))
        goto graph_cleanup;

    /* Don't allow node has loop to self */
    if (graph_node_has_loop_edge(graph))
        goto graph_cleanup;

    /* Do BFS from src nodes on the graph to find isolated nodes */
    if (graph_has_isolated_node(graph))
        goto graph_cleanup;

    /* Initialize graph object */
    graph->src_node_count = src_node_count;
    graph->node_count     = graph_nodes_count(graph);
    graph->id             = graph_id;

    /* Allocate the Graph fast path memory and populate the data */
    if (graph_fp_mem_create(graph))
        goto graph_cleanup;

    /* Call init() of the all the nodes in the graph */
    if (graph_node_init(graph))
        goto graph_mem_destroy;

    /* All good, Lets add the graph to the list */
    graph_id++;
    STAILQ_INSERT_TAIL(&graph_list, graph, next);

    graph_spinlock_unlock();

    return graph->id;
graph_mem_destroy:
    graph_fp_mem_destroy(graph);
graph_cleanup:
    graph_cleanup(graph);
free:
    free(graph);
fail:
    graph_spinlock_unlock();

    return CNE_GRAPH_ID_INVALID;
}

int
cne_graph_destroy(cne_graph_t id)
{
    struct graph *graph, *tmp;
    int rc = -ENOENT;

    if (id == CNE_GRAPH_ID_INVALID)
        return 0;

    graph_spinlock_lock();

    graph = STAILQ_FIRST(&graph_list);
    while (graph != NULL) {
        tmp = STAILQ_NEXT(graph, next);
        if (graph->id == id) {
            /* Call fini() of the all the nodes in the graph */
            graph_node_fini(graph);
            /* Destroy graph fast path memory */
            rc = graph_fp_mem_destroy(graph);
            if (rc)
                SET_ERR_JMP(rc, done, "Graph %s destroy failed", graph->name);

            graph_cleanup(graph);
            STAILQ_REMOVE(&graph_list, graph, graph, next);
            free(graph);
            graph_id--;
            goto done;
        }
        graph = tmp;
    }

done:
    graph_spinlock_unlock();
    return rc;
}

cne_graph_t
cne_graph_from_name(const char *name)
{
    struct graph *graph;

    STAILQ_FOREACH (graph, &graph_list, next)
        if (strncmp(graph->name, name, CNE_GRAPH_NAMESIZE) == 0)
            return graph->id;

    return CNE_GRAPH_ID_INVALID;
}

char *
cne_graph_id_to_name(cne_graph_t id)
{
    struct graph *graph;

    GRAPH_ID_CHECK(id);
    STAILQ_FOREACH (graph, &graph_list, next)
        if (graph->id == id)
            return graph->name;

fail:
    return NULL;
}

struct cne_node *
cne_graph_node_get(cne_graph_t gid, uint32_t nid)
{
    struct cne_node *node;
    struct graph *graph;
    cne_graph_off_t off;
    cne_node_t count;

    GRAPH_ID_CHECK(gid);
    STAILQ_FOREACH (graph, &graph_list, next)
        if (graph->id == gid) {
            cne_graph_foreach_node(count, off, graph->graph, node)
            {
                if (node->id == nid)
                    return node;
            }
            break;
        }

fail:
    return NULL;
}

struct cne_node *
cne_graph_node_get_by_name(const char *graph_name, const char *node_name)
{
    struct cne_node *node;
    struct graph *graph;
    cne_graph_off_t off;
    cne_node_t count;

    STAILQ_FOREACH (graph, &graph_list, next)
        if (!strncmp(graph->name, graph_name, CNE_GRAPH_NAMESIZE)) {
            cne_graph_foreach_node(count, off, graph->graph, node)
            {
                if (!strncmp(node->name, node_name, CNE_NODE_NAMESIZE))
                    return node;
            }
            break;
        }

    return NULL;
}

struct cne_node *
cne_graph_get_node_by_name(const struct cne_graph *graph, const char *node_name)
{
    struct cne_node *node;
    cne_graph_off_t off;
    cne_node_t count;

    cne_graph_foreach_node(count, off, graph, node)
    {
        if (!strncmp(node->name, node_name, CNE_NODE_NAMESIZE))
            return node;
    }

    return NULL;
}

void __cne_noinline
__cne_node_stream_alloc(struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    uint16_t size = node->size;

    CNE_VERIFY(size != UINT16_MAX);
    /* Allocate double amount of size to avoid immediate realloc */
    size       = CNE_MIN(UINT16_MAX, CNE_MAX(CNE_GRAPH_BURST_SIZE, size * 2));
    node->objs = realloc(node->objs, size * sizeof(void *));
    CNE_VERIFY(node->objs);
    node->size = size;
    node->realloc_count++;
}

void __cne_noinline
__cne_node_stream_alloc_size(struct cne_graph *graph __cne_unused, struct cne_node *node,
                             uint16_t req_size)
{
    uint16_t size = node->size;

    CNE_VERIFY(size != UINT16_MAX);
    /* Allocate double amount of size to avoid immediate realloc */
    size       = CNE_MIN(UINT16_MAX, CNE_MAX(CNE_GRAPH_BURST_SIZE, req_size * 2));
    node->objs = realloc(node->objs, size * sizeof(void *));
    CNE_VERIFY(node->objs);
    node->size = size;
    node->realloc_count++;
}

static int
graph_to_dot(FILE *f, struct graph *graph)
{
    const char *src_edge_color = " [color=blue]\n";
    const char *edge_color     = "\n";
    struct graph_node *graph_node;
    char *node_name;
    cne_edge_t i;
    int rc;

    rc = fprintf(f, "digraph %s {\n\trankdir=LR;\n", graph->name);
    if (rc < 0)
        goto end;

    STAILQ_FOREACH (graph_node, &graph->node_list, next) {
        node_name = graph_node->node->name;
        for (i = 0; i < graph_node->node->nb_edges; i++) {
            rc = fprintf(f, "\t\"%s\"->\"%s\"%s", node_name,
                         graph_node->adjacency_list[i]->node->name,
                         graph_node->node->flags & CNE_NODE_MASK_F ? src_edge_color : edge_color);
            if (rc < 0)
                goto end;
        }
    }
    rc = fprintf(f, "}\n");
    if (rc < 0)
        goto end;

    return 0;
end:
    errno = EBADF;
    return -errno;
}

int
cne_graph_export(const char *name, FILE *f)
{
    struct graph *graph;
    int rc = ENOENT;

    if (!f)
        f = stdout;

    STAILQ_FOREACH (graph, &graph_list, next) {
        if (strncmp(graph->name, name, CNE_GRAPH_NAMESIZE) == 0) {
            rc = graph_to_dot(f, graph);
            goto end;
        }
    }

end:
    return -rc;
}

static int
graph_to_dot_cb(FILE *f, struct graph *graph, cne_graph_export_t *export)
{
    struct graph_node *graph_node;
    char *node_name;
    cne_edge_t nb_edges = 0;

    if (export->header(f, graph->name) < 0)
        goto leave;

    STAILQ_FOREACH (graph_node, &graph->node_list, next) {
        char *adj_names[graph_node->node->nb_edges + 2];

        memset(adj_names, 0, sizeof(adj_names));

        node_name = graph_node->node->name;
        nb_edges  = graph_node->node->nb_edges;

        for (int k = 0; k < nb_edges; k++)
            adj_names[k] = graph_node->adjacency_list[k]->node->name;

        if (export->body(f, node_name, adj_names, nb_edges, graph_node->node->flags) < 0)
            goto leave;
    }

    if (export->trailer(f))
        goto leave;

    return 0;
leave:
    return -EBADF;
}

int
cne_graph_export_cb(const char *name, FILE *f, cne_graph_export_t *exp)
{
    struct graph *graph;

    if (!exp || !name)
        return -EINVAL;

    if (!exp->header || !exp->trailer || !exp->body)
        return -EINVAL;

    if (!f)
        f = stdout;

    STAILQ_FOREACH (graph, &graph_list, next) {
        if (strncmp(graph->name, name, CNE_GRAPH_NAMESIZE) == 0)
            return graph_to_dot_cb(f, graph, exp);
    }

    return -ENOENT;
}

static void
graph_scan_dump(FILE *f, cne_graph_t id, bool all)
{
    struct graph *graph;

    if (!f)
        f = stdout;
    GRAPH_ID_CHECK(id);

    STAILQ_FOREACH (graph, &graph_list, next) {
        if (all == true) {
            graph_dump(f, graph);
        } else if (graph->id == id) {
            graph_dump(f, graph);
            return;
        }
    }

fail:
    return;
}

void
cne_graph_dump(FILE *f, cne_graph_t id)
{
    graph_scan_dump(f, id, false);
}

void
cne_graph_list_dump(FILE *f)
{
    graph_scan_dump(f, 0, true);
}

cne_graph_t
cne_graph_max_count(void)
{
    return graph_id;
}
