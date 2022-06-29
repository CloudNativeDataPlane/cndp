/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#ifndef _CNE_GRAPH_H_
#define _CNE_GRAPH_H_

/**
 * @file cne_graph.h
 *
 * Graph architecture abstracts the data processing functions as
 * "node" and "link" them together to create a complex "graph" to enable
 * reusable/modular data processing functions.
 *
 * This API enables graph framework operations such as create, lookup,
 * dump and destroy on graph and node operations such as clone,
 * edge update, and edge shrink, etc. The API also allows creation of the stats
 * cluster to monitor per graph and per node stats.
 */

#include <stdbool.h>
#include <stdio.h>

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNE_GRAPH_BURST_SIZE  256
#define CNE_GRAPH_NAMESIZE    64                    /**< Max length of graph name. */
#define CNE_NODE_NAMESIZE     64                    /**< Max length of node name. */
#define CNE_GRAPH_OFF_INVALID UINT32_MAX            /**< Invalid graph offset. */
#define CNE_NODE_ID_INVALID   UINT32_MAX            /**< Invalid node id. */
#define CNE_EDGE_ID_INVALID   UINT16_MAX            /**< Invalid edge id. */
#define CNE_GRAPH_ID_INVALID  UINT16_MAX            /**< Invalid graph id. */
#define CNE_GRAPH_FENCE       0xdeadbeef12345678ULL /**< Graph fence data. */

typedef uint32_t cne_graph_off_t; /**< Graph offset type. */
typedef uint32_t cne_node_t;      /**< Node id type. */
typedef uint16_t cne_edge_t;      /**< Edge id type. */
typedef uint16_t cne_graph_t;     /**< Graph id type. */

/** Burst size in terms of log2 */
#if CNE_GRAPH_BURST_SIZE == 1
#define CNE_GRAPH_BURST_SIZE_LOG2 0 /**< Object burst size of 1. */
#elif CNE_GRAPH_BURST_SIZE == 2
#define CNE_GRAPH_BURST_SIZE_LOG2 1 /**< Object burst size of 2. */
#elif CNE_GRAPH_BURST_SIZE == 4
#define CNE_GRAPH_BURST_SIZE_LOG2 2 /**< Object burst size of 4. */
#elif CNE_GRAPH_BURST_SIZE == 8
#define CNE_GRAPH_BURST_SIZE_LOG2 3 /**< Object burst size of 8. */
#elif CNE_GRAPH_BURST_SIZE == 16
#define CNE_GRAPH_BURST_SIZE_LOG2 4 /**< Object burst size of 16. */
#elif CNE_GRAPH_BURST_SIZE == 32
#define CNE_GRAPH_BURST_SIZE_LOG2 5 /**< Object burst size of 32. */
#elif CNE_GRAPH_BURST_SIZE == 64
#define CNE_GRAPH_BURST_SIZE_LOG2 6 /**< Object burst size of 64. */
#elif CNE_GRAPH_BURST_SIZE == 128
#define CNE_GRAPH_BURST_SIZE_LOG2 7 /**< Object burst size of 128. */
#elif CNE_GRAPH_BURST_SIZE == 256
#define CNE_GRAPH_BURST_SIZE_LOG2 8 /**< Object burst size of 256. */
#else
#error "Unsupported burst size"
#endif

/* Forward declaration */
struct cne_node;                     /**< Node object */
struct cne_graph;                    /**< Graph object */
struct cne_graph_cluster_stats;      /**< Stats for Cluster of graphs */
struct cne_graph_cluster_node_stats; /**< Node stats within cluster of graphs */

/**
 * Node process function.
 *
 * The function invoked when the worker thread walks on nodes using
 * cne_graph_walk().
 *
 * @param graph
 *   Pointer to the graph object.
 * @param node
 *   Pointer to the node object.
 * @param objs
 *   Pointer to an array of objects to be processed.
 * @param nb_objs
 *   Number of objects in the array.
 *
 * @return
 *   Number of objects processed.
 *
 * @see cne_graph_walk()
 *
 */
typedef uint16_t (*cne_node_process_t)(struct cne_graph *graph, struct cne_node *node, void **objs,
                                       uint16_t nb_objs);

/**
 * Node initialization function.
 *
 * The function invoked when the user creates the graph using cne_graph_create()
 *
 * @param graph
 *   Pointer to the graph object.
 * @param node
 *   Pointer to the node object.
 *
 * @return
 *   - 0: Success.
 *   -<0: Failure.
 *
 * @see cne_graph_create()
 */
typedef int (*cne_node_init_t)(const struct cne_graph *graph, struct cne_node *node);

/**
 * Node finalization function.
 *
 * The function invoked when the user destroys the graph using
 * cne_graph_destroy().
 *
 * @param graph
 *   Pointer to the graph object.
 * @param node
 *   Pointer to the node object.
 *
 * @see cne_graph_destroy()
 */
typedef void (*cne_node_fini_t)(const struct cne_graph *graph, struct cne_node *node);

/**
 * Graph cluster stats callback.
 *
 * @param is_first
 *   Flag to denote that stats are of the first node.
 * @param is_last
 *   Flag to denote that stats are of the last node.
 * @param stats
 *   Node cluster stats data.
 *
 * @return
 *   - 0: Success.
 *   -<0: Failure.
 */
typedef int (*cne_graph_cluster_stats_cb_t)(bool is_first, bool is_last,
                                            const struct cne_graph_cluster_node_stats *stats);

/**
 * Structure to hold configuration parameters for graph cluster stats create.
 *
 * @see cne_graph_cluster_stats_create()
 */
struct cne_graph_cluster_stats_param {
    /**< Stats print callback function. NULL value allowed, in that case,
     *   default print stat function used.
     */
    cne_graph_cluster_stats_cb_t fn;

    uint16_t nb_graph_patterns;  /**< Number of graph patterns. */
    const char **graph_patterns; /**< Array of graph patterns based on shell pattern. */
};

/**
 * Node cluster stats data structure.
 *
 * @see struct cne_graph_cluster_stats_param
 */
struct cne_graph_cluster_node_stats {
    uint64_t ts;     /**< Current timestamp. */
    uint64_t calls;  /**< Current number of calls made. */
    uint64_t objs;   /**< Current number of objs processed. */
    uint64_t cycles; /**< Current number of cycles. */

    uint64_t prev_ts;     /**< Previous call timestamp. */
    uint64_t prev_calls;  /**< Previous number of calls. */
    uint64_t prev_objs;   /**< Previous number of processed objs. */
    uint64_t prev_cycles; /**< Previous number of cycles. */

    uint64_t realloc_count; /**< Realloc count. */

    cne_node_t id;                /**< Node identifier of stats. */
    uint64_t hz;                  /**< Cycles per seconds. */
    char name[CNE_NODE_NAMESIZE]; /**< Name of the node. */
} __cne_cache_aligned;

/**
 * Create Graph.
 *
 * Create memory reel, detect loops and find isolated nodes.
 *
 * @param name
 *   Unique name for this graph.
 * @param patterns
 *   Graph node patterns, must be NULL terminated.
 *
 * @return
 *   Unique graph id on success, CNE_GRAPH_ID_INVALID otherwise.
 */
CNDP_API cne_graph_t cne_graph_create(const char *name, const char **patterns);

/**
 * Destroy Graph.
 *
 * Free Graph memory reel.
 *
 * @param id
 *   id of the graph to destroy.
 *
 * @return
 *   0 on success, error otherwise.
 */
CNDP_API int cne_graph_destroy(cne_graph_t id);

/**
 * Get graph id from graph name.
 *
 * @param name
 *   Name of the graph to get id.
 *
 * @return
 *   Graph id on success, CNE_GRAPH_ID_INVALID otherwise.
 */
CNDP_API cne_graph_t cne_graph_from_name(const char *name);

/**
 * Get graph name from graph id.
 *
 * @param id
 *   id of the graph to get name.
 *
 * @return
 *   Graph name on success, NULL otherwise.
 */
CNDP_API char *cne_graph_id_to_name(cne_graph_t id);

/**
 * Export the graph as graphviz dot file
 *
 * @param name
 *   Name of the graph to export.
 * @param f
 *   File pointer to export the graph.
 *
 * @return
 *   0 on success, error otherwise.
 */
CNDP_API int cne_graph_export(const char *name, FILE *f);

/**< Set of functions to be called to help format the graph export data */
typedef struct {
    int (*header)(FILE *f, const char *name); /**< Header function to call if set */
    int (*body)(FILE *f, char *node_name, char **adj_names, cne_edge_t nb_edges,
                int src);    /**< Called for each node entry in the graph */
    int (*trailer)(FILE *f); /**< Called at the end of all of the graph nodes */
} cne_graph_export_t;

/**
 * Export the graph information to a file and use the export functions to help build the data.
 *
 * @param name
 *   The name of the graph to export.
 * @param f
 *   The file pointer to write the exported data, can be NULL and will use stdout.
 * @param exp
 *   The export function structure pointer.
 * @return
 *   0 on success or negative errno number on failure.
 *
 *   EBADF  - exp function return an error.
 *   EINVAL - exp function or name is NULL.
 *   ENOENT - Did not find the graph named.
 */
CNDP_API int cne_graph_export_cb(const char *name, FILE *f, cne_graph_export_t *exp);

/**
 * Get maximum number of graph available.
 *
 * @return
 *   Maximum graph count.
 */
CNDP_API cne_graph_t cne_graph_max_count(void);

/**
 * Get graph object from its name.
 *
 * Typical usage of this API is to get graph objects in the worker thread and
 * call cne_graph_walk() in a loop.
 *
 * @param name
 *   Name of the graph.
 *
 * @return
 *   Graph pointer on success, NULL otherwise.
 *
 * @see cne_graph_walk()
 */
CNDP_API struct cne_graph *cne_graph_lookup(const char *name);

/**
 * Dump the graph information to file.
 *
 * @param f
 *   File pointer to dump graph info.
 * @param id
 *   Graph id to get graph info.
 */
CNDP_API void cne_graph_dump(FILE *f, cne_graph_t id);

/**
 * Dump all graph information to file
 *
 * @param f
 *   File pointer to dump graph info.
 */
CNDP_API void cne_graph_list_dump(FILE *f);

/**
 * Dump graph information along with node info to file
 *
 * @param f
 *   File pointer to dump graph info.
 * @param graph
 *   Graph pointer to get graph info.
 * @param all
 *   true to dump nodes in the graph.
 */
CNDP_API void cne_graph_obj_dump(FILE *f, struct cne_graph *graph, bool all);

/** Macro to browse cne_node object after the graph creation */
#define cne_graph_foreach_node(count, off, graph, node)                       \
    for (count = 0, off = graph->nodes_start, node = CNE_PTR_ADD(graph, off); \
         count < graph->nb_nodes; off = node->next, node = CNE_PTR_ADD(graph, off), count++)

/**
 * Get node object with in graph from id.
 *
 * @param graph_id
 *   Graph id to get node pointer from.
 * @param node_id
 *   Node id to get node pointer.
 *
 * @return
 *   Node pointer on success, NULL otherwise.
 */
CNDP_API struct cne_node *cne_graph_node_get(cne_graph_t graph_id, cne_node_t node_id);

/**
 * Get node pointer with in graph from name.
 *
 * @param graph
 *   Graph name to get node pointer from.
 * @param name
 *   Node name to get the node pointer.
 *
 * @return
 *   Node pointer on success, NULL otherwise.
 */
CNDP_API struct cne_node *cne_graph_node_get_by_name(const char *graph, const char *name);

/**
 * Get node pointer within graph.
 *
 * @param graph
 *   Pointer to the graph to locate the node.
 * @param node_name
 *   Node name to get the node pointer.
 *
 * @return
 *   Node pointer on success, NULL otherwise.
 */
CNDP_API struct cne_node *cne_graph_get_node_by_name(const struct cne_graph *graph,
                                                     const char *node_name);

/**
 * Create graph stats cluster to aggregate runtime node stats.
 *
 * @param prm
 *   Parameters including file pointer to dump stats,
 *   Graph pattern to create cluster and callback function.
 *
 * @return
 *   Valid pointer on success, NULL otherwise.
 */
CNDP_API struct cne_graph_cluster_stats *
cne_graph_cluster_stats_create(const struct cne_graph_cluster_stats_param *prm);

/**
 * Destroy cluster stats.
 *
 * @param stat
 *   Valid cluster pointer to destroy.
 */
CNDP_API void cne_graph_cluster_stats_destroy(struct cne_graph_cluster_stats *stat);

/**
 * Get stats to application.
 *
 * @param[out] stat
 *   Cluster status.
 * @param skip_cb
 *   true to skip callback function invocation.
 */
CNDP_API void cne_graph_cluster_stats_get(struct cne_graph_cluster_stats *stat, bool skip_cb);

/**
 * Reset cluster stats to zero.
 *
 * @param stat
 *   Valid cluster stats pointer.
 */
CNDP_API void cne_graph_cluster_stats_reset(struct cne_graph_cluster_stats *stat);

/**
 * Return the number of nodes in cluster.
 *
 * @param stat
 *   Valid cluster stats pointer.
 * @return
 *   Number of nodes in cluster or -1 if stat pointer is NULL.
 */
CNDP_API int cne_graph_stats_node_count(struct cne_graph_cluster_stats *stat);

/**
 * Structure defines the node registration parameters.
 *
 * @see __cne_node_register(), CNE_NODE_REGISTER()
 */
struct cne_node_register {
    char name[CNE_NODE_NAMESIZE]; /**< Name of the node. */
    uint64_t flags;               /**< Node configuration flag. */
    cne_node_process_t process;   /**< Node process function. */
    cne_node_init_t init;         /**< Node init function. */
    cne_node_fini_t fini;         /**< Node fini function. */
    cne_node_t id;                /**< Node Identifier. */
    cne_node_t parent_id;         /**< Identifier of parent node. */
    cne_edge_t nb_edges;          /**< Number of edges from this node. */
    const char *next_nodes[];     /**< Names of next nodes. */
};

/** Flag bits for cne_node_register.flags field */
#define CNE_NODE_SOURCE_F (1ULL << 0) /**< Node type is source. */
#define CNE_NODE_INPUT_F  (1ULL << 1) /**< Node type is a input node not a source node*/
#define CNE_NODE_MASK_F   (CNE_NODE_SOURCE_F | CNE_NODE_INPUT_F) /**< Flag Mask value */

/**
 * Register new packet processing node. Nodes can be registered
 * dynamically via this call or statically via the CNE_NODE_REGISTER
 * macro.
 *
 * @param node
 *   Valid node pointer with name, process function and next_nodes.
 *
 * @return
 *   Valid node id on success, CNE_NODE_ID_INVALID otherwise.
 *
 * @see CNE_NODE_REGISTER()
 */
cne_node_t __cne_node_register(const struct cne_node_register *node);

/**
 * Register a static node.
 *
 * The static node is registered through the constructor scheme, thereby, it can
 * be used in a multi-process scenario.
 *
 * @param node
 *   Valid node pointer with name, process function, and next_nodes.
 */
#define CNE_NODE_REGISTER(node)                      \
    CNE_INIT(cne_node_register_##node)               \
    {                                                \
        node.parent_id = CNE_NODE_ID_INVALID;        \
        node.id        = __cne_node_register(&node); \
    }

/**
 * Clone a node from static node(node created from CNE_NODE_REGISTER).
 *
 * @param id
 *   Static node id to clone from.
 * @param name
 *   Name of the new node. The library prepends the parent node name to the
 *   user-specified name. The final node name will be,
 *   "parent node name" + "-" + name.
 *
 * @return
 *   Valid node id on success, CNE_NODE_ID_INVALID otherwise.
 */
CNDP_API cne_node_t cne_node_clone(cne_node_t id, const char *name);

/**
 * Get node id from node name.
 *
 * @param name
 *   Valid node name. In the case of the cloned node, the name will be
 *   "parent node name" + "-" + name.
 *
 * @return
 *   Valid node id on success, CNE_NODE_ID_INVALID otherwise.
 */
CNDP_API cne_node_t cne_node_from_name(const char *name);

/**
 * Get node name from node id.
 *
 * @param id
 *   Valid node id.
 *
 * @return
 *   Valid node name on success, NULL otherwise.
 */
CNDP_API char *cne_node_id_to_name(cne_node_t id);

/**
 * Get the number of edges(next-nodes) for a node from node id.
 *
 * @param id
 *   Valid node id.
 *
 * @return
 *   Valid edge count on success, CNE_EDGE_ID_INVALID otherwise.
 */
CNDP_API cne_edge_t cne_node_edge_count(cne_node_t id);

/**
 * Update the edges for a node from node id.
 *
 * @param id
 *   Valid node id.
 * @param from
 *   Index to update the edges from. CNE_EDGE_ID_INVALID is valid,
 *   in that case, it will be added to the end of the list.
 * @param next_nodes
 *   Name of the edges to update.
 * @param nb_edges
 *   Number of edges to update.
 *
 * @return
 *   Valid edge count on success, 0 otherwise.
 */
CNDP_API cne_edge_t cne_node_edge_update(cne_node_t id, cne_edge_t from, const char **next_nodes,
                                         uint16_t nb_edges);

/**
 * Shrink the edges to a given size.
 *
 * @param id
 *   Valid node id.
 * @param size
 *   New size to shrink the edges.
 *
 * @return
 *   New size on success, CNE_EDGE_ID_INVALID otherwise.
 */
CNDP_API cne_edge_t cne_node_edge_shrink(cne_node_t id, cne_edge_t size);

/**
 * Get the edge names from a given node.
 *
 * @param id
 *   Valid node id.
 * @param[out] next_nodes
 *   Buffer to copy the edge names. The NULL value is allowed in that case,
 *   the function returns the size of the array that needs to be allocated.
 *
 * @return
 *   When next_nodes == NULL, it returns the size of the array else
 *   number of item copied.
 */
CNDP_API cne_node_t cne_node_edge_get(cne_node_t id, char *next_nodes[]);

/**
 * Get maximum nodes available.
 *
 * @return
 *   Maximum nodes count.
 */
CNDP_API cne_node_t cne_node_max_count(void);

/**
 * Dump node info to file.
 *
 * @param f
 *   File pointer to dump the node info.
 * @param id
 *   Node id to get the info.
 */
CNDP_API void cne_node_dump(FILE *f, cne_node_t id);

/**
 * Dump all node info to file.
 *
 * @param f
 *   File pointer to dump the node info.
 */
CNDP_API void cne_node_list_dump(FILE *f);

/**
 * Test the validity of node id.
 *
 * @param id
 *   Node id to check.
 *
 * @return
 *   1 if valid id, 0 otherwise.
 */
static __cne_always_inline int
cne_node_is_invalid(cne_node_t id)
{
    return (id == CNE_NODE_ID_INVALID);
}

/**
 * Test the validity of edge id.
 *
 * @param id
 *   Edge node id to check.
 *
 * @return
 *   1 if valid id, 0 otherwise.
 */
static __cne_always_inline int
cne_edge_is_invalid(cne_edge_t id)
{
    return (id == CNE_EDGE_ID_INVALID);
}

/**
 * Test the validity of graph id.
 *
 * @param id
 *   Graph id to check.
 *
 * @return
 *   1 if valid id, 0 otherwise.
 */
static __cne_always_inline int
cne_graph_is_invalid(cne_graph_t id)
{
    return (id == CNE_GRAPH_ID_INVALID);
}

/**
 * Test stats feature support.
 *
 * @return
 *   1 if stats enabled, 0 otherwise.
 */
static __cne_always_inline int
cne_graph_has_stats_feature(void)
{
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_GRAPH_H_ */
