/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#ifndef _CNE_GRAPH_WORKER_H_
#define _CNE_GRAPH_WORKER_H_

/**
 * @file cne_graph_worker.h
 *
 * This API allows a worker thread to walk over a graph and nodes to create,
 * process, enqueue and move streams of objects to the next nodes.
 */

#include <string.h>
#include <cne_common.h>
#include <cne_cycles.h>
#include <cne_prefetch.h>
#include <cne_branch_prediction.h>
#include <cne_log.h>

#include "cne_graph.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @internal
 *
 * Data structure to hold graph data.
 */
struct cne_graph {
    uint32_t tail;                 /**< Tail of circular buffer. */
    uint32_t head;                 /**< Head of circular buffer. */
    uint32_t cir_mask;             /**< Circular buffer wrap around mask. */
    cne_node_t nb_nodes;           /**< Number of nodes in the graph. */
    cne_graph_off_t *cir_start;    /**< Pointer to circular buffer. */
    cne_graph_off_t nodes_start;   /**< Offset at which node memory starts. */
    cne_graph_t id;                /**< Graph identifier. */
    char name[CNE_GRAPH_NAMESIZE]; /**< Name of the graph. */
    uint64_t fence;                /**< Fence. */
} __cne_cache_aligned;

/**
 * @internal
 *
 * Data structure to hold node data.
 */
struct cne_node {
    /* Slow path area */
    uint64_t fence;         /**< Fence. */
    cne_graph_off_t next;   /**< Index to next node. */
    cne_node_t id;          /**< Node identifier. */
    cne_node_t parent_id;   /**< Parent Node identifier. */
    cne_edge_t nb_edges;    /**< Number of edges from this node. */
    uint32_t realloc_count; /**< Number of times realloced. */

    char parent[CNE_NODE_NAMESIZE]; /**< Parent node name. */
    char name[CNE_NODE_NAMESIZE];   /**< Name of the node. */

    /* Fast path area */
#define CNE_NODE_CTX_SZ 16
    uint8_t ctx[CNE_NODE_CTX_SZ] __cne_cache_aligned; /**< Node Context. */
    uint16_t size;                                    /**< Total number of objects available. */
    uint16_t idx;                                     /**< Number of objects used. */
    cne_graph_off_t off;                              /**< Offset of node in the graph reel. */
    uint64_t total_cycles;                            /**< Cycles spent in this node. */
    uint64_t total_calls;                             /**< Calls done to this node. */
    uint64_t total_objs;                              /**< Objects processed by this node. */
    CNE_STD_C11
    union {
        void **objs; /**< Array of object pointers. */
        uint64_t objs_u64;
    };
    CNE_STD_C11
    union {
        cne_node_process_t process; /**< Process function. */
        uint64_t process_u64;
    };
    struct cne_node *nodes[] __cne_cache_min_aligned; /**< Next nodes. */
} __cne_cache_aligned;

/**
 * @internal
 *
 * Allocate a stream of objects.
 *
 * If stream already exists then re-allocate it to a larger size.
 *
 * @param graph
 *   Pointer to the graph object.
 * @param node
 *   Pointer to the node object.
 */
void __cne_node_stream_alloc(struct cne_graph *graph, struct cne_node *node);

/**
 * @internal
 *
 * Allocate a stream with requested number of objects.
 *
 * If stream already exists then re-allocate it to a larger size.
 *
 * @param graph
 *   Pointer to the graph object.
 * @param node
 *   Pointer to the node object.
 * @param req_size
 *   Number of objects to be allocated.
 */
void __cne_node_stream_alloc_size(struct cne_graph *graph, struct cne_node *node,
                                  uint16_t req_size);

/**
 * Perform graph walk on the circular buffer and invoke the process function
 * of the nodes and collect the stats.
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup function.
 *
 * @see cne_graph_lookup()
 */
static inline void
cne_graph_walk(struct cne_graph *graph)
{
    const cne_graph_off_t *cir_start = graph->cir_start;
    const cne_node_t mask            = graph->cir_mask;
    uint32_t head                    = graph->head;
    struct cne_node *node;
    uint64_t start;
    uint16_t rc;
    void **objs;

    /*
     * Walk on the source node(s) ((cir_start - head) -> cir_start) and then
     * on the pending streams (cir_start -> (cir_start + mask) -> cir_start)
     * in a circular buffer fashion.
     *
     *	+-----+ <= cir_start - head [number of source nodes]
     *	|     |
     *	| ... | <= source nodes
     *	|     |
     *	+-----+ <= cir_start [head = 0] [tail = 0]
     *	|     |
     *	| ... | <= pending streams
     *	|     |
     *	+-----+ <= cir_start + mask
     */
    while (likely(head != graph->tail)) {
        node = CNE_PTR_ADD(graph, cir_start[(int32_t)head++]);
        CNE_ASSERT(node->fence == CNE_GRAPH_FENCE);
        objs = node->objs;
        cne_prefetch0(objs);

        if (cne_graph_has_stats_feature()) {
            start = cne_rdtsc();
            rc    = node->process(graph, node, objs, node->idx);
            node->total_cycles += cne_rdtsc() - start;
            node->total_calls++;
            node->total_objs += rc;
        } else
            node->process(graph, node, objs, node->idx);
        node->idx = 0;
        head      = likely((int32_t)head > 0) ? head & mask : head;
    }
    graph->tail = 0;
}

/* Fast path helper functions */

/**
 * @internal
 *
 * Enqueue a given node to the tail of the graph reel.
 *
 * @param graph
 *   Pointer Graph object.
 * @param node
 *   Pointer to node object to be enqueued.
 */
static __cne_always_inline void
__cne_node_enqueue_tail_update(struct cne_graph *graph, struct cne_node *node)
{
    uint32_t tail;

    tail                     = graph->tail;
    graph->cir_start[tail++] = node->off;
    graph->tail              = tail & graph->cir_mask;
}

/**
 * @internal
 *
 * Enqueue sequence prologue function.
 *
 * Updates the node to tail of graph reel and resizes the number of objects
 * available in the stream as needed.
 *
 * @param graph
 *   Pointer to the graph object.
 * @param node
 *   Pointer to the node object.
 * @param idx
 *   Index at which the object enqueue starts from.
 * @param space
 *   Space required for the object enqueue.
 */
static __cne_always_inline void
__cne_node_enqueue_prologue(struct cne_graph *graph, struct cne_node *node, const uint16_t idx,
                            const uint16_t space)
{
    /* Add to the pending stream list if the node is new */
    if (idx == 0)
        __cne_node_enqueue_tail_update(graph, node);

    if (unlikely(node->size < (idx + space)))
        __cne_node_stream_alloc_size(graph, node, node->size + space);
}

/**
 * @internal
 *
 * Get the node pointer from current node edge id.
 *
 * @param node
 *   Current node pointer.
 * @param next
 *   Edge id of the required node.
 *
 * @return
 *   Pointer to the node denoted by the edge id.
 */
static __cne_always_inline struct cne_node *
__cne_node_next_node_get(struct cne_node *node, cne_edge_t next)
{
    CNE_ASSERT(next < node->nb_edges);
    CNE_ASSERT(node->fence == CNE_GRAPH_FENCE);
    node = node->nodes[next];
    CNE_ASSERT(node->fence == CNE_GRAPH_FENCE);

    return node;
}

/**
 * Add the objs to node for further processing but do not set
 * the node to pending state in the circular buffer. The node
 * should already be a source so it will already be processed.
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param objs
 *   Objs to enqueue.
 * @param nb_objs
 *   Number of objs to enqueue.
 */
static inline void
cne_node_add_objects_to_source(struct cne_graph *graph, struct cne_node *node, void **objs,
                               uint16_t nb_objs)
{
    const uint16_t idx = node->idx;

    if (unlikely(node->size < (idx + nb_objs)))
        __cne_node_stream_alloc(graph, node);

    memcpy(&node->objs[idx], objs, nb_objs * sizeof(void *));
    node->idx = idx + nb_objs;
}
/**
 * Enqueue the objs to a input node type and set the node to pending state in the circular buffer.
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param node
 *   Node to add objects to.
 * @param objs
 *   Objs to enqueue.
 * @param nb_objs
 *   Number of objs to enqueue.
 */
static inline void
cne_node_add_objects_to_input(struct cne_graph *graph, struct cne_node *node, void **objs,
                              uint16_t nb_objs)
{
    const uint16_t idx = node->idx;

    __cne_node_enqueue_prologue(graph, node, idx, nb_objs);

    memcpy(&node->objs[idx], objs, nb_objs * sizeof(void *));
    node->idx = idx + nb_objs;
}

/**
 * Enqueue the objs to next node for further processing and set
 * the next node to pending state in the circular buffer.
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to enqueue objs.
 * @param objs
 *   Objs to enqueue.
 * @param nb_objs
 *   Number of objs to enqueue.
 */
static inline void
cne_node_enqueue(struct cne_graph *graph, struct cne_node *node, cne_edge_t next, void **objs,
                 uint16_t nb_objs)
{
    node               = __cne_node_next_node_get(node, next);
    const uint16_t idx = node->idx;

    __cne_node_enqueue_prologue(graph, node, idx, nb_objs);

    memcpy(&node->objs[idx], objs, nb_objs * sizeof(void *));
    node->idx = idx + nb_objs;
}

/**
 * Enqueue only one obj to next node for further processing and
 * set the next node to pending state in the circular buffer.
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to enqueue objs.
 * @param obj
 *   Obj to enqueue.
 */
static inline void
cne_node_enqueue_x1(struct cne_graph *graph, struct cne_node *node, cne_edge_t next, void *obj)
{
    node         = __cne_node_next_node_get(node, next);
    uint16_t idx = node->idx;

    __cne_node_enqueue_prologue(graph, node, idx, 1);

    node->objs[idx++] = obj;
    node->idx         = idx;
}

/**
 * Enqueue only two objs to next node for further processing and
 * set the next node to pending state in the circular buffer.
 * Same as cne_node_enqueue_x1 but enqueue two objs.
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to enqueue objs.
 * @param obj0
 *   Obj to enqueue.
 * @param obj1
 *   Obj to enqueue.
 */
static inline void
cne_node_enqueue_x2(struct cne_graph *graph, struct cne_node *node, cne_edge_t next, void *obj0,
                    void *obj1)
{
    node         = __cne_node_next_node_get(node, next);
    uint16_t idx = node->idx;

    __cne_node_enqueue_prologue(graph, node, idx, 2);

    node->objs[idx++] = obj0;
    node->objs[idx++] = obj1;
    node->idx         = idx;
}

/**
 * Enqueue only four objs to next node for further processing and
 * set the next node to pending state in the circular buffer.
 * Same as cne_node_enqueue_x1 but enqueue four objs.
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to enqueue objs.
 * @param obj0
 *   1st obj to enqueue.
 * @param obj1
 *   2nd obj to enqueue.
 * @param obj2
 *   3rd obj to enqueue.
 * @param obj3
 *   4th obj to enqueue.
 */
static inline void
cne_node_enqueue_x4(struct cne_graph *graph, struct cne_node *node, cne_edge_t next, void *obj0,
                    void *obj1, void *obj2, void *obj3)
{
    node         = __cne_node_next_node_get(node, next);
    uint16_t idx = node->idx;

    __cne_node_enqueue_prologue(graph, node, idx, 4);

    node->objs[idx++] = obj0;
    node->objs[idx++] = obj1;
    node->objs[idx++] = obj2;
    node->objs[idx++] = obj3;
    node->idx         = idx;
}

/**
 * Enqueue objs to multiple next nodes for further processing and
 * set the next nodes to pending state in the circular buffer.
 * objs[i] will be enqueued to nexts[i].
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param nexts
 *   List of relative next node indices to enqueue objs.
 * @param objs
 *   List of objs to enqueue.
 * @param nb_objs
 *   Number of objs to enqueue.
 */
static inline void
cne_node_enqueue_next(struct cne_graph *graph, struct cne_node *node, cne_edge_t *nexts,
                      void **objs, uint16_t nb_objs)
{
    uint16_t i;

    for (i = 0; i < nb_objs; i++)
        cne_node_enqueue_x1(graph, node, nexts[i], objs[i]);
}

/**
 * Get the stream of next node to enqueue the objs.
 * Once done with the updating objs, needs to call
 * cne_node_next_stream_put to put the next node to pending state.
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to get stream.
 * @param nb_objs
 *   Requested free size of the next stream.
 *
 * @return
 *   Valid next stream on success.
 *
 * @see cne_node_next_stream_put().
 */
static inline void **
cne_node_next_stream_get(struct cne_graph *graph, struct cne_node *node, cne_edge_t next,
                         uint16_t nb_objs)
{
    node                = __cne_node_next_node_get(node, next);
    const uint16_t idx  = node->idx;
    uint16_t free_space = node->size - idx;

    if (unlikely(free_space < nb_objs))
        __cne_node_stream_alloc_size(graph, node, node->size + nb_objs);

    return &node->objs[idx];
}

/**
 * Put the next stream to pending state in the circular buffer
 * for further processing. Should be invoked after cne_node_next_stream_get().
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index.
 * @param idx
 *   Number of objs updated in the stream after getting the stream using
 *   cne_node_next_stream_get.
 *
 * @see cne_node_next_stream_get().
 */
static inline void
cne_node_next_stream_put(struct cne_graph *graph, struct cne_node *node, cne_edge_t next,
                         uint16_t idx)
{
    if (unlikely(!idx))
        return;

    node = __cne_node_next_node_get(node, next);

    if (node->idx == 0)
        __cne_node_enqueue_tail_update(graph, node);

    node->idx += idx;
}

/**
 * Home run scenario, Enqueue all the objs of current node to next
 * node in optimized way by swapping the streams of both nodes.
 * Performs good when next node is not already in pending state.
 * If next node is already in pending state then normal enqueue
 * will be used.
 *
 * @param graph
 *   Graph pointer returned from cne_graph_lookup().
 * @param src
 *   Current node pointer.
 * @param next
 *   Relative next node index.
 */
static inline void
cne_node_next_stream_move(struct cne_graph *graph, struct cne_node *src, cne_edge_t next)
{
    struct cne_node *dst = __cne_node_next_node_get(src, next);

    CNE_DEBUG("Src %-16s', Dst '%-16s' next %d\n", src->name, dst->name, next);

    /* Swap the pointers if dst doesn't have valid objs */
    if (likely(dst->idx == 0)) {
        void **dobjs = dst->objs;
        uint16_t dsz = dst->size;

        dst->objs = src->objs;
        dst->size = src->size;
        src->objs = dobjs;
        src->size = dsz;
        dst->idx  = src->idx;

        __cne_node_enqueue_tail_update(graph, dst);
    } else /* Move the objects from src node to dst node */
        cne_node_enqueue(graph, src, next, src->objs, src->idx);
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_GRAPH_WORKER_H_ */
