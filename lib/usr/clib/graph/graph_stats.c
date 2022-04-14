/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <fnmatch.h>           // for fnmatch
#include <stdbool.h>           // for bool, false, true
#include <cne_common.h>        // for CNE_PTR_ADD, CNE_CACHE_LINE_SIZE
#include <cne_system.h>        // for cne_get_timer_hz
#include <errno.h>             // for ENOMEM, EINVAL, errno, ENOENT
#include <inttypes.h>          // for PRIu64
#include <stdint.h>            // for uint64_t, uint32_t
#include <stdio.h>             // for NULL, size_t
#include <stdlib.h>            // for free, realloc, aligned_alloc
#include <string.h>            // for memset, memcpy
#include <sys/queue.h>         // for STAILQ_FOREACH

#include "graph_private.h"                // for SET_ERR_JMP, graph_node, graph_no...
#include "cne_branch_prediction.h"        // for unlikely
#include "cne_cycles.h"                   // for cne_rdtsc
#include "cne_graph.h"                    // for cne_graph_cluster_node_stats, cne...
#include "cne_graph_worker.h"             // for cne_node, cne_graph
#include "cne_log.h"                      // for CNE_LOG_ERR
#include "cne_stdio.h"                    // for cne_printf

/* Capture all graphs of cluster */
struct cluster {
    cne_graph_t nb_graphs;
    cne_graph_t size;

    struct graph **graphs;
};

/* Capture same node ID across cluster  */
struct cluster_node {
    struct cne_graph_cluster_node_stats stat;
    cne_node_t nb_nodes;

    struct cne_node *nodes[];
};

struct cne_graph_cluster_stats {
    /* Header */
    cne_graph_cluster_stats_cb_t fn;
    uint32_t cluster_node_size; /* Size of struct cluster_node */
    cne_node_t max_nodes;
    void *cookie;
    size_t sz;

    struct cluster_node clusters[];
} __cne_cache_aligned;

#define border()                                                      \
    cne_printf("[yellow]+------------------+---------------+--------" \
               "-------+--------+--------+----------+------------+[]\n")

static inline void
print_banner(void)
{
    border();
    cne_printf("[yellow]|[green]%-18s[yellow]|[green]%15s[yellow]|[green]%15s[yellow]|[green]%"
               "8s[yellow]|[green]%8s[yellow]|[green]%10s[yellow]|[green]%12s[yellow]|[]\n",
               "Node", "Calls", "Objects", "Realloc", "Objs/c", "KObjs/c", "Cycles/c");
    border();
}

static inline void
print_node(const struct cne_graph_cluster_node_stats *stat)
{
    double objs_per_call, objs_per_sec, cycles_per_call, ts_per_hz;
    const uint64_t prev_calls = stat->prev_calls;
    const uint64_t prev_objs  = stat->prev_objs;
    const uint64_t cycles     = stat->cycles;
    const uint64_t calls      = stat->calls;
    const uint64_t objs       = stat->objs;
    uint64_t call_delta;

    call_delta      = calls - prev_calls;
    objs_per_call   = call_delta ? (double)((objs - prev_objs) / call_delta) : 0;
    cycles_per_call = call_delta ? (double)((cycles - stat->prev_cycles) / call_delta) : 0;
    ts_per_hz       = (double)((stat->ts - stat->prev_ts) / stat->hz);
    objs_per_sec    = ts_per_hz ? (objs - prev_objs) / ts_per_hz : 0;
    objs_per_sec /= 1000;

    cne_printf("[yellow]|[magenta]%-18s[yellow]|[cyan]%'15" PRIu64 "[yellow]|[cyan]%'15" PRIu64
               "[yellow]|[cyan]%'8" PRIu64
               "[yellow]|[cyan]%'8.1f[yellow]|[orange]%'10.1f[yellow]|[orange]%'12.1f[yellow]|[]\n",
               stat->name, calls, objs, stat->realloc_count, objs_per_call, objs_per_sec,
               cycles_per_call);
}

static int
graph_cluster_stats_cb(bool is_first, bool is_last, const struct cne_graph_cluster_node_stats *stat)
{
    if (unlikely(is_first))
        print_banner();
    print_node(stat);
    if (unlikely(is_last))
        border();

    return 0;
};

static struct cne_graph_cluster_stats *
stats_mem_init(struct cluster *cluster, const struct cne_graph_cluster_stats_param *prm)
{
    size_t sz                             = sizeof(struct cne_graph_cluster_stats);
    struct cne_graph_cluster_stats *stats = NULL;
    cne_graph_cluster_stats_cb_t fn;
    uint32_t cluster_node_size;

    /* Fix up callback */
    fn = prm->fn;
    if (fn == NULL)
        fn = graph_cluster_stats_cb;

    cluster_node_size = sizeof(struct cluster_node);
    /* For a given cluster, max nodes will be the max number of graphs */
    cluster_node_size += cluster->nb_graphs * sizeof(struct cne_node *);
    cluster_node_size = CNE_ALIGN(cluster_node_size, CNE_CACHE_LINE_SIZE);

    stats = realloc(NULL, sz);
    if (stats) {
        memset(stats, 0, sz);
        stats->fn                = fn;
        stats->cluster_node_size = cluster_node_size;
        stats->max_nodes         = 0;
        stats->sz                = sz;
    }

    return stats;
}

static int
stats_mem_populate(struct cne_graph_cluster_stats **stats_in, struct cne_graph *graph,
                   struct graph_node *graph_node)
{
    struct cne_graph_cluster_stats *stats = *stats_in;
    cne_node_t id                         = graph_node->node->id;
    struct cluster_node *cluster;
    struct cne_node *node;
    cne_node_t count;

    cluster = stats->clusters;

    /* Iterate over cluster node array to find node ID match */
    for (count = 0; count < stats->max_nodes; count++) {
        /* Found an existing node in the reel */
        if (cluster->stat.id == id) {
            node = graph_node_id_to_ptr(graph, id);
            if (node == NULL)
                SET_ERR_JMP(ENOENT, err, "Failed to find node %s in graph %s",
                            graph_node->node->name, graph->name);

            cluster->nodes[cluster->nb_nodes++] = node;
            return 0;
        }
        cluster = CNE_PTR_ADD(cluster, stats->cluster_node_size);
    }

    /* Allocate space for new node in the reel */
    stats = realloc(stats, stats->sz + stats->cluster_node_size);
    if (stats == NULL)
        SET_ERR_JMP(ENOMEM, err, "Realloc failed");
    *stats_in = stats;

    /* Clear the new struct cluster_node area */
    cluster = CNE_PTR_ADD(stats, stats->sz), memset(cluster, 0, stats->cluster_node_size);
    memcpy(cluster->stat.name, graph_node->node->name, CNE_NODE_NAMESIZE);
    cluster->stat.id = graph_node->node->id;
    cluster->stat.hz = cne_get_timer_hz();
    node             = graph_node_id_to_ptr(graph, id);
    if (node == NULL)
        SET_ERR_JMP(ENOENT, err, "Failed to find node %s in graph %s", graph_node->node->name,
                    graph->name);
    cluster->nodes[cluster->nb_nodes++] = node;

    stats->sz += stats->cluster_node_size;
    stats->max_nodes++;

    return 0;
err:
    return -errno;
}

static void
stats_mem_fini(struct cne_graph_cluster_stats *stats)
{
    free(stats);
}

static void
cluster_init(struct cluster *cluster)
{
    memset(cluster, 0, sizeof(*cluster));
}

static int
cluster_add(struct cluster *cluster, struct graph *graph)
{
    cne_graph_t count;
    size_t sz;

    /* Skip the if graph is already added to cluster */
    for (count = 0; count < cluster->nb_graphs; count++)
        if (cluster->graphs[count] == graph)
            return 0;

    /* Expand the cluster if required to store graph objects */
    if (cluster->nb_graphs + 1 > cluster->size) {
        cluster->size   = CNE_MAX(1, cluster->size * 2);
        sz              = sizeof(struct graph *) * cluster->size;
        cluster->graphs = realloc(cluster->graphs, sz);
        if (cluster->graphs == NULL)
            SET_ERR_JMP(ENOMEM, free, "Failed to realloc");
    }

    /* Add graph to cluster */
    cluster->graphs[cluster->nb_graphs++] = graph;

    return 0;
free:
    return -errno;
}

static void
cluster_fini(struct cluster *cluster)
{
    if (cluster->graphs)
        free(cluster->graphs);
}

static int
expand_pattern_to_cluster(struct cluster *cluster, const char *pattern)
{
    struct graph_head *graph_head = graph_list_head_get();
    struct graph *graph;
    bool found = false;

    /* Check for pattern match */
    STAILQ_FOREACH (graph, graph_head, next) {
        if (fnmatch(pattern, graph->name, 0) == 0) {
            if (cluster_add(cluster, graph))
                goto fail;
            found = true;
        }
    }
    if (found == false)
        SET_ERR_JMP(EFAULT, fail, "Pattern %s graph not found", pattern);

    return 0;
fail:
    return -errno;
}

struct cne_graph_cluster_stats *
cne_graph_cluster_stats_create(const struct cne_graph_cluster_stats_param *prm)
{
    struct cne_graph_cluster_stats *stats, *rc = NULL;
    struct graph_node *graph_node;
    struct cluster cluster;
    struct graph *graph;
    const char *pattern;
    cne_graph_t i;

    /* Sanity checks */
    if (!cne_graph_has_stats_feature())
        SET_ERR_JMP(EINVAL, fail, "Stats feature is not enabled");

    if (prm == NULL)
        SET_ERR_JMP(EINVAL, fail, "Invalid param");

    if (prm->graph_patterns == NULL || prm->nb_graph_patterns == 0)
        SET_ERR_JMP(EINVAL, fail, "Invalid graph param");

    cluster_init(&cluster);

    graph_spinlock_lock();
    /* Expand graph pattern and add the graph to the cluster */
    for (i = 0; i < prm->nb_graph_patterns; i++) {
        pattern = prm->graph_patterns[i];
        if (expand_pattern_to_cluster(&cluster, pattern))
            goto bad_pattern;
    }

    /* Alloc the stats memory */
    stats = stats_mem_init(&cluster, prm);
    if (stats == NULL)
        SET_ERR_JMP(ENOMEM, bad_pattern, "Failed to alloc stats memory");

    /* Iterate over M(Graph) x N (Nodes in graph) */
    for (i = 0; i < cluster.nb_graphs; i++) {
        graph = cluster.graphs[i];
        STAILQ_FOREACH (graph_node, &graph->node_list, next) {
            struct cne_graph *graph_fp = graph->graph;
            if (stats_mem_populate(&stats, graph_fp, graph_node))
                goto realloc_fail;
        }
    }

    /* Finally copy to aligned memory to avoid pressure on realloc */
    rc = aligned_alloc(CNE_CACHE_LINE_SIZE, stats->sz);

    if (rc)
        memcpy(rc, stats, stats->sz);
    else
        SET_ERR_JMP(ENOMEM, realloc_fail, "calloc failed");

realloc_fail:
    stats_mem_fini(stats);
bad_pattern:
    graph_spinlock_unlock();
    cluster_fini(&cluster);
fail:
    return rc;
}

void
cne_graph_cluster_stats_destroy(struct cne_graph_cluster_stats *stat)
{
    return free(stat);
}

static inline void
cluster_node_arregate_stats(struct cluster_node *cluster)
{
    uint64_t calls = 0, cycles = 0, objs = 0, realloc_count = 0;
    struct cne_graph_cluster_node_stats *stat = &cluster->stat;
    struct cne_node *node;
    cne_node_t count;

    for (count = 0; count < cluster->nb_nodes; count++) {
        node = cluster->nodes[count];

        calls += node->total_calls;
        objs += node->total_objs;
        cycles += node->total_cycles;
        realloc_count += node->realloc_count;
    }

    stat->calls         = calls;
    stat->objs          = objs;
    stat->cycles        = cycles;
    stat->ts            = cne_rdtsc();
    stat->realloc_count = realloc_count;
}

static inline void
cluster_node_store_prev_stats(struct cluster_node *cluster)
{
    struct cne_graph_cluster_node_stats *stat = &cluster->stat;

    stat->prev_ts     = stat->ts;
    stat->prev_calls  = stat->calls;
    stat->prev_objs   = stat->objs;
    stat->prev_cycles = stat->cycles;
}

void
cne_graph_cluster_stats_get(struct cne_graph_cluster_stats *stat, bool skip_cb)
{
    struct cluster_node *cluster;
    cne_node_t count;
    int rc = 0;

    cluster = stat->clusters;

    for (count = 0; count < stat->max_nodes; count++) {
        cluster_node_arregate_stats(cluster);
        if (!skip_cb)
            rc = stat->fn(!count, (count == stat->max_nodes - 1), &cluster->stat);
        cluster_node_store_prev_stats(cluster);
        if (rc)
            break;
        cluster = CNE_PTR_ADD(cluster, stat->cluster_node_size);
    }
}

int
cne_graph_stats_node_count(struct cne_graph_cluster_stats *stat)
{
    return (stat) ? (int)stat->max_nodes : -1;
}

void
cne_graph_cluster_stats_reset(struct cne_graph_cluster_stats *stat)
{
    struct cluster_node *cluster;
    cne_node_t count;

    cluster = stat->clusters;

    for (count = 0; count < stat->max_nodes; count++) {
        struct cne_graph_cluster_node_stats *node = &cluster->stat;

        node->ts            = 0;
        node->calls         = 0;
        node->objs          = 0;
        node->cycles        = 0;
        node->prev_ts       = 0;
        node->prev_calls    = 0;
        node->prev_objs     = 0;
        node->prev_cycles   = 0;
        node->realloc_count = 0;
        cluster             = CNE_PTR_ADD(cluster, stat->cluster_node_size);
    }
}
