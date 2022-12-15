/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */
#include <stdio.h>                   // for snprintf, NULL, EOF
#include <unistd.h>                  // for usleep
#include <getopt.h>                  // for getopt_long, option
#include <bsd/string.h>              // for strlcpy
#include <tst_info.h>                // for tst_end, tst_start, tst_i...
#include <test.h>                    // for TEST_CASE_ST, unit_test_suite_runner
#include <cne_common.h>              // for CNE_DIM, CNE_SET_USED, CNE_PRIORITY_LAST
#include <cne_graph.h>               // for cne_node_t, cne_node_id_to_name, CNE_N...
#include <cne_graph_worker.h>        // for cne_node, cne_node_enqueue_x1, cne_nod...
#include <cne_vec.h>                 // for vec_add
#include <errno.h>                   // for ENOMEM, errno
#include <stdbool.h>                 // for false, true
#include <stdint.h>                  // for uint8_t, uint16_t, uint32_t, uintptr_t
#include <stdlib.h>                  // for free, malloc, calloc
#include <string.h>                  // for memset, strcmp

#include "graph_test.h"        // for GRAPH_PRINT_FLAG, GRAPH_VERBOSE_FLAG

#define TEST_GRAPH_PERF              "graph_perf_data"
#define TEST_GRAPH_SRC_NAME          "test_graph_perf_source"
#define TEST_GRAPH_SRC_BRST_ONE_NAME "test_graph_perf_source_one"
#define TEST_GRAPH_WRK_NAME          "test_graph_perf_worker"
#define TEST_GRAPH_SNK_NAME          "test_graph_perf_sink"

#define SOURCES(map)         CNE_DIM(map)
#define STAGES(map)          CNE_DIM(map)
#define NODES_PER_STAGE(map) CNE_DIM(map[0])
#define SINKS(map)           CNE_DIM(map[0])

#define MAX_EDGES_PER_NODE 7

struct test_node_data {
    uint8_t node_id;
    uint8_t is_sink;
    uint8_t next_nodes[MAX_EDGES_PER_NODE];
    uint8_t next_percentage[MAX_EDGES_PER_NODE];
};

struct test_graph_perf {
    char name[32];
    uint16_t nb_nodes;
    cne_graph_t graph_id;
    struct test_node_data *node_data;
};

struct graph_lcore_data {
    uint8_t done;
    cne_graph_t graph_id;
};

static struct test_graph_perf **test_graph_perf_vec;

static struct test_graph_perf *
graph_search(const char *name)
{
    struct test_graph_perf **g;

    vec_foreach (g, test_graph_perf_vec) {
        if (!strcmp(name, (*g)->name))
            return *g;
    }

    return NULL;
}

static struct test_node_data *
graph_get_node_data(struct test_graph_perf *graph_data, cne_node_t id)
{
    struct test_node_data *node_data = NULL;
    int i;

    for (i = 0; i < graph_data->nb_nodes; i++)
        if (graph_data->node_data[i].node_id == id) {
            node_data = &graph_data->node_data[i];
            break;
        }

    return node_data;
}

static int
test_node_ctx_init(const struct cne_graph *graph, struct cne_node *node)
{
    struct test_graph_perf *graph_data;
    struct test_node_data *node_data;
    cne_node_t nid  = node->id;
    cne_edge_t edge = 0;
    int i;

    CNE_SET_USED(graph);

    graph_data = graph_search(TEST_GRAPH_PERF);
    if (!graph_data)
        return -1;

    node_data = graph_get_node_data(graph_data, nid);
    if (!node_data)
        return -1;
    node->ctx[0] = node->nb_edges;
    for (i = 0; i < node->nb_edges && !node_data->is_sink; i++, edge++) {
        node->ctx[i + 1] = edge;
        node->ctx[i + 9] = node_data->next_percentage[i];
    }

    return 0;
}

/* Source node function */
static uint16_t
test_perf_node_worker_source(struct cne_graph *graph, struct cne_node *node, void **objs,
                             uint16_t nb_objs)
{
    uint16_t count;
    int i;

    CNE_SET_USED(objs);
    CNE_SET_USED(nb_objs);

    /* Create a proportional stream for every next */
    for (i = 0; i < node->ctx[0]; i++) {
        count = (node->ctx[i + 9] * CNE_GRAPH_BURST_SIZE) / 100;
        cne_node_next_stream_get(graph, node, node->ctx[i + 1], count);
        cne_node_next_stream_put(graph, node, node->ctx[i + 1], count);
    }

    return CNE_GRAPH_BURST_SIZE;
}

static struct cne_node_register test_graph_perf_source = {
    .name    = TEST_GRAPH_SRC_NAME,
    .process = test_perf_node_worker_source,
    .flags   = CNE_NODE_SOURCE_F,
    .init    = test_node_ctx_init,
};

CNE_NODE_REGISTER(test_graph_perf_source);

static uint16_t
test_perf_node_worker_source_burst_one(struct cne_graph *graph, struct cne_node *node, void **objs,
                                       uint16_t nb_objs)
{
    uint16_t count;
    int i;

    CNE_SET_USED(objs);
    CNE_SET_USED(nb_objs);

    /* Create a proportional stream for every next */
    for (i = 0; i < node->ctx[0]; i++) {
        count = (node->ctx[i + 9]) / 100;
        cne_node_next_stream_get(graph, node, node->ctx[i + 1], count);
        cne_node_next_stream_put(graph, node, node->ctx[i + 1], count);
    }

    return 1;
}

static struct cne_node_register test_graph_perf_source_burst_one = {
    .name    = TEST_GRAPH_SRC_BRST_ONE_NAME,
    .process = test_perf_node_worker_source_burst_one,
    .flags   = CNE_NODE_SOURCE_F,
    .init    = test_node_ctx_init,
};

CNE_NODE_REGISTER(test_graph_perf_source_burst_one);

/* Worker node function */
static uint16_t
test_perf_node_worker(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    uint16_t next = 0;
    uint16_t enq  = 0;
    uint16_t count;
    int i;

    /* Move stream for single next node */
    if (node->ctx[0] == 1) {
        cne_node_next_stream_move(graph, node, node->ctx[1]);
        return nb_objs;
    }

    /* Enqueue objects to next nodes proportionally */
    for (i = 0; i < node->ctx[0]; i++) {
        next  = node->ctx[i + 1];
        count = (node->ctx[i + 9] * nb_objs) / 100;
        enq += count;
        while (count) {
            switch (count & (4 - 1)) {
            case 0:
                cne_node_enqueue_x4(graph, node, next, objs[0], objs[1], objs[2], objs[3]);
                objs += 4;
                count -= 4;
                break;
            case 1:
                cne_node_enqueue_x1(graph, node, next, objs[0]);
                objs += 1;
                count -= 1;
                break;
            case 2:
                cne_node_enqueue_x2(graph, node, next, objs[0], objs[1]);
                objs += 2;
                count -= 2;
                break;
            case 3:
                cne_node_enqueue_x2(graph, node, next, objs[0], objs[1]);
                cne_node_enqueue_x1(graph, node, next, objs[0]);
                objs += 3;
                count -= 3;
                break;
            }
        }
    }

    if (enq != nb_objs)
        cne_node_enqueue(graph, node, next, objs, nb_objs - enq);

    return nb_objs;
}

static struct cne_node_register test_graph_perf_worker = {
    .name    = TEST_GRAPH_WRK_NAME,
    .process = test_perf_node_worker,
    .init    = test_node_ctx_init,
};

CNE_NODE_REGISTER(test_graph_perf_worker);

/* Last node in graph a.k.a sink node */
static uint16_t
test_perf_node_sink(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    CNE_SET_USED(graph);
    CNE_SET_USED(node);
    CNE_SET_USED(objs);
    CNE_SET_USED(nb_objs);

    return nb_objs;
}

static struct cne_node_register test_graph_perf_sink = {
    .name    = TEST_GRAPH_SNK_NAME,
    .process = test_perf_node_sink,
    .init    = test_node_ctx_init,
};

CNE_NODE_REGISTER(test_graph_perf_sink);

static int
graph_perf_setup(void)
{
    return 0;
}

static void
graph_perf_teardown(void)
{
}

static inline cne_node_t
graph_node_get(const char *pname, char *nname)
{
    cne_node_t pnode_id = cne_node_from_name(pname);
    char lookup_name[CNE_NODE_NAMESIZE];
    cne_node_t node_id;

    snprintf(lookup_name, CNE_NODE_NAMESIZE, "%s-%s", pname, nname);
    node_id = cne_node_from_name(lookup_name);

    if (node_id != CNE_NODE_ID_INVALID) {
        if (cne_node_edge_count(node_id))
            cne_node_edge_shrink(node_id, 0);
        return node_id;
    }

    return cne_node_clone(pnode_id, nname);
}

static uint16_t
graph_node_count_edges(uint32_t stage, uint16_t node, uint16_t nodes_per_stage,
                       uint8_t edge_map[][nodes_per_stage][nodes_per_stage], char *ename[],
                       struct test_node_data *node_data, cne_node_t **node_map)
{
    uint8_t total_percent = 0;
    uint16_t edges        = 0;
    int i;

    for (i = 0; i < nodes_per_stage && edges < MAX_EDGES_PER_NODE; i++) {
        if (edge_map[stage + 1][i][node]) {
            const char *node_name = cne_node_id_to_name(node_map[stage + 1][i]);

            if (node_name == NULL) {
                tst_error("Invalid node name");
                goto fail;
            }
            ename[edges] = malloc(sizeof(char) * CNE_NODE_NAMESIZE);
            snprintf(ename[edges], CNE_NODE_NAMESIZE, "%s", node_name);
            node_data->next_nodes[edges]      = node_map[stage + 1][i];
            node_data->next_percentage[edges] = edge_map[stage + 1][i][node];
            edges++;
            total_percent += edge_map[stage + 1][i][node];
        }
    }

    if (edges >= MAX_EDGES_PER_NODE || (edges && total_percent != 100))
        goto fail;

    return edges;
fail:
    for (i = 0; i < edges; i++)
        free(ename[i]);
    return CNE_EDGE_ID_INVALID;
}

static int
graph_init(const char *gname, uint8_t nb_srcs, uint8_t nb_sinks, uint32_t stages,
           uint16_t nodes_per_stage, uint8_t src_map[][nodes_per_stage],
           uint8_t snk_map[][nb_sinks], uint8_t edge_map[][nodes_per_stage][nodes_per_stage],
           uint8_t burst_one)
{
    struct test_graph_perf *graph_data;
    char nname[CNE_NODE_NAMESIZE / 2];
    struct test_node_data *node_data;
    char *ename[nodes_per_stage];
    uint8_t total_percent = 0;
    cne_node_t *src_nodes;
    cne_node_t *snk_nodes;
    cne_node_t **node_map;
    char **node_patterns;
    cne_graph_t graph_id;
    cne_edge_t edges;
    cne_edge_t count;
    uint32_t i, j, k;

    graph_data = calloc(1, sizeof(struct test_graph_perf));
    if (graph_data == NULL) {
        tst_error("Failed to allocate graph common memory");
        return -ENOMEM;
    }
    vec_add(test_graph_perf_vec, graph_data);
    strlcpy(graph_data->name, TEST_GRAPH_PERF, sizeof(graph_data->name));

    graph_data->nb_nodes = 0;
    graph_data->node_data =
        malloc(sizeof(struct test_node_data) * (nb_srcs + nb_sinks + stages * nodes_per_stage));
    if (graph_data->node_data == NULL) {
        tst_error("Failed to reserve memzone for graph data");
        goto memzone_free;
    }

    node_patterns = calloc(1, sizeof(char *) * (nb_srcs + nb_sinks + stages * nodes_per_stage + 1));
    if (node_patterns == NULL) {
        tst_error("Failed to reserve memory for node patterns");
        goto data_free;
    }

    src_nodes = calloc(nb_srcs, sizeof(cne_node_t));
    if (src_nodes == NULL) {
        tst_error("Failed to reserve memory for src nodes");
        goto pattern_free;
    }

    snk_nodes = calloc(nb_sinks, sizeof(cne_node_t));
    if (snk_nodes == NULL) {
        tst_error("Failed to reserve memory for snk nodes");
        goto src_free;
    }

    node_map =
        calloc(1, sizeof(cne_node_t *) * stages + sizeof(cne_node_t) * nodes_per_stage * stages);
    if (node_map == NULL) {
        tst_error("Failed to reserve memory for node map");
        goto snk_free;
    }

    /* Setup the Graph */
    for (i = 0; i < stages; i++) {
        node_map[i] = (cne_node_t *)(node_map + stages) + nodes_per_stage * i;
        for (j = 0; j < nodes_per_stage; j++) {
            char *node_name;

            total_percent = 0;
            for (k = 0; k < nodes_per_stage; k++)
                total_percent += edge_map[i][j][k];
            if (!total_percent)
                continue;
            node_patterns[graph_data->nb_nodes] = malloc(CNE_NODE_NAMESIZE);
            if (node_patterns[graph_data->nb_nodes] == NULL) {
                tst_error("Failed to create memory for pattern");
                goto pattern_name_free;
            }

            /* Clone a worker node */
            snprintf(nname, sizeof(nname), "%d-%d", i, j);
            node_map[i][j] = graph_node_get(TEST_GRAPH_WRK_NAME, nname);
            if (node_map[i][j] == CNE_NODE_ID_INVALID) {
                tst_error("Failed to create node[%s]", nname);
                graph_data->nb_nodes++;
                goto pattern_name_free;
            }
            node_name = cne_node_id_to_name(node_map[i][j]);
            if (node_name == NULL) {
                tst_error("Invalid node name");
                graph_data->nb_nodes++;
                goto pattern_name_free;
            }
            snprintf(node_patterns[graph_data->nb_nodes], CNE_NODE_NAMESIZE, "%s", node_name);
            node_data          = &graph_data->node_data[graph_data->nb_nodes];
            node_data->node_id = node_map[i][j];
            node_data->is_sink = false;
            graph_data->nb_nodes++;
        }
    }

    for (i = 0; i < stages - 1; i++) {
        for (j = 0; j < nodes_per_stage; j++) {
            /* Count edges i.e connections of worker node to next */
            node_data = graph_get_node_data(graph_data, node_map[i][j]);
            edges =
                graph_node_count_edges(i, j, nodes_per_stage, edge_map, ename, node_data, node_map);
            if (edges == CNE_EDGE_ID_INVALID) {
                tst_error("Invalid edge configuration");
                goto pattern_name_free;
            }
            if (!edges)
                continue;

            /* Connect a node in stage 'i' to nodes
             * in stage 'i + 1' with edges.
             */
            count = cne_node_edge_update(node_map[i][j], 0, (const char **)(uintptr_t)ename, edges);
            for (k = 0; k < edges; k++)
                free(ename[k]);
            if (count != edges) {
                tst_error("Couldn't add edges %d %d", edges, count);
                goto pattern_name_free;
            }
        }
    }

    /* Setup Source nodes */
    for (i = 0; i < nb_srcs; i++) {
        const char *node_name;

        edges                               = 0;
        total_percent                       = 0;
        node_patterns[graph_data->nb_nodes] = malloc(CNE_NODE_NAMESIZE);
        if (node_patterns[graph_data->nb_nodes] == NULL) {
            tst_error("Failed to create memory for pattern");
            goto pattern_name_free;
        }
        /* Clone a source node */
        snprintf(nname, sizeof(nname), "%d", i);
        src_nodes[i] =
            graph_node_get(burst_one ? TEST_GRAPH_SRC_BRST_ONE_NAME : TEST_GRAPH_SRC_NAME, nname);
        if (src_nodes[i] == CNE_NODE_ID_INVALID) {
            tst_error("Failed to create node[%s]", nname);
            graph_data->nb_nodes++;
            goto pattern_name_free;
        }
        node_name = cne_node_id_to_name(src_nodes[i]);
        if (node_name == NULL) {
            tst_error("Failed to get node name");
            goto pattern_name_free;
        }
        snprintf(node_patterns[graph_data->nb_nodes], CNE_NODE_NAMESIZE, "%s", node_name);
        node_data          = &graph_data->node_data[graph_data->nb_nodes];
        node_data->node_id = src_nodes[i];
        node_data->is_sink = false;
        graph_data->nb_nodes++;

        /* Prepare next node list  to connect to */
        for (j = 0; j < nodes_per_stage; j++) {
            const char *node_name;

            if (!src_map[i][j])
                continue;
            node_name = cne_node_id_to_name(node_map[0][j]);
            if (node_name == NULL) {
                tst_error("Invalid node name");
                continue;
            }
            ename[edges] = malloc(sizeof(char) * CNE_NODE_NAMESIZE);
            snprintf(ename[edges], CNE_NODE_NAMESIZE, "%s", node_name);
            node_data->next_nodes[edges]      = node_map[0][j];
            node_data->next_percentage[edges] = src_map[i][j];
            edges++;
            total_percent += src_map[i][j];
        }

        if (!edges)
            continue;
        if (edges >= MAX_EDGES_PER_NODE || total_percent != 100) {
            tst_error("Invalid edge configuration");
            for (j = 0; j < edges; j++)
                free(ename[j]);
            goto pattern_name_free;
        }

        /* Connect to list of next nodes using edges */
        count = cne_node_edge_update(src_nodes[i], 0, (const char **)(uintptr_t)ename, edges);
        for (k = 0; k < edges; k++)
            free(ename[k]);
        if (count != edges) {
            tst_error("Couldn't add edges %d %d", edges, count);
            goto pattern_name_free;
        }
    }

    /* Setup Sink nodes */
    for (i = 0; i < nb_sinks; i++) {
        char *node_name;

        node_patterns[graph_data->nb_nodes] = malloc(CNE_NODE_NAMESIZE);
        if (node_patterns[graph_data->nb_nodes] == NULL) {
            tst_error("Failed to create memory for pattern");
            goto pattern_name_free;
        }

        /* Clone a sink node */
        snprintf(nname, sizeof(nname), "%d", i);
        snk_nodes[i] = graph_node_get(TEST_GRAPH_SNK_NAME, nname);
        if (snk_nodes[i] == CNE_NODE_ID_INVALID) {
            tst_error("Failed to create node[%s]", nname);
            graph_data->nb_nodes++;
            goto pattern_name_free;
        }
        node_name = cne_node_id_to_name(snk_nodes[i]);
        if (node_name == NULL) {
            tst_error("Invalid node name");
            graph_data->nb_nodes++;
            goto pattern_name_free;
        }
        snprintf(node_patterns[graph_data->nb_nodes], CNE_NODE_NAMESIZE, "%s", node_name);
        node_data          = &graph_data->node_data[graph_data->nb_nodes];
        node_data->node_id = snk_nodes[i];
        node_data->is_sink = true;
        graph_data->nb_nodes++;
    }

    /* Connect last stage worker nodes to sink nodes */
    for (i = 0; i < nodes_per_stage; i++) {
        edges         = 0;
        total_percent = 0;
        node_data     = graph_get_node_data(graph_data, node_map[stages - 1][i]);
        /* Prepare list of sink nodes to connect to */
        for (j = 0; j < nb_sinks; j++) {
            char *node_name;

            if (!snk_map[i][j])
                continue;

            if (!node_data) {
                tst_error("graph_get_node_data() failed");
                for (k = 0; k < edges; k++)
                    free(ename[k]);
                goto pattern_name_free;
            }

            node_name = cne_node_id_to_name(snk_nodes[j]);
            if (node_name == NULL) {
                tst_error("Invalid node name");
                for (k = 0; k < edges; k++)
                    free(ename[k]);
                goto pattern_name_free;
            }
            ename[edges] = malloc(sizeof(char) * CNE_NODE_NAMESIZE);
            snprintf(ename[edges], CNE_NODE_NAMESIZE, "%s", node_name);
            node_data->next_nodes[edges]      = snk_nodes[j];
            node_data->next_percentage[edges] = snk_map[i][j];
            edges++;
            total_percent += snk_map[i][j];
        }
        if (!edges)
            continue;
        if (edges >= MAX_EDGES_PER_NODE || total_percent != 100) {
            tst_error("Invalid edge configuration");
            for (k = 0; k < edges; k++)
                free(ename[k]);
            goto pattern_name_free;
        }

        /* Connect a worker node to a list of sink nodes */
        count = cne_node_edge_update(node_map[stages - 1][i], 0, (const char **)(uintptr_t)ename,
                                     edges);
        for (k = 0; k < edges; k++)
            free(ename[k]);
        if (count != edges) {
            tst_error("Couldn't add edges %d %d", edges, count);
            goto pattern_name_free;
        }
    }

    /* Create a Graph */
    graph_id = cne_graph_create(gname, (const char **)(uintptr_t)node_patterns);
    if (graph_id == CNE_GRAPH_ID_INVALID) {
        tst_error("Graph creation failed with error = %d", errno);
        goto pattern_name_free;
    }
    graph_data->graph_id = graph_id;

    free(node_map);
    for (i = 0; i < graph_data->nb_nodes; i++)
        free(node_patterns[i]);
    free(snk_nodes);
    free(src_nodes);
    free(node_patterns);
    return 0;

pattern_name_free:
    free(node_map);
    for (i = 0; i < graph_data->nb_nodes; i++)
        free(node_patterns[i]);
snk_free:
    free(snk_nodes);
src_free:
    free(src_nodes);
pattern_free:
    free(node_patterns);
data_free:
    free(graph_data->node_data);
memzone_free:
    free(graph_data);
    return -ENOMEM;
}

static int
measure_perf_get(cne_graph_t graph_id)
{
    const char *pattern = cne_graph_id_to_name(graph_id);
    //    uint32_t lcore_id   = cne_get_next_lcore(-1, 1, 0);
    struct cne_graph_cluster_stats_param param;
    struct cne_graph_cluster_stats *stats;
    struct graph_lcore_data *data;

    data = calloc(1, sizeof(struct graph_lcore_data));
    if (!data)
        return -1;
    data->graph_id = graph_id;
    data->done     = 0;

    /* Collect stats for few msecs */
    if (cne_graph_has_stats_feature()) {
        memset(&param, 0, sizeof(param));
        param.graph_patterns    = &pattern;
        param.nb_graph_patterns = 1;

        stats = cne_graph_cluster_stats_create(&param);
        if (stats == NULL) {
            tst_error("Failed to create stats");
            free(data);
            return -ENOMEM;
        }

        usleep(3E2);
        cne_graph_cluster_stats_get(stats, true);
        usleep(1E3);
        cne_graph_cluster_stats_get(stats, false);
        cne_graph_cluster_stats_destroy(stats);
    } else
        usleep(1E3);

    data->done = 1;
    free(data);

    return 0;
}

static inline void
graph_fini(void)
{
    struct test_graph_perf *graph_data = graph_search(TEST_GRAPH_PERF);
    if (!graph_data)
        return;

    cne_graph_destroy(graph_data->graph_id);
    free(graph_data->node_data);
    free(graph_data);
}

static int
measure_perf(void)
{
    struct test_graph_perf *graph_data = graph_search(TEST_GRAPH_PERF);
    if (!graph_data)
        return -1;

    return measure_perf_get(graph_data->graph_id);
}

static inline int
graph_hr_4s_1n_1src_1snk(void)
{
    return measure_perf();
}

static inline int
graph_hr_4s_1n_1src_1snk_brst_one(void)
{
    return measure_perf();
}

static inline int
graph_hr_4s_1n_2src_1snk(void)
{
    return measure_perf();
}

static inline int
graph_hr_4s_1n_1src_2snk(void)
{
    return measure_perf();
}

static inline int
graph_tree_4s_4n_1src_4snk(void)
{
    return measure_perf();
}

static inline int
graph_reverse_tree_3s_4n_1src_1snk(void)
{
    return measure_perf();
}

static inline int
graph_parallel_tree_5s_4n_4src_4snk(void)
{
    return measure_perf();
}

/* Graph Topology
 * nodes per stage:	1
 * stages:		4
 * src:			1
 * sink:		1
 */
static inline int
graph_init_hr(void)
{
    uint8_t edge_map[][1][1] = {
        {{100}},
        {{100}},
        {{100}},
        {{100}},
    };
    uint8_t src_map[][1] = {{100}};
    uint8_t snk_map[][1] = {{100}};

    return graph_init("graph_hr", SOURCES(src_map), SINKS(snk_map), STAGES(edge_map),
                      NODES_PER_STAGE(edge_map), src_map, snk_map, edge_map, 0);
}

/* Graph Topology
 * nodes per stage:	1
 * stages:		4
 * src:			1
 * sink:		1
 */
static inline int
graph_init_hr_brst_one(void)
{
    uint8_t edge_map[][1][1] = {
        {{100}},
        {{100}},
        {{100}},
        {{100}},
    };
    uint8_t src_map[][1] = {{100}};
    uint8_t snk_map[][1] = {{100}};

    return graph_init("graph_hr", SOURCES(src_map), SINKS(snk_map), STAGES(edge_map),
                      NODES_PER_STAGE(edge_map), src_map, snk_map, edge_map, 1);
}

/* Graph Topology
 * nodes per stage:	1
 * stages:		4
 * src:			2
 * sink:		1
 */
static inline int
graph_init_hr_multi_src(void)
{
    uint8_t edge_map[][1][1] = {
        {{100}},
        {{100}},
        {{100}},
        {{100}},
    };
    uint8_t src_map[][1] = {{100}, {100}};
    uint8_t snk_map[][1] = {{100}};

    return graph_init("graph_hr", SOURCES(src_map), SINKS(snk_map), STAGES(edge_map),
                      NODES_PER_STAGE(edge_map), src_map, snk_map, edge_map, 0);
}

/* Graph Topology
 * nodes per stage:	1
 * stages:		4
 * src:			1
 * sink:		2
 */
static inline int
graph_init_hr_multi_snk(void)
{
    uint8_t edge_map[][1][1] = {
        {{100}},
        {{100}},
        {{100}},
        {{100}},
    };
    uint8_t src_map[][1] = {{100}};
    uint8_t snk_map[][2] = {{50, 50}};

    return graph_init("graph_hr", SOURCES(src_map), SINKS(snk_map), STAGES(edge_map),
                      NODES_PER_STAGE(edge_map), src_map, snk_map, edge_map, 0);
}

/* Graph Topology
 * nodes per stage:	4
 * stages:		4
 * src:			1
 * sink:		4
 */
static inline int
graph_init_tree(void)
{
    uint8_t edge_map[][4][4] = {
        {{100, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}},
        {{50, 0, 0, 0}, {50, 0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}},
        {{33, 33, 0, 0}, {34, 34, 0, 0}, {33, 33, 0, 0}, {0, 0, 0, 0}},
        {{25, 25, 25, 0}, {25, 25, 25, 0}, {25, 25, 25, 0}, {25, 25, 25, 0}}};
    uint8_t src_map[][4] = {{100, 0, 0, 0}};
    uint8_t snk_map[][4] = {{100, 0, 0, 0}, {0, 100, 0, 0}, {0, 0, 100, 0}, {0, 0, 0, 100}};

    return graph_init("graph_full_split", SOURCES(src_map), SINKS(snk_map), STAGES(edge_map),
                      NODES_PER_STAGE(edge_map), src_map, snk_map, edge_map, 0);
}

/* Graph Topology
 * nodes per stage:	4
 * stages:		3
 * src:			1
 * sink:		1
 */
static inline int
graph_init_reverse_tree(void)
{
    uint8_t edge_map[][4][4] = {
        {{25, 25, 25, 25}, {25, 25, 25, 25}, {25, 25, 25, 25}, {25, 25, 25, 25}},
        {{33, 33, 33, 33}, {33, 33, 33, 33}, {34, 34, 34, 34}, {0, 0, 0, 0}},
        {{50, 50, 50, 0}, {50, 50, 50, 0}, {0, 0, 0, 0}, {0, 0, 0, 0}},
    };
    uint8_t src_map[][4] = {{25, 25, 25, 25}};
    uint8_t snk_map[][1] = {{100}, {100}, {0}, {0}};

    return graph_init("graph_full_split", SOURCES(src_map), SINKS(snk_map), STAGES(edge_map),
                      NODES_PER_STAGE(edge_map), src_map, snk_map, edge_map, 0);
}

/* Graph Topology
 * nodes per stage:	4
 * stages:		5
 * src:			4
 * sink:		4
 */
static inline int
graph_init_parallel_tree(void)
{
    uint8_t edge_map[][4][4] = {
        {{100, 0, 0, 0}, {0, 100, 0, 0}, {0, 0, 100, 0}, {0, 0, 0, 100}},
        {{100, 0, 0, 0}, {0, 100, 0, 0}, {0, 0, 100, 0}, {0, 0, 0, 100}},
        {{100, 0, 0, 0}, {0, 100, 0, 0}, {0, 0, 100, 0}, {0, 0, 0, 100}},
        {{100, 0, 0, 0}, {0, 100, 0, 0}, {0, 0, 100, 0}, {0, 0, 0, 100}},
        {{100, 0, 0, 0}, {0, 100, 0, 0}, {0, 0, 100, 0}, {0, 0, 0, 100}},
    };
    uint8_t src_map[][4] = {{100, 0, 0, 0}, {0, 100, 0, 0}, {0, 0, 100, 0}, {0, 0, 0, 100}};
    uint8_t snk_map[][4] = {{100, 0, 0, 0}, {0, 100, 0, 0}, {0, 0, 100, 0}, {0, 0, 0, 100}};

    return graph_init("graph_parallel", SOURCES(src_map), SINKS(snk_map), STAGES(edge_map),
                      NODES_PER_STAGE(edge_map), src_map, snk_map, edge_map, 0);
}

/** Graph Creation cheat sheet
 *  edge_map -> dictates graph flow from worker stage 0 to worker stage n-1.
 *  src_map  -> dictates source nodes enqueue percentage to worker stage 0.
 *  snk_map  -> dictates stage n-1 enqueue percentage to sink.
 *
 *  Layout:
 *  edge_map[<nb_stages>][<nodes_per_stg>][<nodes_in_nxt_stg = nodes_per_stg>]
 *  src_map[<nb_sources>][<nodes_in_stage0 = nodes_per_stage>]
 *  snk_map[<nodes_in_stage(n-1) = nodes_per_stage>][<nb_sinks>]
 *
 *  The last array dictates the percentage of received objs to enqueue to next
 *  stage.
 *
 *  Note: edge_map[][0][] will always be unused as it will receive from source
 *
 *  Example:
 *	Graph:
 *	http://bit.ly/2PqbqOy
 *	Each stage(n) connects to all nodes in the next stage in decreasing
 *	order.
 *	Since we can't resize the edge_map dynamically we get away by creating
 *	dummy nodes and assigning 0 percentages.
 *	Max nodes across all stages = 4
 *	stages = 3
 *	nb_src = 1
 *	nb_snk = 1
 *			   // Stages
 *	edge_map[][4][4] = {
 *		// Nodes per stage
 *		{
 *		    {25, 25, 25, 25},
 *		    {25, 25, 25, 25},
 *		    {25, 25, 25, 25},
 *		    {25, 25, 25, 25}
 *		},	// This will be unused.
 *		{
 *		    // Nodes enabled in current stage + prev stage enq %
 *		    {33, 33, 33, 33},
 *		    {33, 33, 33, 33},
 *		    {34, 34, 34, 34},
 *		    {0, 0, 0, 0}
 *		},
 *		{
 *		    {50, 50, 50, 0},
 *		    {50, 50, 50, 0},
 *		    {0, 0, 0, 0},
 *		    {0, 0, 0, 0}
 *		},
 *	};
 *	Above, each stage tells how much it should receive from previous except
 *	from stage_0.
 *
 *	src_map[][4] = { {25, 25, 25, 25} };
 *	Here, we tell each source the % it has to send to stage_0 nodes. In
 *	case we want 2 source node we can declare as
 *	src_map[][4] = { {25, 25, 25, 25}, {25, 25, 25, 25} };
 *
 *	snk_map[][1] = { {100}, {100}, {0}, {0} }
 *	Here, we tell stage - 1 nodes how much to enqueue to sink_0.
 *	If we have 2 sinks we can do as follows
 *	snk_map[][2] = { {50, 50}, {50, 50}, {0, 0}, {0, 0} }
 */

static struct unit_test_suite graph_perf_testsuite = {
    .suite_name = "Graph library performance test suite",
    .setup      = graph_perf_setup,
    .teardown   = graph_perf_teardown,
    .unit_test_cases =
        {
            TEST_CASE_ST(graph_init_hr, graph_fini, graph_hr_4s_1n_1src_1snk),
            TEST_CASE_ST(graph_init_hr_brst_one, graph_fini, graph_hr_4s_1n_1src_1snk_brst_one),
            TEST_CASE_ST(graph_init_hr_multi_src, graph_fini, graph_hr_4s_1n_2src_1snk),
            TEST_CASE_ST(graph_init_hr_multi_snk, graph_fini, graph_hr_4s_1n_1src_2snk),
            TEST_CASE_ST(graph_init_tree, graph_fini, graph_tree_4s_4n_1src_4snk),
            TEST_CASE_ST(graph_init_reverse_tree, graph_fini, graph_reverse_tree_3s_4n_1src_1snk),
            TEST_CASE_ST(graph_init_parallel_tree, graph_fini, graph_parallel_tree_5s_4n_4src_4snk),
            TEST_CASES_END(), /**< NULL terminate unit test array */
        },
};

static int
test_graph_perf_func(void)
{
    test_graph_perf_vec = vec_free(test_graph_perf_vec);

    return unit_test_suite_runner(&graph_perf_testsuite);
}

int
graph_perf_main(int argc, char **argv)
{
    tst_info_t *tst;
    int opt, flags = 0;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "Vp", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            flags |= GRAPH_VERBOSE_FLAG;
            break;
        case 'p':
            flags |= GRAPH_PRINT_FLAG;
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(flags);

    tst = tst_start("Graph Perf");

    if (test_graph_perf_func() < 0)
        goto leave;

    tst_ok("%s tests passed", tst->name);
    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_error("%s tests failed", tst->name);
    tst_end(tst, TST_FAILED);
    return -1;
}
