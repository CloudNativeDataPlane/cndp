/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */
#include <inttypes.h>                // for PRId64
#include <stdio.h>                   // for printf, NULL, EOF, stdout
#include <string.h>                  // for strcmp, strncmp, memset
#include <getopt.h>                  // for getopt_long, option
#include <tst_info.h>                // for tst_end, tst_start, tst_i...
#include <test.h>                    // for TEST_CASE, unit_test_suite_runner, TES...
#include <cne_graph.h>               // for cne_node_from_name, cne_node_clone
#include <cne_graph_worker.h>        // for cne_node_enqueue, cne_node, cne_node_n...
#include <pktmbuf.h>                 // for pktmbuf_t
#include <errno.h>                   // for errno
#include <stdbool.h>                 // for bool
#include <stdint.h>                  // for uint32_t, uint64_t, uint16_t, uint8_t
#include <stdlib.h>                  // for free, rand, malloc

#include "graph_test.h"
#include "cne_common.h"        // for CNE_SET_USED, CNE_PRIORITY_LAST, SOCKE...

static uint16_t test_node_worker_source(struct cne_graph *graph, struct cne_node *node, void **objs,
                                        uint16_t nb_objs);

static uint16_t test_node0_worker(struct cne_graph *graph, struct cne_node *node, void **objs,
                                  uint16_t nb_objs);

static uint16_t test_node1_worker(struct cne_graph *graph, struct cne_node *node, void **objs,
                                  uint16_t nb_objs);

static uint16_t test_node2_worker(struct cne_graph *graph, struct cne_node *node, void **objs,
                                  uint16_t nb_objs);

static uint16_t test_node3_worker(struct cne_graph *graph, struct cne_node *node, void **objs,
                                  uint16_t nb_objs);

#define MBUFF_SIZE 512
#define MAX_NODES  4

static pktmbuf_t mbuf[MAX_NODES + 1][MBUFF_SIZE];
static void *mbuf_p[MAX_NODES + 1][MBUFF_SIZE];
static cne_graph_t graph_id;
static uint64_t obj_stats[MAX_NODES + 1];
static uint64_t fn_calls[MAX_NODES + 1];

// clang-format off
const char *node_patterns[] = {
    "test_node_source1",
    "test_node00",
    "test_node00-test_node11",
    "test_node00-test_node22",
    "test_node00-test_node33",
    NULL
};

const char *node_names[] = {
    "test_node00",
    "test_node00-test_node11",
    "test_node00-test_node22",
    "test_node00-test_node33",
    NULL
};
// clang-format on

struct test_node_register {
    char name[CNE_NODE_NAMESIZE];
    cne_node_process_t process;
    uint16_t nb_edges;
    const char *next_nodes[MAX_NODES];
};

typedef struct {
    uint32_t idx;
    struct test_node_register node;
} test_node_t;

typedef struct {
    test_node_t test_node[MAX_NODES];
} test_main_t;

// clang-format off
static test_main_t test_main = {
    .test_node = {
        {
            .node = {
                .name       = "test_node00",
                .process    = test_node0_worker,
                .nb_edges   = 2,
                .next_nodes = {
                    "test_node00-test_node11",
                    "test_node00-test_node22"
                    },
            },
        },
        {
            .node = {
                .name       = "test_node11",
                .process    = test_node1_worker,
                .nb_edges   = 1,
                .next_nodes = { "test_node00-test_node22" },
            },
        },
        {
            .node = {
                .name       = "test_node22",
                .process    = test_node2_worker,
                .nb_edges   = 1,
                .next_nodes = { "test_node00-test_node33" },
            },
        },
        {
            .node = {
                .name       = "test_node33",
                .process    = test_node3_worker,
                .nb_edges   = 1,
                .next_nodes = { "test_node00" },
            },
        },
    },
};
// clang-format on

static int
node_init(const struct cne_graph *graph, struct cne_node *node)
{
    CNE_SET_USED(graph);
    *(uint32_t *)node->ctx = node->id;

    return 0;
}

static struct cne_node_register test_node_source = {
    .name       = "test_node_source1",
    .process    = test_node_worker_source,
    .flags      = CNE_NODE_SOURCE_F,
    .nb_edges   = 2,
    .init       = node_init,
    .next_nodes = {"test_node00", "test_node00-test_node11"},
};
CNE_NODE_REGISTER(test_node_source);

static struct cne_node_register test_node0 = {
    .name    = "test_node00",
    .process = test_node0_worker,
    .init    = node_init,
};
CNE_NODE_REGISTER(test_node0);

uint16_t
test_node_worker_source(struct cne_graph *graph, struct cne_node *node, void **objs,
                        uint16_t nb_objs)
{
    uint32_t obj_node0 = rand() % 100, obj_node1;
    test_main_t *tm    = &test_main;
    pktmbuf_t *data;
    void **next_stream;
    cne_node_t next;
    uint32_t i;

    CNE_SET_USED(objs);
    nb_objs = CNE_GRAPH_BURST_SIZE;

    /* Prepare stream for next node 0 */
    obj_node0   = nb_objs * obj_node0 * 0.01;
    next        = 0;
    next_stream = cne_node_next_stream_get(graph, node, next, obj_node0);
    for (i = 0; i < obj_node0; i++) {
        data                  = &mbuf[0][i];
        pktmbuf_udata64(data) = ((uint64_t)tm->test_node[0].idx << 32) | i;
        if ((i + 1) == obj_node0)
            pktmbuf_udata64(data) |= (1UL << 16);
        next_stream[i] = &mbuf[0][i];
    }
    cne_node_next_stream_put(graph, node, next, obj_node0);

    /* Prepare stream for next node 1 */
    obj_node1   = nb_objs - obj_node0;
    next        = 1;
    next_stream = cne_node_next_stream_get(graph, node, next, obj_node1);
    for (i = 0; i < obj_node1; i++) {
        data                  = &mbuf[0][obj_node0 + i];
        pktmbuf_udata64(data) = ((uint64_t)tm->test_node[1].idx << 32) | i;
        if ((i + 1) == obj_node1)
            pktmbuf_udata64(data) |= (1UL << 16);
        next_stream[i] = &mbuf[0][obj_node0 + i];
    }

    cne_node_next_stream_put(graph, node, next, obj_node1);
    obj_stats[0] += nb_objs;
    fn_calls[0] += 1;
    return nb_objs;
}

uint16_t
test_node0_worker(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    test_main_t *tm = &test_main;

    if (*(uint32_t *)node->ctx == test_node0.id) {
        uint32_t obj_node0 = rand() % 100, obj_node1;
        pktmbuf_t *data;
        uint8_t second_pass = 0;
        uint32_t count      = 0;
        uint32_t i;

        obj_stats[1] += nb_objs;
        fn_calls[1] += 1;

        for (i = 0; i < nb_objs; i++) {
            data = (pktmbuf_t *)objs[i];
            if ((pktmbuf_udata64(data) >> 32) != tm->test_node[0].idx) {
                tst_error("Data idx miss match at node 0, expected = %u got = %u",
                          tm->test_node[0].idx, (uint32_t)(pktmbuf_udata64(data) >> 32));
                goto end;
            }

            if ((pktmbuf_udata64(data) & 0xffff) != (i - count)) {
                tst_error("Expected buff count miss match at node 0");
                goto end;
            }

            if (pktmbuf_udata64(data) & (0x1 << 16))
                count = i + 1;
            if (pktmbuf_udata64(data) & (0x1 << 17))
                second_pass = 1;
        }

        if (count != i) {
            tst_error("Count mismatch at node 0");
            goto end;
        }

        obj_node0 = nb_objs * obj_node0 * 0.01;
        for (i = 0; i < obj_node0; i++) {
            data                  = &mbuf[1][i];
            pktmbuf_udata64(data) = ((uint64_t)tm->test_node[1].idx << 32) | i;
            if ((i + 1) == obj_node0)
                pktmbuf_udata64(data) |= (1UL << 16);
            if (second_pass)
                pktmbuf_udata64(data) |= (1UL << 17);
        }
        cne_node_enqueue(graph, node, 0, (void **)&mbuf_p[1][0], obj_node0);

        obj_node1 = nb_objs - obj_node0;
        for (i = 0; i < obj_node1; i++) {
            data                  = &mbuf[1][obj_node0 + i];
            pktmbuf_udata64(data) = ((uint64_t)tm->test_node[2].idx << 32) | i;
            if ((i + 1) == obj_node1)
                pktmbuf_udata64(data) |= (1UL << 16);
            if (second_pass)
                pktmbuf_udata64(data) |= (1UL << 17);
        }
        cne_node_enqueue(graph, node, 1, (void **)&mbuf_p[1][obj_node0], obj_node1);

    } else if (*(uint32_t *)node->ctx == tm->test_node[1].idx)
        test_node1_worker(graph, node, objs, nb_objs);
    else if (*(uint32_t *)node->ctx == tm->test_node[2].idx)
        test_node2_worker(graph, node, objs, nb_objs);
    else if (*(uint32_t *)node->ctx == tm->test_node[3].idx)
        test_node3_worker(graph, node, objs, nb_objs);
    else
        tst_error("Unexpected node context");

end:
    return nb_objs;
}

uint16_t
test_node1_worker(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    test_main_t *tm     = &test_main;
    uint8_t second_pass = 0;
    uint32_t obj_node0  = 0;
    pktmbuf_t *data;
    uint32_t count = 0;
    uint32_t i;

    obj_stats[2] += nb_objs;
    fn_calls[2] += 1;
    for (i = 0; i < nb_objs; i++) {
        data = (pktmbuf_t *)objs[i];
        if ((pktmbuf_udata64(data) >> 32) != tm->test_node[1].idx) {
            tst_error("Data idx miss match at node 1, expected = %u got = %u", tm->test_node[1].idx,
                      (uint32_t)(pktmbuf_udata64(data) >> 32));
            goto end;
        }

        if ((pktmbuf_udata64(data) & 0xffff) != (i - count)) {
            tst_error("Expected buff count miss match at node 1");
            goto end;
        }

        if (pktmbuf_udata64(data) & (0x1 << 16))
            count = i + 1;
        if (pktmbuf_udata64(data) & (0x1 << 17))
            second_pass = 1;
    }

    if (count != i) {
        tst_error("Count mismatch at node 1");
        goto end;
    }

    obj_node0 = nb_objs;
    for (i = 0; i < obj_node0; i++) {
        data                  = &mbuf[2][i];
        pktmbuf_udata64(data) = ((uint64_t)tm->test_node[2].idx << 32) | i;
        if ((i + 1) == obj_node0)
            pktmbuf_udata64(data) |= (1UL << 16);
        if (second_pass)
            pktmbuf_udata64(data) |= (1UL << 17);
    }
    cne_node_enqueue(graph, node, 0, (void **)&mbuf_p[2][0], obj_node0);

end:
    return nb_objs;
}

uint16_t
test_node2_worker(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    test_main_t *tm     = &test_main;
    uint8_t second_pass = 0;
    pktmbuf_t *data;
    uint32_t count = 0;
    uint32_t obj_node0;
    uint32_t i;

    obj_stats[3] += nb_objs;
    fn_calls[3] += 1;
    for (i = 0; i < nb_objs; i++) {
        data = (pktmbuf_t *)objs[i];
        if ((pktmbuf_udata64(data) >> 32) != tm->test_node[2].idx) {
            tst_error("Data idx miss match at node 2, expected = %u got = %u", tm->test_node[2].idx,
                      (uint32_t)(pktmbuf_udata64(data) >> 32));
            goto end;
        }

        if ((pktmbuf_udata64(data) & 0xffff) != (i - count)) {
            tst_error("Expected buff count miss match at node 2");
            goto end;
        }

        if (pktmbuf_udata64(data) & (0x1 << 16))
            count = i + 1;
        if (pktmbuf_udata64(data) & (0x1 << 17))
            second_pass = 1;
    }

    if (count != i) {
        tst_error("Count mismatch at node 2");
        goto end;
    }

    if (!second_pass) {
        obj_node0 = nb_objs;
        for (i = 0; i < obj_node0; i++) {
            data                  = &mbuf[3][i];
            pktmbuf_udata64(data) = ((uint64_t)tm->test_node[3].idx << 32) | i;
            if ((i + 1) == obj_node0)
                pktmbuf_udata64(data) |= (1UL << 16);
        }
        cne_node_enqueue(graph, node, 0, (void **)&mbuf_p[3][0], obj_node0);
    }

end:
    return nb_objs;
}

uint16_t
test_node3_worker(struct cne_graph *graph, struct cne_node *node, void **objs, uint16_t nb_objs)
{
    test_main_t *tm     = &test_main;
    uint8_t second_pass = 0;
    pktmbuf_t *data;
    uint32_t count = 0;
    uint32_t obj_node0;
    uint32_t i;

    obj_stats[4] += nb_objs;
    fn_calls[4] += 1;
    for (i = 0; i < nb_objs; i++) {
        data = (pktmbuf_t *)objs[i];
        if ((pktmbuf_udata64(data) >> 32) != tm->test_node[3].idx) {
            tst_error("Data idx miss match at node 3, expected = %u got = %u", tm->test_node[3].idx,
                      (uint32_t)(pktmbuf_udata64(data) >> 32));
            goto end;
        }

        if ((pktmbuf_udata64(data) & 0xffff) != (i - count)) {
            tst_error("Expected buff count miss match at node 3");
            goto end;
        }

        if (pktmbuf_udata64(data) & (0x1 << 16))
            count = i + 1;
        if (pktmbuf_udata64(data) & (0x1 << 17))
            second_pass = 1;
    }

    if (count != i) {
        tst_error("Count mismatch at node 3");
        goto end;
    }

    if (second_pass) {
        tst_error("Unexpected buffers are at node 3");
        goto end;
    } else {
        obj_node0 = nb_objs * 2;
        for (i = 0; i < obj_node0; i++) {
            data                  = &mbuf[4][i];
            pktmbuf_udata64(data) = ((uint64_t)tm->test_node[0].idx << 32) | i;
            pktmbuf_udata64(data) |= (1UL << 17);
            if ((i + 1) == obj_node0)
                pktmbuf_udata64(data) |= (1UL << 16);
        }
        cne_node_enqueue(graph, node, 0, (void **)&mbuf_p[4][0], obj_node0);
    }

end:
    return nb_objs;
}

static int
test_lookup_functions(void)
{
    test_main_t *tm = &test_main;
    int i;

    /* Verify the name with ID */
    for (i = 1; i < MAX_NODES; i++) {
        char *name = cne_node_id_to_name(tm->test_node[i].idx);
        if (!name)
            return -1;

        if (strcmp(name, node_names[i]) != 0) {
            tst_error("Test node name verify by ID = %d failed Expected = %s, got %s", i,
                      node_names[i], name);
            return -1;
        }
    }

    /* Verify by name */
    for (i = 1; i < MAX_NODES; i++) {
        uint32_t idx = cne_node_from_name(node_names[i]);
        if (idx != tm->test_node[i].idx) {
            tst_error("Test node ID verify by name = %s failed Expected = %d, got %d",
                      node_names[i], tm->test_node[i].idx, idx);
            return -1;
        }
    }

    /* Verify edge count */
    for (i = 1; i < MAX_NODES; i++) {
        uint32_t count = cne_node_edge_count(tm->test_node[i].idx);
        if (count != tm->test_node[i].node.nb_edges) {
            tst_error("Test number of edges for node = %s failed Expected = %d, got = %d",
                      tm->test_node[i].node.name, tm->test_node[i].node.nb_edges, count);
            return -1;
        }
    }

    /* Verify edge names */
    for (i = 1; i < MAX_NODES; i++) {
        uint32_t j, count;
        char **next_edges;

        count = cne_node_edge_get(tm->test_node[i].idx, NULL);
        if (count != tm->test_node[i].node.nb_edges * sizeof(char *)) {
            tst_error("Test number of edge count for node = %s failed Expected = %d, got = %d",
                      tm->test_node[i].node.name, tm->test_node[i].node.nb_edges, count);
            return -1;
        }
        next_edges = malloc(count);
        if (!next_edges) {
            tst_error("Malloc of next edges failed");
            return -1;
        }
        count = cne_node_edge_get(tm->test_node[i].idx, next_edges);
        if (count != tm->test_node[i].node.nb_edges) {
            tst_error("Test number of edges for node = %s failed Expected = %d, got %d",
                      tm->test_node[i].node.name, tm->test_node[i].node.nb_edges, count);
            free(next_edges);
            return -1;
        }

        for (j = 0; j < count; j++) {
            if (strcmp(next_edges[j], tm->test_node[i].node.next_nodes[j]) != 0) {
                tst_error("Edge name miss match, expected = %s got = %s",
                          tm->test_node[i].node.next_nodes[j], next_edges[j]);
                free(next_edges);
                return -1;
            }
        }
        free(next_edges);
    }

    return 0;
}

static int
test_node_clone(void)
{
    test_main_t *tm = &test_main;
    uint32_t node_id, dummy_id;
    int i;

    node_id              = cne_node_from_name("test_node00");
    tm->test_node[0].idx = node_id;

    /* Clone with same name, should fail */
    dummy_id = cne_node_clone(node_id, "test_node00");
    if (!cne_node_is_invalid(dummy_id)) {
        tst_error("Got valid id when clone with same name, Expecting fail");
        return -1;
    }

    for (i = 1; i < MAX_NODES; i++) {
        tm->test_node[i].idx = cne_node_clone(node_id, tm->test_node[i].node.name);
        if (cne_node_is_invalid(tm->test_node[i].idx)) {
            tst_error("Got invalid node id");
            return -1;
        }
    }

    /* Clone from cloned node should fail */
    dummy_id = cne_node_clone(tm->test_node[1].idx, "dummy_node");
    if (!cne_node_is_invalid(dummy_id)) {
        tst_error("Got valid node id when cloning from cloned node, expected fail");
        return -1;
    }

    return 0;
}

static int
test_update_edges(void)
{
    test_main_t *tm = &test_main;
    uint32_t node_id;
    uint16_t count;
    int i;

    node_id = cne_node_from_name("test_node00");
    count   = cne_node_edge_update(node_id, 0, tm->test_node[0].node.next_nodes,
                                   tm->test_node[0].node.nb_edges);
    if (count != tm->test_node[0].node.nb_edges) {
        tst_error("Update edges failed expected: %d got = %d", tm->test_node[0].node.nb_edges,
                  count);
        return -1;
    }

    for (i = 1; i < MAX_NODES; i++) {
        count = cne_node_edge_update(tm->test_node[i].idx, 0, tm->test_node[i].node.next_nodes,
                                     tm->test_node[i].node.nb_edges);
        if (count != tm->test_node[i].node.nb_edges) {
            tst_error("Update edges failed expected: %d got = %d", tm->test_node[i].node.nb_edges,
                      count);
            return -1;
        }

        count = cne_node_edge_shrink(tm->test_node[i].idx, tm->test_node[i].node.nb_edges);
        if (count != tm->test_node[i].node.nb_edges) {
            tst_error("Shrink edges failed");
            return -1;
        }
    }

    return 0;
}

static int
test_create_graph(void)
{
    // clang-format off
    static const char *node_patterns_dummy[] = {
        "test_node_source1",
        "test_node00",
        "test_node00-test_node11",
        "test_node00-test_node22",
        "test_node00-test_node33",
        "test_node00-dummy_node",
        NULL
    };
    // clang-format on
    uint32_t dummy_node_id;
    uint32_t node_id;

    node_id       = cne_node_from_name("test_node00");
    dummy_node_id = cne_node_clone(node_id, "dummy_node");
    if (cne_node_is_invalid(dummy_node_id)) {
        tst_error("Got invalid node id");
        return -1;
    }

    graph_id = cne_graph_create("worker0", node_patterns_dummy);
    if (graph_id != CNE_GRAPH_ID_INVALID) {
        tst_error("Graph creation success with isolated node, expected graph creation fail");
        return -1;
    }

    graph_id = cne_graph_create("worker0", node_patterns);
    if (graph_id == CNE_GRAPH_ID_INVALID) {
        tst_error("Graph creation failed with error = %d", errno);
        return -1;
    }
    return 0;
}

static int
test_graph_walk(void)
{
    struct cne_graph *graph = cne_graph_lookup("worker0");
    int i;

    if (!graph) {
        tst_error("Graph lookup failed");
        return -1;
    }

    for (i = 0; i < 5; i++)
        cne_graph_walk(graph);
    return 0;
}

static int
test_graph_lookup_functions(void)
{
    test_main_t *tm = &test_main;
    struct cne_node *node;
    int i;

    for (i = 0; i < MAX_NODES; i++) {
        node = cne_graph_node_get(graph_id, tm->test_node[i].idx);
        if (!node) {
            tst_error("cne_graph_node_get, failed for node = %d", tm->test_node[i].idx);
            return -1;
        }

        if (tm->test_node[i].idx != node->id) {
            tst_error("Node id didn't match, expected = %d got = %d", tm->test_node[i].idx,
                      node->id);
            return 0;
        }

        if (strncmp(node->name, node_names[i], CNE_NODE_NAMESIZE)) {
            tst_error("Node name didn't match, expected = %s got %s", node_names[i], node->name);
            return -1;
        }
    }

    for (i = 0; i < MAX_NODES; i++) {
        node = cne_graph_node_get_by_name("worker0", node_names[i]);
        if (!node) {
            tst_error("cne_graph_node_get, failed for node = %d", tm->test_node[i].idx);
            return -1;
        }

        if (tm->test_node[i].idx != node->id) {
            tst_error("Node id didn't match, expected = %d got = %d", tm->test_node[i].idx,
                      node->id);
            return 0;
        }

        if (strncmp(node->name, node_names[i], CNE_NODE_NAMESIZE)) {
            tst_error("Node name didn't match, expected = %s got %s", node_names[i], node->name);
            return -1;
        }
    }

    return 0;
}

static int
graph_cluster_stats_cb_t(bool is_first, bool is_last, const struct cne_graph_cluster_node_stats *st)
{
    int i;

    CNE_SET_USED(is_first);
    CNE_SET_USED(is_last);

    for (i = 0; i < MAX_NODES + 1; i++) {
        cne_node_t id = cne_node_from_name(node_patterns[i]);
        if (id == st->id) {
            if (obj_stats[i] != st->objs) {
                tst_error("Obj count miss match for node = %s expected = %" PRId64 ", got=%" PRId64,
                          node_patterns[i], obj_stats[i], st->objs);
                return -1;
            }

            if (fn_calls[i] != st->calls) {
                tst_error("Func call miss match for node = %s expected = %" PRId64
                          ", got = %" PRId64,
                          node_patterns[i], fn_calls[i], st->calls);
                return -1;
            }
        }
    }
    return 0;
}

static int
test_print_stats(void)
{
    struct cne_graph_cluster_stats_param s_param;
    struct cne_graph_cluster_stats *stats;
    const char *pattern = "worker0";

    if (!cne_graph_has_stats_feature())
        return 0;

    /* Prepare stats object */
    memset(&s_param, 0, sizeof(s_param));
    s_param.graph_patterns    = &pattern;
    s_param.nb_graph_patterns = 1;
    s_param.fn                = graph_cluster_stats_cb_t;

    stats = cne_graph_cluster_stats_create(&s_param);
    if (stats == NULL) {
        tst_info("Unable to get stats");
        return -1;
    }
    /* Clear screen and move to top left */
    cne_graph_cluster_stats_get(stats, 0);
    cne_graph_cluster_stats_destroy(stats);

    return 0;
}

static int
graph_setup(void)
{
    int i, j;

    for (i = 0; i <= MAX_NODES; i++) {
        for (j = 0; j < MBUFF_SIZE; j++)
            mbuf_p[i][j] = &mbuf[i][j];
    }
    if (test_node_clone()) {
        tst_error("test_node_clone: fail");
        return -1;
    }
    tst_info("test_node_clone: pass");

    return 0;
}

static void
graph_teardown(void)
{
    int id;

    id = cne_graph_destroy(cne_graph_from_name("worker0"));
    if (id)
        tst_error("Graph Destroy failed");
}

// clang-format off
static struct unit_test_suite graph_testsuite = {
    .suite_name = "Graph library test suite",
    .setup      = graph_setup,
    .teardown   = graph_teardown,
    .unit_test_cases =
        {
            TEST_CASE(test_update_edges),
            TEST_CASE(test_lookup_functions),
            TEST_CASE(test_create_graph),
            TEST_CASE(test_graph_lookup_functions),
            TEST_CASE(test_graph_walk),
            TEST_CASE(test_print_stats),
            TEST_CASES_END(), /**< NULL terminate unit test array */
        },
};
// clang-format on

static int
graph_autotest_fn(void)
{
    return unit_test_suite_runner(&graph_testsuite);
}

int
graph_main(int argc, char **argv)
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

    tst = tst_start("Graph");

    if (graph_autotest_fn() < 0)
        goto leave;

    tst_ok("%s tests passed", tst->name);
    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_error("%s tests failed", tst->name);
    tst_end(tst, TST_FAILED);
    return -1;
}
