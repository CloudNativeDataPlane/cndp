/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#include <stdbool.h>           // for bool, true, false
#include <stdio.h>             // for NULL, FILE, size_t
#include <string.h>            // for strncmp
#include <cne_common.h>        // for CNE_MAX, CNE_BUILD_BUG_ON, CNE_CACHE_L
#include <cne_log.h>           // for CNE_ASSERT
#include <bsd/string.h>        // for strlcpy
#include <errno.h>             // for errno, E2BIG, ENOMEM, EEXIST, EINVAL
#include <stddef.h>            // for offsetof
#include <stdint.h>            // for int16_t, uint16_t
#include <stdlib.h>            // for calloc, free, realloc
#include <sys/queue.h>         // for STAILQ_FOREACH, STAILQ_HEAD_INITIALIZER
#include <sys/types.h>         // for ssize_t

#include "graph_private.h"           // for node, node::(anonymous), graph_spinloc
#include "cne_graph.h"               // for cne_node_register, cne_node_t, cne_edge_t
#include "cne_graph_worker.h"        // for cne_node

static struct node_head node_list = STAILQ_HEAD_INITIALIZER(node_list);
static cne_node_t node_id;

#define NODE_ID_CHECK(id) ID_CHECK(id, node_id)

/* Private functions */

struct node_head *
node_list_head_get(void)
{
    return &node_list;
}

struct node *
node_from_name(const char *name)
{
    struct node *node;

    STAILQ_FOREACH (node, &node_list, next)
        if (strncmp(node->name, name, CNE_NODE_NAMESIZE) == 0)
            return node;

    return NULL;
}

static bool
node_has_duplicate_entry(const char *name)
{
    struct node *node;

    /* Is duplicate name registered */
    STAILQ_FOREACH (node, &node_list, next) {
        if (strncmp(node->name, name, CNE_NODE_NAMESIZE) == 0) {
            errno = EEXIST;
            return 1;
        }
    }

    return 0;
}

/* Public functions */

cne_node_t
__cne_node_register(const struct cne_node_register *reg)
{
    struct node *node;
    cne_edge_t i;
    size_t sz;

    /* Limit Node specific metadata to one cacheline on 64B CL machine */
    CNE_BUILD_BUG_ON((offsetof(struct cne_node, nodes) - offsetof(struct cne_node, ctx)) !=
                     CNE_CACHE_LINE_MIN_SIZE);

    graph_spinlock_lock();

    /* Check sanity */
    if (reg == NULL || reg->process == NULL) {
        errno = EINVAL;
        CNE_ERR_GOTO(fail, "Invalid register pointer\n");
    }

    /* Check for duplicate name */
    if (node_has_duplicate_entry(reg->name))
        CNE_ERR_GOTO(fail, "Duplicate node %s\n", reg->name);

    sz   = sizeof(struct node) + (reg->nb_edges * CNE_NODE_NAMESIZE);
    node = calloc(1, sz);
    if (node == NULL) {
        errno = ENOMEM;
        CNE_ERR_GOTO(fail, "Failed to allocate memory\n");
    }

    /* Initialize the node */
    if (strlcpy(node->name, reg->name, CNE_NODE_NAMESIZE) == 0) {
        errno = E2BIG;
        CNE_ERR_GOTO(free, "Node name %s too big\n", reg->name);
    }
    node->flags     = reg->flags;
    node->process   = reg->process;
    node->init      = reg->init;
    node->fini      = reg->fini;
    node->nb_edges  = reg->nb_edges;
    node->parent_id = reg->parent_id;
    for (i = 0; i < reg->nb_edges; i++) {
        if (strlcpy(node->next_nodes[i], reg->next_nodes[i], CNE_NODE_NAMESIZE) == 0) {
            errno = E2BIG;
            goto free;
        }
    }

    node->id = node_id++;

    CNE_DEBUG("Register %3d '%-16s' with %u edges 0x%04lx flags\n", node->id, reg->name,
              reg->nb_edges, reg->flags);

    /* Add the node at tail */
    STAILQ_INSERT_TAIL(&node_list, node, next);
    graph_spinlock_unlock();

    return node->id;
free:
    free(node);
fail:
    graph_spinlock_unlock();
    return CNE_NODE_ID_INVALID;
}

static int
clone_name(struct cne_node_register *reg, struct node *node, const char *name)
{
    ssize_t sz, rc;

#define SZ CNE_NODE_NAMESIZE
    rc = strlcpy(reg->name, node->name, SZ);
    if (rc < 0)
        goto fail;
    sz = rc;
    rc = strlcpy(reg->name + sz, "-", CNE_MAX((int16_t)(SZ - sz), 0));
    if (rc < 0)
        goto fail;
    sz += rc;
    sz = strlcpy(reg->name + sz, name, CNE_MAX((int16_t)(SZ - sz), 0));
    if (sz < 0)
        goto fail;

    return 0;
fail:
    errno = E2BIG;
    return -errno;
}

static cne_node_t
node_clone(struct node *node, const char *name)
{
    cne_node_t rc = CNE_NODE_ID_INVALID;
    struct cne_node_register *reg;
    cne_edge_t i;

    /* Don't allow to clone a node from a cloned node */
    if (node->parent_id != CNE_NODE_ID_INVALID) {
        errno = EEXIST;
        goto fail;
    }

    /* Check for duplicate name */
    if (node_has_duplicate_entry(name))
        goto fail;

    reg = calloc(1, sizeof(*reg) + (sizeof(char *) * node->nb_edges));
    if (reg == NULL) {
        errno = ENOMEM;
        goto fail;
    }

    /* Clone the source node */
    reg->flags     = node->flags;
    reg->process   = node->process;
    reg->init      = node->init;
    reg->fini      = node->fini;
    reg->nb_edges  = node->nb_edges;
    reg->parent_id = node->id;

    for (i = 0; i < node->nb_edges; i++)
        reg->next_nodes[i] = node->next_nodes[i];

    /* Naming ceremony of the new node. name is node->name + "-" + name */
    if (clone_name(reg, node, name))
        goto free;

    rc = __cne_node_register(reg);

free:
    free(reg);
fail:
    return rc;
}

cne_node_t
cne_node_clone(cne_node_t id, const char *name)
{
    struct node *node;

    NODE_ID_CHECK(id);

    STAILQ_FOREACH (node, &node_list, next)
        if (node->id == id)
            return node_clone(node, name);

fail:
    return CNE_NODE_ID_INVALID;
}

cne_node_t
cne_node_from_name(const char *name)
{
    struct node *node;

    STAILQ_FOREACH (node, &node_list, next)
        if (strncmp(node->name, name, CNE_NODE_NAMESIZE) == 0)
            return node->id;

    return CNE_NODE_ID_INVALID;
}

char *
cne_node_id_to_name(cne_node_t id)
{
    struct node *node;

    NODE_ID_CHECK(id);
    STAILQ_FOREACH (node, &node_list, next)
        if (node->id == id)
            return node->name;

fail:
    return NULL;
}

cne_edge_t
cne_node_edge_count(cne_node_t id)
{
    struct node *node;

    NODE_ID_CHECK(id);
    STAILQ_FOREACH (node, &node_list, next)
        if (node->id == id)
            return node->nb_edges;

fail:
    return CNE_EDGE_ID_INVALID;
}

static cne_edge_t
edge_update(struct node *node, struct node *prev, cne_edge_t from, const char **next_nodes,
            cne_edge_t nb_edges)
{
    cne_edge_t i, max_edges, count = 0;
    struct node *new_node;
    bool need_realloc;
    size_t sz;

    if (from == CNE_EDGE_ID_INVALID)
        from = node->nb_edges;

    /* Don't create hole in next_nodes[] list */
    if (from > node->nb_edges) {
        errno = ENOMEM;
        goto fail;
    }

    /* Remove me from list */
    STAILQ_REMOVE(&node_list, node, node, next);

    /* Allocate the storage space for new node if required */
    max_edges    = from + nb_edges;
    need_realloc = max_edges > node->nb_edges;
    if (need_realloc) {
        sz       = sizeof(struct node) + (max_edges * CNE_NODE_NAMESIZE);
        new_node = realloc(node, sz);
        if (new_node == NULL) {
            errno = ENOMEM;
            goto restore;
        } else
            node = new_node;
    }

    /* Update the new nodes name */
    for (i = from; i < max_edges; i++, count++) {
        if (strlcpy(node->next_nodes[i], next_nodes[count], CNE_NODE_NAMESIZE) == 0) {
            errno = E2BIG;
            goto restore;
        }
    }

restore:
    /* Update the linked list to point new node address in prev node */
    if (prev)
        STAILQ_INSERT_AFTER(&node_list, prev, node, next);
    else
        STAILQ_INSERT_HEAD(&node_list, node, next);

    if (need_realloc)
        node->nb_edges = max_edges;

fail:
    return count;
}

cne_edge_t
cne_node_edge_shrink(cne_node_t id, cne_edge_t size)
{
    cne_edge_t rc = CNE_EDGE_ID_INVALID;
    struct node *node;

    NODE_ID_CHECK(id);
    graph_spinlock_lock();

    STAILQ_FOREACH (node, &node_list, next) {
        if (node->id == id) {
            if (node->nb_edges < size) {
                errno = E2BIG;
                goto fail;
            }
            node->nb_edges = size;
            rc             = size;
            break;
        }
    }

fail:
    graph_spinlock_unlock();
    return rc;
}

cne_edge_t
cne_node_edge_update(cne_node_t id, cne_edge_t from, const char **next_nodes, uint16_t nb_edges)
{
    cne_edge_t rc = CNE_EDGE_ID_INVALID;
    struct node *n, *prev;

    NODE_ID_CHECK(id);
    graph_spinlock_lock();

    prev = NULL;
    STAILQ_FOREACH (n, &node_list, next) {
        if (n->id == id) {
            rc = edge_update(n, prev, from, next_nodes, nb_edges);
            break;
        }
        prev = n;
    }

    graph_spinlock_unlock();
fail:
    return rc;
}

static cne_node_t
node_copy_edges(struct node *node, char *next_nodes[])
{
    cne_edge_t i;

    for (i = 0; i < node->nb_edges; i++)
        next_nodes[i] = node->next_nodes[i];

    return i;
}

cne_node_t
cne_node_edge_get(cne_node_t id, char *next_nodes[])
{
    cne_node_t rc = CNE_NODE_ID_INVALID;
    struct node *node;

    NODE_ID_CHECK(id);
    graph_spinlock_lock();

    STAILQ_FOREACH (node, &node_list, next) {
        if (node->id == id) {
            if (next_nodes == NULL)
                rc = sizeof(char *) * node->nb_edges;
            else
                rc = node_copy_edges(node, next_nodes);
            break;
        }
    }

    graph_spinlock_unlock();
fail:
    return rc;
}

static void
node_scan_dump(FILE *f, cne_node_t id, bool all)
{
    struct node *node;
    bool hdr = true;

    if (!f)
        f = stdout;
    NODE_ID_CHECK(id);

    STAILQ_FOREACH (node, &node_list, next) {
        if (all)
            node_dump(f, node, hdr);
        else if (node->id == id) {
            node_dump(f, node, hdr);
            break;
        }
        hdr = false;
    }

fail:
    return;
}

void
cne_node_dump(FILE *f, cne_node_t id)
{
    node_scan_dump(f, id, false);
}

void
cne_node_list_dump(FILE *f)
{
    node_scan_dump(f, 0, true);
}

cne_node_t
cne_node_max_count(void)
{
    return node_id;
}
