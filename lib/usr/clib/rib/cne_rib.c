/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2023 Intel Corporation
 */

#include <stdbool.h>           // for bool
#include <stdint.h>            // for uint32_t, uint8_t, uint64_t
#include <mempool.h>           // for mempool_cfg, mempool_destroy, mem...
#include <cne_rwlock.h>        // for cne_rwlock_write_unlock, cne_rwlo...
#include <cne_mmap.h>          // for mmap_free, mmap_addr, mmap_alloc
#include <cne_rib.h>
#include <bsd/string.h>        // for strlcpy

#include "cne_branch_prediction.h"        // for unlikely
#include "cne_common.h"                   // for CNE_MIN
#include "cne_log.h"                      // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_NU...

static cne_rwlock_t __rib_lock;

#define CNE_RIB_VALID_NODE 1
/* Maximum depth value possible for IPv4 RIB. */
#define RIB_MAXDEPTH 32
/* Maximum length of a RIB name. */
#define CNE_RIB_NAMESIZE 64

struct cne_rib_node {
    struct cne_rib_node *left;
    struct cne_rib_node *right;
    struct cne_rib_node *parent;
    uint32_t ip;
    uint8_t depth;
    uint8_t flag;
    uint64_t nh;
    __extension__ uint64_t ext[0];
};

struct cne_rib {
    char name[CNE_RIB_NAMESIZE];
    struct cne_rib_node *tree;
    mmap_t *mm;
    mempool_t *node_pool;
    uint32_t cur_nodes;
    uint32_t cur_routes;
    uint32_t max_nodes;
};

static inline bool
is_valid_node(struct cne_rib_node *node)
{
    return (node->flag & CNE_RIB_VALID_NODE) == CNE_RIB_VALID_NODE;
}

static inline bool
is_right_node(struct cne_rib_node *node)
{
    return node->parent->right == node;
}

/*
 * Check if ip1 is covered by ip2/depth prefix
 */
static inline bool
is_covered(uint32_t ip1, uint32_t ip2, uint8_t depth)
{
    return ((ip1 ^ ip2) & cne_rib_depth_to_mask(depth)) == 0;
}

static inline struct cne_rib_node *
get_nxt_node(struct cne_rib_node *node, uint32_t ip)
{
    return (ip & (1 << (31 - node->depth))) ? node->right : node->left;
}

static struct cne_rib_node *
node_alloc(struct cne_rib *rib)
{
    struct cne_rib_node *ent;

    if (unlikely(mempool_get(rib->node_pool, (void *)&ent) < 0))
        return NULL;
    ++rib->cur_nodes;
    return ent;
}

static void
node_free(struct cne_rib *rib, struct cne_rib_node *ent)
{
    --rib->cur_nodes;
    mempool_put(rib->node_pool, ent);
}

struct cne_rib_node *
cne_rib_lookup(struct cne_rib *rib, uint32_t ip)
{
    struct cne_rib_node *cur, *prev = NULL;

    if (rib == NULL)
        return NULL;

    cur = rib->tree;
    while ((cur != NULL) && is_covered(ip, cur->ip, cur->depth)) {
        if (is_valid_node(cur))
            prev = cur;
        cur = get_nxt_node(cur, ip);
    }
    return prev;
}

struct cne_rib_node *
cne_rib_lookup_parent(struct cne_rib_node *ent)
{
    struct cne_rib_node *tmp;

    if (ent == NULL)
        return NULL;
    tmp = ent->parent;
    while ((tmp != NULL) && !is_valid_node(tmp))
        tmp = tmp->parent;
    return tmp;
}

static struct cne_rib_node *
__rib_lookup_exact(struct cne_rib *rib, uint32_t ip, uint8_t depth)
{
    struct cne_rib_node *cur;

    cur = rib->tree;
    while (cur != NULL) {
        if ((cur->ip == ip) && (cur->depth == depth) && is_valid_node(cur))
            return cur;
        if ((cur->depth > depth) || !is_covered(ip, cur->ip, cur->depth))
            break;
        cur = get_nxt_node(cur, ip);
    }
    return NULL;
}

struct cne_rib_node *
cne_rib_lookup_exact(struct cne_rib *rib, uint32_t ip, uint8_t depth)
{
    if ((rib == NULL) || (depth > RIB_MAXDEPTH))
        return NULL;
    ip &= cne_rib_depth_to_mask(depth);

    return __rib_lookup_exact(rib, ip, depth);
}

/*
 *  Traverses on subtree and retrieves more specific routes
 *  for a given in args ip/depth prefix
 *  last = NULL means the first invocation
 */
struct cne_rib_node *
cne_rib_get_nxt(struct cne_rib *rib, uint32_t ip, uint8_t depth, struct cne_rib_node *last,
                int flag)
{
    struct cne_rib_node *tmp, *prev = NULL;

    if ((rib == NULL) || (depth > RIB_MAXDEPTH))
        return NULL;

    if (last == NULL) {
        tmp = rib->tree;
        while ((tmp) && (tmp->depth < depth))
            tmp = get_nxt_node(tmp, ip);
    } else {
        tmp = last;
        while ((tmp->parent != NULL) && (is_right_node(tmp) || (tmp->parent->right == NULL))) {
            tmp = tmp->parent;
            if (is_valid_node(tmp) && (is_covered(tmp->ip, ip, depth) && (tmp->depth > depth)))
                return tmp;
        }
        tmp = (tmp->parent) ? tmp->parent->right : NULL;
    }
    while (tmp) {
        if (is_valid_node(tmp) && (is_covered(tmp->ip, ip, depth) && (tmp->depth > depth))) {
            prev = tmp;
            if (flag == CNE_RIB_GET_NXT_COVER)
                return prev;
        }
        tmp = (tmp->left) ? tmp->left : tmp->right;
    }
    return prev;
}

void
cne_rib_remove(struct cne_rib *rib, uint32_t ip, uint8_t depth)
{
    struct cne_rib_node *cur, *prev, *child;

    cur = cne_rib_lookup_exact(rib, ip, depth);
    if (cur == NULL)
        return;

    --rib->cur_routes;
    cur->flag &= ~CNE_RIB_VALID_NODE;
    while (!is_valid_node(cur)) {
        if ((cur->left != NULL) && (cur->right != NULL))
            return;
        child = (cur->left == NULL) ? cur->right : cur->left;
        if (child != NULL)
            child->parent = cur->parent;
        if (cur->parent == NULL) {
            rib->tree = child;
            node_free(rib, cur);
            return;
        }
        if (cur->parent->left == cur)
            cur->parent->left = child;
        else
            cur->parent->right = child;
        prev = cur;
        cur  = cur->parent;
        node_free(rib, prev);
    }
}

struct cne_rib_node *
cne_rib_insert(struct cne_rib *rib, uint32_t ip, uint8_t depth)
{
    struct cne_rib_node **tmp;
    struct cne_rib_node *prev        = NULL;
    struct cne_rib_node *new_node    = NULL;
    struct cne_rib_node *common_node = NULL;
    int d                            = 0;
    uint32_t common_prefix;
    uint8_t common_depth;

    if ((rib == NULL) || (depth > RIB_MAXDEPTH))
        return NULL;

    tmp = &rib->tree;
    ip &= cne_rib_depth_to_mask(depth);
    new_node = __rib_lookup_exact(rib, ip, depth);
    if (new_node != NULL)
        return NULL;

    new_node = node_alloc(rib);
    if (new_node == NULL)
        return NULL;
    new_node->left   = NULL;
    new_node->right  = NULL;
    new_node->parent = NULL;
    new_node->ip     = ip;
    new_node->depth  = depth;
    new_node->flag   = CNE_RIB_VALID_NODE;

    /* traverse down the tree to find matching node or closest matching */
    while (1) {
        /* insert as the last node in the branch */
        if (*tmp == NULL) {
            *tmp             = new_node;
            new_node->parent = prev;
            ++rib->cur_routes;
            return *tmp;
        }
        /*
         * Intermediate node found.
         * Previous cne_rib_lookup_exact() returned NULL
         * but node with proper search criteria is found.
         * Validate intermediate node and return.
         */
        if ((ip == (*tmp)->ip) && (depth == (*tmp)->depth)) {
            node_free(rib, new_node);
            (*tmp)->flag |= CNE_RIB_VALID_NODE;
            ++rib->cur_routes;
            return *tmp;
        }
        d = (*tmp)->depth;
        if ((d >= depth) || !is_covered(ip, (*tmp)->ip, d))
            break;
        prev = *tmp;
        tmp  = (ip & (1 << (31 - d))) ? &(*tmp)->right : &(*tmp)->left;
    }
    /* closest node found, new_node should be inserted in the middle */
    common_depth  = CNE_MIN(depth, (*tmp)->depth);
    common_prefix = ip ^ (*tmp)->ip;
    d             = (common_prefix == 0) ? 32 : __builtin_clz(common_prefix);

    common_depth  = CNE_MIN(d, common_depth);
    common_prefix = ip & cne_rib_depth_to_mask(common_depth);
    if ((common_prefix == ip) && (common_depth == depth)) {
        /* insert as a parent */
        if ((*tmp)->ip & (1 << (31 - depth)))
            new_node->right = *tmp;
        else
            new_node->left = *tmp;
        new_node->parent = (*tmp)->parent;
        (*tmp)->parent   = new_node;
        *tmp             = new_node;
    } else {
        /* create intermediate node */
        common_node = node_alloc(rib);
        if (common_node == NULL) {
            node_free(rib, new_node);
            return NULL;
        }
        common_node->ip     = common_prefix;
        common_node->depth  = common_depth;
        common_node->flag   = 0;
        common_node->parent = (*tmp)->parent;
        new_node->parent    = common_node;
        (*tmp)->parent      = common_node;
        if ((new_node->ip & (1 << (31 - common_depth))) == 0) {
            common_node->left  = new_node;
            common_node->right = *tmp;
        } else {
            common_node->left  = *tmp;
            common_node->right = new_node;
        }
        *tmp = common_node;
    }
    ++rib->cur_routes;
    return new_node;
}

int
cne_rib_get_ip(const struct cne_rib_node *node, uint32_t *ip)
{
    if ((node == NULL) || (ip == NULL))
        return -1;
    *ip = node->ip;
    return 0;
}

int
cne_rib_get_depth(const struct cne_rib_node *node, uint8_t *depth)
{
    if ((node == NULL) || (depth == NULL))
        return -1;
    *depth = node->depth;
    return 0;
}

void *
cne_rib_get_ext(struct cne_rib_node *node)
{
    return (node == NULL) ? NULL : &node->ext[0];
}

int
cne_rib_get_nh(const struct cne_rib_node *node, uint64_t *nh)
{
    if ((node == NULL) || (nh == NULL))
        return -1;
    *nh = node->nh;
    return 0;
}

int
cne_rib_set_nh(struct cne_rib_node *node, uint64_t nh)
{
    if (node == NULL)
        return -1;
    node->nh = nh;
    return 0;
}

struct cne_rib *
cne_rib_create(const char *name, const struct cne_rib_conf *conf)
{
    struct cne_rib *rib    = NULL;
    mmap_t *mm             = NULL;
    struct mempool_cfg cfg = {0};
    mempool_t *node_pool;

    /* Check user arguments. */
    if (name == NULL || conf == NULL || conf->max_nodes <= 0)
        return NULL;

    cfg.objcnt = conf->max_nodes;
    cfg.objsz  = sizeof(struct cne_rib_node) + conf->ext_sz;

    mm = mmap_alloc(cfg.objcnt, cfg.objsz, MMAP_HUGEPAGE_DEFAULT);
    if (!mm)
        CNE_NULL_RET("Failed to mmap() memory\n");
    cfg.addr = mmap_addr(mm);

    cne_rwlock_write_lock(&__rib_lock);

    node_pool = mempool_create(&cfg);

    if (node_pool == NULL)
        CNE_ERR_GOTO(exit, "Can not allocate mempool for %s\n", name);

    /* Allocate memory to store the RIB data structures. */
    rib = calloc(1, sizeof(struct cne_rib));
    if (rib == NULL)
        CNE_ERR_GOTO(exit, "RIB %s memory allocation failed\n", name);

    rib->mm = mm;
    strlcpy(rib->name, name, sizeof(rib->name));
    rib->tree      = NULL;
    rib->max_nodes = conf->max_nodes;
    rib->node_pool = node_pool;

    cne_rwlock_write_unlock(&__rib_lock);

    return rib;

exit:
    cne_rwlock_write_unlock(&__rib_lock);
    mempool_destroy(node_pool);
    mmap_free(mm);

    return NULL;
}

void
cne_rib_free(struct cne_rib *rib)
{
    struct cne_rib_node *tmp = NULL;

    if (rib == NULL)
        return;

    while ((tmp = cne_rib_get_nxt(rib, 0, 0, tmp, CNE_RIB_GET_NXT_ALL)) != NULL)
        cne_rib_remove(rib, tmp->ip, tmp->depth);

    mempool_destroy(rib->node_pool);
    mmap_free(rib->mm);
    free(rib);
}
