/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <stdbool.h>           // for bool, false, true
#include <stdint.h>            // for uint8_t, uint64_t, uint32_t
#include <mempool.h>           // for mempool_cfg, mempool_destroy, mem...
#include <cne_rwlock.h>        // for cne_rwlock_write_unlock, cne_rwlo...
#include <cne_mmap.h>          // for mmap_free, mmap_addr, mmap_alloc
#include <cne_rib6.h>
#include <bsd/string.h>        // for strlcpy
#include <stdlib.h>            // for NULL, calloc, free

#include "cne_branch_prediction.h"        // for unlikely
#include "cne_common.h"                   // for CNE_MIN
#include "cne_log.h"                      // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_NU...

#define CNE_RIB_VALID_NODE 1
#define RIB6_MAXDEPTH      128
#define CNE_RIB6_NAMESIZE  64 /**< Maximum length of a RIB6 name. */

static cne_rwlock_t __rib6_lock;

struct cne_rib6_node {
    struct cne_rib6_node *left;
    struct cne_rib6_node *right;
    struct cne_rib6_node *parent;
    uint64_t nh;
    uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE];
    uint8_t depth;
    uint8_t flag;
    __extension__ uint64_t ext[0];
};

struct cne_rib6 {
    char name[CNE_RIB6_NAMESIZE];
    struct cne_rib6_node *tree;
    mmap_t *mm;
    mempool_t *node_pool;
    uint32_t cur_nodes;
    uint32_t cur_routes;
    int max_nodes;
};

static inline bool
is_valid_node(struct cne_rib6_node *node)
{
    return (node->flag & CNE_RIB_VALID_NODE) == CNE_RIB_VALID_NODE;
}

static inline bool
is_right_node(struct cne_rib6_node *node)
{
    return node->parent->right == node;
}

/*
 * Check if ip1 is covered by ip2/depth prefix
 */
static inline bool
is_covered(const uint8_t ip1[CNE_RIB6_IPV6_ADDR_SIZE], const uint8_t ip2[CNE_RIB6_IPV6_ADDR_SIZE],
           uint8_t depth)
{
    int i;

    for (i = 0; i < CNE_RIB6_IPV6_ADDR_SIZE; i++)
        if ((ip1[i] ^ ip2[i]) & get_msk_part(depth, i))
            return false;

    return true;
}

static inline int
get_dir(const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE], uint8_t depth)
{
    int i = 0;
    uint8_t p_depth, msk;

    for (p_depth = depth; p_depth >= 8; p_depth -= 8)
        i++;

    msk = 1 << (7 - p_depth);
    return (ip[i] & msk) != 0;
}

static inline struct cne_rib6_node *
get_nxt_node(struct cne_rib6_node *node, const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE])
{
    return (get_dir(ip, node->depth)) ? node->right : node->left;
}

static struct cne_rib6_node *
node_alloc(struct cne_rib6 *rib)
{
    struct cne_rib6_node *ent;

    if (unlikely(mempool_get(rib->node_pool, (void *)&ent) < 0))
        return NULL;

    ++rib->cur_nodes;
    return ent;
}

static void
node_free(struct cne_rib6 *rib, struct cne_rib6_node *ent)
{
    --rib->cur_nodes;
    mempool_put(rib->node_pool, ent);
}

struct cne_rib6_node *
cne_rib6_lookup(struct cne_rib6 *rib, const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE])
{
    struct cne_rib6_node *cur;
    struct cne_rib6_node *prev = NULL;

    if (unlikely(rib == NULL))
        return NULL;
    cur = rib->tree;

    while ((cur != NULL) && is_covered(ip, cur->ip, cur->depth)) {
        if (is_valid_node(cur))
            prev = cur;
        cur = get_nxt_node(cur, ip);
    }
    return prev;
}

struct cne_rib6_node *
cne_rib6_lookup_parent(struct cne_rib6_node *ent)
{
    struct cne_rib6_node *tmp;

    if (ent == NULL)
        return NULL;

    tmp = ent->parent;
    while ((tmp != NULL) && (!is_valid_node(tmp)))
        tmp = tmp->parent;

    return tmp;
}

struct cne_rib6_node *
cne_rib6_lookup_exact(struct cne_rib6 *rib, const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE],
                      uint8_t depth)
{
    struct cne_rib6_node *cur;
    uint8_t tmp_ip[CNE_RIB6_IPV6_ADDR_SIZE];
    int i;

    if ((rib == NULL) || (ip == NULL) || (depth > RIB6_MAXDEPTH))
        return NULL;
    cur = rib->tree;

    for (i = 0; i < CNE_RIB6_IPV6_ADDR_SIZE; i++)
        tmp_ip[i] = ip[i] & get_msk_part(depth, i);

    while (cur != NULL) {
        if (cne_rib6_is_equal(cur->ip, tmp_ip) && (cur->depth == depth) && is_valid_node(cur))
            return cur;

        if (!(is_covered(tmp_ip, cur->ip, cur->depth)) || (cur->depth >= depth))
            break;

        cur = get_nxt_node(cur, tmp_ip);
    }

    return NULL;
}

/*
 *  Traverses on subtree and retrieves more specific routes
 *  for a given in args ip/depth prefix
 *  last = NULL means the first invocation
 */
struct cne_rib6_node *
cne_rib6_get_nxt(struct cne_rib6 *rib, const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE], uint8_t depth,
                 struct cne_rib6_node *last, int flag)
{
    struct cne_rib6_node *tmp, *prev = NULL;
    uint8_t tmp_ip[CNE_RIB6_IPV6_ADDR_SIZE];
    int i;

    if ((rib == NULL) || (ip == NULL) || (depth > RIB6_MAXDEPTH))
        return NULL;

    for (i = 0; i < CNE_RIB6_IPV6_ADDR_SIZE; i++)
        tmp_ip[i] = ip[i] & get_msk_part(depth, i);

    if (last == NULL) {
        tmp = rib->tree;
        while ((tmp) && (tmp->depth < depth))
            tmp = get_nxt_node(tmp, tmp_ip);
    } else {
        tmp = last;
        while ((tmp->parent != NULL) && (is_right_node(tmp) || (tmp->parent->right == NULL))) {
            tmp = tmp->parent;
            if (is_valid_node(tmp) && (is_covered(tmp->ip, tmp_ip, depth) && (tmp->depth > depth)))
                return tmp;
        }
        tmp = (tmp->parent != NULL) ? tmp->parent->right : NULL;
    }
    while (tmp) {
        if (is_valid_node(tmp) && (is_covered(tmp->ip, tmp_ip, depth) && (tmp->depth > depth))) {
            prev = tmp;
            if (flag == CNE_RIB6_GET_NXT_COVER)
                return prev;
        }
        tmp = (tmp->left != NULL) ? tmp->left : tmp->right;
    }
    return prev;
}

void
cne_rib6_remove(struct cne_rib6 *rib, const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE], uint8_t depth)
{
    struct cne_rib6_node *cur, *prev, *child;

    cur = cne_rib6_lookup_exact(rib, ip, depth);
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

struct cne_rib6_node *
cne_rib6_insert(struct cne_rib6 *rib, const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE], uint8_t depth)
{
    struct cne_rib6_node **tmp;
    struct cne_rib6_node *prev        = NULL;
    struct cne_rib6_node *new_node    = NULL;
    struct cne_rib6_node *common_node = NULL;
    uint8_t common_prefix[CNE_RIB6_IPV6_ADDR_SIZE];
    uint8_t tmp_ip[CNE_RIB6_IPV6_ADDR_SIZE];
    int i, d;
    uint8_t common_depth, ip_xor;

    if (unlikely((rib == NULL) || (ip == NULL) || (depth > RIB6_MAXDEPTH)))
        return NULL;

    tmp = &rib->tree;

    for (i = 0; i < CNE_RIB6_IPV6_ADDR_SIZE; i++)
        tmp_ip[i] = ip[i] & get_msk_part(depth, i);

    new_node = cne_rib6_lookup_exact(rib, tmp_ip, depth);
    if (new_node != NULL)
        return NULL;

    new_node = node_alloc(rib);
    if (new_node == NULL)
        return NULL;
    new_node->left   = NULL;
    new_node->right  = NULL;
    new_node->parent = NULL;
    cne_rib6_copy_addr(new_node->ip, tmp_ip);
    new_node->depth = depth;
    new_node->flag  = CNE_RIB_VALID_NODE;

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
         * Previous cne_rib6_lookup_exact() returned NULL
         * but node with proper search criteria is found.
         * Validate intermediate node and return.
         */
        if (cne_rib6_is_equal(tmp_ip, (*tmp)->ip) && (depth == (*tmp)->depth)) {
            node_free(rib, new_node);
            (*tmp)->flag |= CNE_RIB_VALID_NODE;
            ++rib->cur_routes;
            return *tmp;
        }

        if (!is_covered(tmp_ip, (*tmp)->ip, (*tmp)->depth) || ((*tmp)->depth >= depth)) {
            break;
        }
        prev = *tmp;

        tmp = (get_dir(tmp_ip, (*tmp)->depth)) ? &(*tmp)->right : &(*tmp)->left;
    }

    /* closest node found, new_node should be inserted in the middle */
    common_depth = CNE_MIN(depth, (*tmp)->depth);
    for (i = 0, d = 0; i < CNE_RIB6_IPV6_ADDR_SIZE; i++) {
        ip_xor = tmp_ip[i] ^ (*tmp)->ip[i];
        if (ip_xor == 0)
            d += 8;
        else {
            d += __builtin_clz(ip_xor << 24);
            break;
        }
    }

    common_depth = CNE_MIN(d, common_depth);

    for (i = 0; i < CNE_RIB6_IPV6_ADDR_SIZE; i++)
        common_prefix[i] = tmp_ip[i] & get_msk_part(common_depth, i);

    if (cne_rib6_is_equal(common_prefix, tmp_ip) && (common_depth == depth)) {
        /* insert as a parent */
        if (get_dir((*tmp)->ip, depth))
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
        cne_rib6_copy_addr(common_node->ip, common_prefix);
        common_node->depth  = common_depth;
        common_node->flag   = 0;
        common_node->parent = (*tmp)->parent;
        new_node->parent    = common_node;
        (*tmp)->parent      = common_node;
        if (get_dir((*tmp)->ip, common_depth) == 1) {
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
cne_rib6_get_ip(const struct cne_rib6_node *node, uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE])
{
    if ((node == NULL) || (ip == NULL))
        return -1;
    cne_rib6_copy_addr(ip, node->ip);
    return 0;
}

int
cne_rib6_get_depth(const struct cne_rib6_node *node, uint8_t *depth)
{
    if ((node == NULL) || (depth == NULL))
        return -1;
    *depth = node->depth;
    return 0;
}

void *
cne_rib6_get_ext(struct cne_rib6_node *node)
{
    return (node == NULL) ? NULL : &node->ext[0];
}

int
cne_rib6_get_nh(const struct cne_rib6_node *node, uint64_t *nh)
{
    if ((node == NULL) || (nh == NULL))
        return -1;
    *nh = node->nh;
    return 0;
}

int
cne_rib6_set_nh(struct cne_rib6_node *node, uint64_t nh)
{
    if (node == NULL)
        return -1;
    node->nh = nh;
    return 0;
}

struct cne_rib6 *
cne_rib6_create(const char *name, const struct cne_rib6_conf *conf)
{
    struct cne_rib6 *rib = NULL;
    mmap_t *mm           = NULL;
    mempool_t *node_pool;
    struct mempool_cfg cfg = {0};

    /* Check user arguments. */
    if (name == NULL || conf == NULL || conf->max_nodes <= 0)
        return NULL;

    cfg.objcnt = conf->max_nodes;
    cfg.objsz  = sizeof(struct cne_rib6_node) + conf->ext_sz;
    mm         = mmap_alloc(cfg.objcnt, cfg.objsz, MMAP_HUGEPAGE_DEFAULT);
    if (!mm)
        CNE_NULL_RET("Unable to mmap() memory\n");
    cfg.addr = mmap_addr(mm);

    cne_rwlock_write_lock(&__rib6_lock);

    node_pool = mempool_create(&cfg);

    if (node_pool == NULL)
        CNE_ERR_GOTO(exit, "Can not allocate mempool for RIB6 %s\n", name);

    /* Allocate memory to store the RIB6 data structures. */
    rib = calloc(1, sizeof(struct cne_rib6));
    if (rib == NULL)
        CNE_ERR_GOTO(exit, "RIB6 %s memory allocation failed\n", name);

    rib->mm = mm;
    strlcpy(rib->name, name, sizeof(rib->name));
    rib->tree      = NULL;
    rib->max_nodes = conf->max_nodes;
    rib->node_pool = node_pool;

    cne_rwlock_write_unlock(&__rib6_lock);

    return rib;

exit:
    cne_rwlock_write_unlock(&__rib6_lock);
    mempool_destroy(node_pool);
    mmap_free(mm);
    return NULL;
}

void
cne_rib6_free(struct cne_rib6 *rib)
{
    struct cne_rib6_node *tmp = NULL;

    if (unlikely(rib == NULL))
        return;

    while ((tmp = cne_rib6_get_nxt(rib, 0, 0, tmp, CNE_RIB6_GET_NXT_ALL)) != NULL)
        cne_rib6_remove(rib, tmp->ip, tmp->depth);

    mempool_destroy(rib->node_pool);
    mmap_free(rib->mm);
    free(rib);
}
