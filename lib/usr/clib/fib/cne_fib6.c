/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2023 Intel Corporation
 */

#include <stdint.h>              // for uint8_t, uint64_t
#include <cne_rwlock.h>          // for cne_rwlock_write_unlock, cne_rwlock_write_...
#include <cne_log.h>             // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_NULL_RET
#include <cne_rib6.h>            // for cne_rib6_free, cne_rib6_conf, cne_rib6_create
#include "private_fib6.h"        // for IPV6_ADDR_LEN, CNE_FIB6_TRIE
#include <cne_fib6.h>
#include <bsd/string.h>        // for strlcpy
#include <errno.h>             // for EINVAL, ENOENT
#include <stdio.h>             // for NULL, snprintf
#include <stdlib.h>            // for free, calloc

#include "trie.h"        // for trie_get_lookup_fn, trie_create, trie_free

static cne_rwlock_t __fib6_lock;

/* Maximum length of a FIB name. */
#define FIB6_NAMESIZE 64

struct cne_fib6 {
    char name[FIB6_NAMESIZE];
    enum cne_fib_type type;      /**< Type of FIB struct */
    struct cne_rib6 *rib;        /**< RIB helper datastruct */
    void *dp;                    /**< pointer to the dataplane struct*/
    cne_fib6_lookup_fn_t lookup; /**< fib lookup function */
    cne_fib6_modify_fn_t modify; /**< modify fib datastruct */
    uint64_t def_nh;
};

static void
dummy_lookup(void *fib_p, uint8_t ips[][IPV6_ADDR_LEN], uint64_t *next_hops, const unsigned int n)
{
    unsigned int i;
    struct cne_fib6 *fib = fib_p;
    struct cne_rib6_node *node;

    for (i = 0; i < n; i++) {
        node = cne_rib6_lookup(fib->rib, ips[i]);
        if (node != NULL)
            cne_rib6_get_nh(node, &next_hops[i]);
        else
            next_hops[i] = fib->def_nh;
    }
}

static int
dummy_modify(struct cne_fib6 *fib, const uint8_t ip[IPV6_ADDR_LEN], uint8_t depth,
             uint64_t next_hop, int op)
{
    struct cne_rib6_node *node;
    if ((fib == NULL) || (depth > CNE_FIB6_MAXDEPTH))
        return -EINVAL;

    node = cne_rib6_lookup_exact(fib->rib, ip, depth);

    switch (op) {
    case CNE_FIB_ADD:
        if (node == NULL)
            node = cne_rib6_insert(fib->rib, ip, depth);
        if (node == NULL)
            return -1;
        return cne_rib6_set_nh(node, next_hop);
    case CNE_FIB_DEL:
        if (node == NULL)
            return -ENOENT;
        cne_rib6_remove(fib->rib, ip, depth);
        return 0;
    }
    return -EINVAL;
}

static int
init_dataplane(struct cne_fib6 *fib, struct cne_fib_conf *conf)
{
    char dp_name[sizeof(void *)];

    snprintf(dp_name, sizeof(dp_name), "%p", fib);
    switch (conf->type) {
    case CNE_FIB_DUMMY:
        fib->dp     = fib;
        fib->lookup = dummy_lookup;
        fib->modify = dummy_modify;
        return 0;
    case CNE_FIB_TRIE:
        fib->dp = trie_create(dp_name, conf);
        if (fib->dp == NULL)
            return -1;
        fib->lookup = trie_get_lookup_fn(fib->dp, CNE_FIB_LOOKUP_DEFAULT);
        fib->modify = trie_modify;
        return 0;
    default:
        return -EINVAL;
    }
    return 0;
}

int
cne_fib6_add(struct cne_fib6 *fib, const uint8_t ip[IPV6_ADDR_LEN], uint8_t depth,
             uint64_t next_hop)
{
    if ((fib == NULL) || (ip == NULL) || (fib->modify == NULL) || (depth > CNE_FIB6_MAXDEPTH))
        return -EINVAL;
    return fib->modify(fib, ip, depth, next_hop, CNE_FIB_ADD);
}

int
cne_fib6_delete(struct cne_fib6 *fib, const uint8_t ip[IPV6_ADDR_LEN], uint8_t depth)
{
    if ((fib == NULL) || (ip == NULL) || (fib->modify == NULL) || (depth > CNE_FIB6_MAXDEPTH))
        return -EINVAL;
    return fib->modify(fib, ip, depth, 0, CNE_FIB_DEL);
}

int
cne_fib6_lookup_bulk(struct cne_fib6 *fib, uint8_t ips[][IPV6_ADDR_LEN], uint64_t *next_hops, int n)
{
    fib->lookup(fib->dp, ips, next_hops, n);
    return 0;
}

struct cne_fib6 *
cne_fib6_create(const char *name, struct cne_fib_conf *conf)
{
    int ret;
    struct cne_fib6 *fib = NULL;
    struct cne_rib6 *rib = NULL;
    struct cne_rib6_conf rib_conf;

    /* Check user arguments. */
    if ((name == NULL) || (conf == NULL) || (conf->max_routes < 0) || (conf->type > CNE_FIB_TRIE))
        return NULL;

    rib_conf.ext_sz    = 0;
    rib_conf.max_nodes = conf->max_routes * 2;

    rib = cne_rib6_create(name, &rib_conf);
    if (rib == NULL)
        CNE_NULL_RET("Can not allocate RIB %s\n", name);

    cne_rwlock_write_lock(&__fib6_lock);

    /* Allocate memory to store the FIB data structures. */
    fib = calloc(1, sizeof(struct cne_fib6));
    if (fib == NULL)
        CNE_ERR_GOTO(exit, "FIB %s memory allocation failed\n", name);

    strlcpy(fib->name, name, sizeof(fib->name));
    fib->rib    = rib;
    fib->type   = conf->type;
    fib->def_nh = conf->default_nh;
    ret         = init_dataplane(fib, conf);
    if (ret < 0)
        CNE_ERR_GOTO(exit, "FIB dataplane struct %s memory allocation failed\n", name);

    cne_rwlock_write_unlock(&__fib6_lock);

    return fib;

exit:
    free(fib);
    cne_rwlock_write_unlock(&__fib6_lock);
    cne_rib6_free(rib);

    return NULL;
}

static void
free_dataplane(struct cne_fib6 *fib)
{
    switch (fib->type) {
    case CNE_FIB_DUMMY:
        return;
    case CNE_FIB_TRIE:
        trie_free(fib->dp);
    default:
        return;
    }
}

void
cne_fib6_free(struct cne_fib6 *fib)
{
    if (fib == NULL)
        return;

    free_dataplane(fib);
    cne_rib6_free(fib->rib);
    free(fib);
}

void *
cne_fib6_get_dp(struct cne_fib6 *fib)
{
    return (fib == NULL) ? NULL : fib->dp;
}

struct cne_rib6 *
cne_fib6_get_rib(struct cne_fib6 *fib)
{
    return (fib == NULL) ? NULL : fib->rib;
}

int
cne_fib6_select_lookup(struct cne_fib6 *fib, enum cne_fib_lookup_type type)
{
    cne_fib6_lookup_fn_t fn;

    switch (fib->type) {
    case CNE_FIB_TRIE:
        fn = trie_get_lookup_fn(fib->dp, type);
        if (fn == NULL)
            return -EINVAL;
        fib->lookup = fn;
        return 0;
    default:
        return -EINVAL;
    }
}
