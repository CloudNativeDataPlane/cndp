/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2025 Intel Corporation
 */

#include <stdint.h>            // for uint64_t, uint32_t, uint8_t
#include <cne_rwlock.h>        // for cne_rwlock_write_unlock, cne_rwlock_write_lock
#include <cne_log.h>           // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_NULL_RET
#include <cne_rib.h>           // for cne_rib_free, cne_rib_conf, cne_rib_create
#include <cne_fib.h>
#include <bsd/string.h>        // for strlcpy
#include <errno.h>             // for EINVAL, ENOENT
#include <stdlib.h>            // for NULL, free, calloc

#include "dir24_8.h"        // for dir24_8_get_lookup_fn, dir24_8_create, dir24...

static cne_rwlock_t __fib_lock;

/* Maximum length of a FIB name. */
#define CNE_FIB_NAMESIZE 64

struct cne_fib {
    char name[CNE_FIB_NAMESIZE];
    enum cne_fib_type type;     /**< Type of FIB struct */
    struct cne_rib *rib;        /**< RIB helper datastruct */
    void *dp;                   /**< pointer to the dataplane struct*/
    cne_fib_lookup_fn_t lookup; /**< fib lookup function */
    cne_fib_modify_fn_t modify; /**< modify fib datastruct */
    uint64_t def_nh;
};

static void
dummy_lookup(void *fib_p, const uint32_t *ips, uint64_t *next_hops, const unsigned int n)
{
    unsigned int i;
    struct cne_fib *fib = fib_p;
    struct cne_rib_node *node;

    for (i = 0; i < n; i++) {
        node = cne_rib_lookup(fib->rib, ips[i]);
        if (node != NULL)
            cne_rib_get_nh(node, &next_hops[i]);
        else
            next_hops[i] = fib->def_nh;
    }
}

static int
dummy_modify(struct cne_fib *fib, uint32_t ip, uint8_t depth, uint64_t next_hop, int op)
{
    struct cne_rib_node *node;
    if ((fib == NULL) || (depth > CNE_FIB_MAXDEPTH))
        return -EINVAL;

    node = cne_rib_lookup_exact(fib->rib, ip, depth);

    switch (op) {
    case CNE_FIB_ADD:
        if (node == NULL)
            node = cne_rib_insert(fib->rib, ip, depth);
        if (node == NULL)
            return -1;
        return cne_rib_set_nh(node, next_hop);
    case CNE_FIB_DEL:
        if (node == NULL)
            return -ENOENT;
        cne_rib_remove(fib->rib, ip, depth);
        return 0;
    }
    return -EINVAL;
}

static int
init_dataplane(struct cne_fib *fib, struct cne_fib_conf *conf)
{
    switch (conf->type) {
    case CNE_FIB_DUMMY:
        fib->dp     = fib;
        fib->lookup = dummy_lookup;
        fib->modify = dummy_modify;
        return 0;
    case CNE_FIB_DIR24_8:
        fib->dp = dir24_8_create(conf);
        if (fib->dp == NULL)
            return -1;
        fib->lookup = dir24_8_get_lookup_fn(fib->dp, CNE_FIB_LOOKUP_DEFAULT);
        fib->modify = dir24_8_modify;
        return 0;
    default:
        return -EINVAL;
    }
    return 0;
}

int
cne_fib_add(struct cne_fib *fib, uint32_t ip, uint8_t depth, uint64_t next_hop)
{
    if ((fib == NULL) || (fib->modify == NULL) || (depth > CNE_FIB_MAXDEPTH))
        return -EINVAL;
    return fib->modify(fib, ip, depth, next_hop, CNE_FIB_ADD);
}

int
cne_fib_delete(struct cne_fib *fib, uint32_t ip, uint8_t depth)
{
    if ((fib == NULL) || (fib->modify == NULL) || (depth > CNE_FIB_MAXDEPTH))
        return -EINVAL;
    return fib->modify(fib, ip, depth, 0, CNE_FIB_DEL);
}

int
cne_fib_lookup_bulk(struct cne_fib *fib, uint32_t *ips, uint64_t *next_hops, int n)
{
    fib->lookup(fib->dp, ips, next_hops, n);
    return 0;
}

struct cne_fib *
cne_fib_create(const char *name, struct cne_fib_conf *conf)
{
    int ret;
    struct cne_fib *fib = NULL;
    struct cne_rib *rib = NULL;
    struct cne_rib_conf rib_conf;

    /* Check user arguments. */
    if ((name == NULL) || (conf == NULL) || (conf->max_routes < 0) ||
        (conf->type > CNE_FIB_DIR24_8))
        return NULL;

    rib_conf.ext_sz    = 0;
    rib_conf.max_nodes = conf->max_routes * 2;

    rib = cne_rib_create(name, &rib_conf);
    if (rib == NULL)
        CNE_NULL_RET("Can not allocate RIB %s\n", name);

    cne_rwlock_write_lock(&__fib_lock);

    /* Allocate memory to store the FIB data structures. */
    fib = calloc(1, sizeof(struct cne_fib));
    if (fib == NULL)
        CNE_ERR_GOTO(exit, "FIB %s memory allocation failed\n", name);

    strlcpy(fib->name, name, sizeof(fib->name));
    fib->rib    = rib;
    fib->type   = conf->type;
    fib->def_nh = conf->default_nh;
    ret         = init_dataplane(fib, conf);
    if (ret < 0)
        CNE_ERR_GOTO(free_fib,
                     "FIB dataplane struct %s memory allocation failed "
                     "with err %d\n",
                     name, ret);

    cne_rwlock_write_unlock(&__fib_lock);

    return fib;

free_fib:
    free(fib);
exit:
    cne_rwlock_write_unlock(&__fib_lock);
    cne_rib_free(rib);

    return NULL;
}

static void
free_dataplane(struct cne_fib *fib)
{
    switch (fib->type) {
    case CNE_FIB_DUMMY:
        return;
    case CNE_FIB_DIR24_8:
        dir24_8_free(fib->dp);
    default:
        return;
    }
}

void
cne_fib_free(struct cne_fib *fib)
{
    if (fib == NULL)
        return;

    free_dataplane(fib);
    cne_rib_free(fib->rib);
    free(fib);
}

void *
cne_fib_get_dp(struct cne_fib *fib)
{
    return (fib == NULL) ? NULL : fib->dp;
}

struct cne_rib *
cne_fib_get_rib(struct cne_fib *fib)
{
    return (fib == NULL) ? NULL : fib->rib;
}

int
cne_fib_select_lookup(struct cne_fib *fib, enum cne_fib_lookup_type type)
{
    cne_fib_lookup_fn_t fn;

    switch (fib->type) {
    case CNE_FIB_DIR24_8:
        fn = dir24_8_get_lookup_fn(fib->dp, type);
        if (fn == NULL)
            return -EINVAL;
        fib->lookup = fn;
        return 0;
    default:
        return -EINVAL;
    }
}
