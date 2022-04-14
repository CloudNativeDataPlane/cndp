/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

/* Created by Keith Wiles @ intel.com */

#include <stdbool.h>
#include <sys/queue.h>        // for TAILQ_HEAD

#include <mempool.h>        // for mempool_cfg, mempool_t, mempool_create, memp...

#include "cne_vec.h"
#include "cne_common.h"        // for __cne_unused

TAILQ_HEAD(vec_histogram_head, vec_histogram) vec_hist_head;

static void
vec_obj_init(mempool_t *mp, void *arg, void *obj, unsigned idx __cne_unused)
{
    vec_hdr_t *v = (vec_hdr_t *)CNE_PTR_ADD(obj, (CNE_CACHE_LINE_SIZE - sizeof(vec_hdr_t)));
    uint32_t n   = *(uint32_t *)arg;

    vec_init(v, n, mp, VEC_FREE_FLAG);
}

mempool_t *
vec_pool_create(unsigned int n, unsigned int entries, unsigned int entry_sz,
                unsigned int cache_size)
{
    struct mempool_cfg cfg = {0};
    mempool_t *mp          = NULL;

    if (entry_sz == 0)
        entry_sz = 1;

    cfg.objcnt   = n;
    cfg.objsz    = CNE_ALIGN_CEIL((entries * entry_sz), CNE_CACHE_LINE_SIZE) + CNE_CACHE_LINE_SIZE;
    cfg.cache_sz = cache_size;
    mp           = mempool_create(&cfg);
    if (mp)
        mempool_obj_iter(mp, vec_obj_init, (void *)&entries);

    return mp;
}

void
vec_pool_destroy(mempool_t *mp)
{
    mempool_destroy(mp);
}

int
vec_ptr_copy(char **to, char **from, int len)
{
    char *v;

    if (!to || !from || len == 0)
        return 0;

    vec_foreach_ptr (v, from) {
        if (len == 0)
            break;

        vec_add_ptr(to, v);
        if (vec_full(to))
            break;
    }

    len = vec_len(from) - vec_len(to);
    memmove(from, &from[vec_len(to)], len * sizeof(char *));
    vec_len(from) = len;
    return vec_len(to);
}

void
vec_dump(const char *msg, void *vec)
{
    vec_hdr_t *h;

    if (!vec)
        return;

    h = vec_header(vec);

    cne_printf("[orange]%-8s[]  ", msg ? msg : "");
    cne_printf("Vec @ %p, ", vec);
    cne_printf("flags 0x%04x, ", h->flags);
    cne_printf("len   %5d, ", h->len);
    cne_printf("tlen  %5d, ", h->tlen);
    cne_printf("pool  %p\n", h->pool);
}

struct vec_histogram *
vec_histogram_create(uint32_t size)
{
    struct vec_histogram *h;

    if (size == 0)
        return NULL;

    size++;
    h = malloc((size * sizeof(uint64_t)) + sizeof(struct vec_histogram));
    if (!h)
        return NULL;

    memset(h, 0, (size * sizeof(uint64_t)) + sizeof(struct vec_histogram));

    h->size = size;

    return h;
}

void
vec_histogram_dump(FILE *f, struct vec_histogram *h)
{
    uint32_t i, k;
    uint64_t m;

    if (!h)
        return;

    if (!f)
        f = stdout;

    fprintf(f, "CNET Vec Histogram\n");
    for (i = 0; i < h->size; i++) {
        if (h->histogram[i] == 0)
            continue;

        fprintf(f, "%4u-%16lu: ", i, h->histogram[i]);
        m = (h->histogram[i] / 100);
        if (m)
            m = h->histogram[i] / m;
        for (k = 0; k < m; k++)
            fprintf(f, "*");
        fprintf(f, "\n");
    }
}
