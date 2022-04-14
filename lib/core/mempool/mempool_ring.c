/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <errno.h>        // for ENOBUFS, errno

#include "mempool_private.h"        // for cne_mempool
#include "mempool_ring.h"
#include "cne_common.h"          // for cne_align32pow2
#include "cne_ring.h"            // for cne_ring_t
#include "cne_ring_api.h"        // for cne_ring_count, cne_ring_create, cne_ri...

int
mempool_ring_enqueue(struct cne_mempool *mp, void *const *obj_table, unsigned n)
{
    return cne_ring_enqueue_bulk(mp->objring, obj_table, n, NULL) == 0 ? -ENOBUFS : 0;
}

int
mempool_ring_dequeue(struct cne_mempool *mp, void **obj_table, unsigned n)
{
    return cne_ring_dequeue_bulk(mp->objring, obj_table, n, NULL) == 0 ? -ENOBUFS : 0;
}

unsigned
mempool_ring_get_count(const struct cne_mempool *mp)
{
    return cne_ring_count(mp->objring);
}

int
mempool_ring_alloc(struct cne_mempool *mp)
{
    cne_ring_t *r;
    unsigned int sz;

    /* The ring size must be a power of two, if the number of objects is
     * equal to ring size we need to increase the size to the next power of 2
     * to make sure it can hold all of the objects. A bit of wasted memory if you
     * have a large ring, the ring could be twice the size at least compared to the
     * number of object in the ring.
     */
    sz = cne_align32pow2(mp->obj_cnt + 1);

    /*
     * Allocate the ring that will be used to store objects.
     * Ring functions will return appropriate errors if we are
     * running as a secondary process etc., so no checks made
     * in this function for that condition.
     */
    r = cne_ring_create("mempool", 0, sz, 0);
    if (r == NULL)
        return errno;

    mp->objring = r;

    return 0;
}

void
mempool_ring_free(struct cne_mempool *mp)
{
    cne_ring_free(mp->objring);
}

int
mempool_ring_populate(struct cne_mempool *mp, void *vaddr, mempool_populate_obj_cb_t *obj_cb,
                      void *obj_cb_arg)
{
    char *va   = vaddr;
    size_t off = 0;
    void *obj;
    unsigned int i;

    for (i = 0; i < mp->obj_cnt; i++) {
        obj = va + off;
        obj_cb(mp, obj_cb_arg, obj);
        mempool_ring_enqueue(mp, &obj, 1);
        off += mp->obj_sz;
    }

    return i;
}
