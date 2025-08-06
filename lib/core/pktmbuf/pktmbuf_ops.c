/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation.
 * Copyright (c) 2019-2020 6WIND S.A.
 */

#include <string.h>         // for memcpy
#include <stdio.h>          // for NULL
#include <stdint.h>         // for uint16_t
#include <cne_log.h>        // for CNE_LOG_ERR, CNE_ERR_RET, CNE_RET
#include <mempool.h>        // for mempool_cfg, mempool_create, mempool_destroy

#include "pktmbuf.h"            // for pktmbuf_reset, pktmbuf_info_s, pktmbuf_s (p...
#include "pktmbuf_ops.h"        // for mbuf_ops_t, pktmbuf_set_default_ops

static int
_default_mbuf_ctor(struct pktmbuf_info_s *pi)
{
    struct mempool_cfg cfg = {0};

    if (!pi)
        CNE_ERR_RET("pktmbuf_info_t pointer is NULL");

    cfg.addr         = pi->addr;
    cfg.mp_init      = NULL; /* not required for pktmbuf */
    cfg.mp_init_arg  = NULL;
    cfg.obj_init     = NULL; /* Done in __mbuf_init() in pktmbuf_pool_create() */
    cfg.obj_init_arg = NULL;
    cfg.objcnt       = pi->bufcnt;
    cfg.objsz        = pi->bufsz;
    cfg.cache_sz     = pi->cache_sz;

    pi->pd = mempool_create(&cfg);
    if (!pi->pd)
        CNE_ERR_RET("Failed to create mempool\n");

    return 0;
}

static void
_default_mbuf_dtor(struct pktmbuf_info_s *pi)
{
    if (!pi)
        CNE_RET("pktmbuf_info_t pointer is NULL\n");
    mempool_destroy(pi->pd);
}

/**
 * Allocate pktmbufs from a mempool
 *
 * @param pi
 *   The pktmbuf_info_t pointer, pointer is tested before this routine is called.
 * @param pkts
 *   The pktmbuf_t pointer array or vector of pktmbuf_t pointers
 * @param npkts
 *   The number of buffers to allocate
 * @return
 *   Number of buffers allocated, 0 when npkts request can't be allocated.
 */
static int
_default_mbuf_alloc(struct pktmbuf_info_s *pi, struct pktmbuf_s **pkts, uint16_t npkts)
{
    int idx = 0;

    if (mempool_get_bulk(pi->pd, (void **)pkts, npkts) != 0)
        return 0;

    /* To understand duff's device on loop unwinding optimization, see
     * https://en.wikipedia.org/wiki/Duff's_device.
     * Here while() loop is used rather than do() while{} to avoid extra
     * check if npkts is zero.
     */
    switch (npkts % 4) {
    case 0:
        while (idx != npkts) {
            pktmbuf_reset(pkts[idx]);
            idx++;
            /* fall-through */
        case 3:
            pktmbuf_reset(pkts[idx]);
            idx++;
            /* fall-through */
        case 2:
            pktmbuf_reset(pkts[idx]);
            idx++;
            /* fall-through */
        case 1:
            pktmbuf_reset(pkts[idx]);
            idx++;
            /* fall-through */
        }
    }
    return npkts;
}

static void
_default_mbuf_free(pktmbuf_info_t *pi, struct pktmbuf_s **pkts, uint16_t npkts)
{
    if (pi && pkts)
        mempool_put_bulk(pi->pd, (void **)pkts, npkts); /* All packets belong to the same pool */
}

// clang-format off
/**
 * Default pktmbuf operator structure, containing function pointers.
 */
static mbuf_ops_t _default_mbuf_ops = {
    .mbuf_ctor  = _default_mbuf_ctor,
    .mbuf_dtor  = _default_mbuf_dtor,
    .mbuf_alloc = _default_mbuf_alloc,
    .mbuf_free  = _default_mbuf_free
};
// clang-format on

void
pktmbuf_set_default_ops(mbuf_ops_t *ops)
{
    if (ops)
        memcpy(ops, &_default_mbuf_ops, sizeof(mbuf_ops_t));
}
