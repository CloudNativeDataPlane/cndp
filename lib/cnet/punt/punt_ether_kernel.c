/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Red Hat Inc.
 * Copyright (c) 2023 Intel Corporation
 */

#include <net/cne_ether.h>           // for ether_addr_copy, cne_ether_hdr, ether_ad...
#include <cnet.h>                    // for cnet_add_instance, cnet, per_thread_cnet
#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <xskdev.h>
#include <pktmbuf.h>        // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <pmd_tap.h>
#include <cnet_node_names.h>

#include "punt_ether_kernel_priv.h"

#define PREFETCH_CNT 6

static __cne_always_inline void
punt_ether_kernel_process_mbuf(struct cne_node *node, pktmbuf_t **mbufs, uint16_t cnt)
{
    punt_ether_kernel_node_ctx_t *ctx = (punt_ether_kernel_node_ctx_t *)node->ctx;

    for (int i = 0; i < cnt; i++)
        pktmbuf_adj_offset(mbufs[i], -(mbufs[i]->l2_len));

    int nb = pktdev_tx_burst(ctx->lport, mbufs, cnt);
    if (nb == PKTDEV_ADMIN_STATE_DOWN)
        CNE_WARN("Failed to send packets: %s\n", strerror(errno));
}

static uint16_t
punt_ether_kernel_node_process(struct cne_graph *graph __cne_unused, struct cne_node *node,
                               void **objs, uint16_t nb_objs)
{
    uint16_t n_left_from;
    pktmbuf_t *mbufs[PREFETCH_CNT], **pkts;
    int k;

    pkts        = (pktmbuf_t **)objs;
    n_left_from = nb_objs;

    for (k = 0; k < PREFETCH_CNT && k < n_left_from; k++)
        cne_prefetch0(pktmbuf_mtod_offset(pkts[k], void *, sizeof(struct cne_ether_hdr)));

    while (n_left_from >= PREFETCH_CNT) {
        /* Prefetch next-next mbufs */
        if (likely(n_left_from > ((PREFETCH_CNT * 3) - 1))) {
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 0]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 1]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 2]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 3]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 4]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 5]);
        }

        /* Prefetch next mbuf data */
        if (likely(n_left_from > ((PREFETCH_CNT * 2) - 1))) {
            uint16_t pre = PREFETCH_CNT;

            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 0], void *, pkts[pre + 0]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 1], void *, pkts[pre + 1]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 2], void *, pkts[pre + 2]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 3], void *, pkts[pre + 3]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 4], void *, pkts[pre + 4]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 5], void *, pkts[pre + 5]->l2_len));
        }

        memcpy(mbufs, pkts, (PREFETCH_CNT * sizeof(void *)));

        pkts += PREFETCH_CNT;
        n_left_from -= PREFETCH_CNT;

        punt_ether_kernel_process_mbuf(node, mbufs, PREFETCH_CNT);
    }

    while (n_left_from > 0) {
        mbufs[0] = pkts[0];

        n_left_from--;
        pkts++;

        punt_ether_kernel_process_mbuf(node, mbufs, 1);
    }

    return nb_objs;
}

static int
punt_ether_kernel_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    punt_ether_kernel_node_ctx_t *ctx = (punt_ether_kernel_node_ctx_t *)node->ctx;

    lport_cfg_t cfg = {0}; /**< CFG for tun/tap setup */
    ctx->mmap       = mmap_alloc(DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, MMAP_HUGEPAGE_4KB);
    if (ctx->mmap == NULL)
        cne_panic("Failed to mmap(%lu, %s) memory",
                  (uint64_t)DEFAULT_MBUF_COUNT * (uint64_t)DEFAULT_MBUF_SIZE,
                  mmap_name_by_type(MMAP_HUGEPAGE_4KB));

    memset(&cfg, 0, sizeof(cfg));

    strlcpy(cfg.name, TAP_NAME, sizeof(cfg.name));
    strlcpy(cfg.pmd_name, PMD_NET_TAP_NAME, sizeof(cfg.pmd_name));
    strlcpy(cfg.ifname, TAP_NAME, sizeof(cfg.ifname));

    cfg.addr = cfg.umem_addr = mmap_addr(ctx->mmap);
    cfg.umem_size            = mmap_size(ctx->mmap, NULL, NULL);
    cfg.qid                  = LPORT_DFLT_START_QUEUE_IDX;
    cfg.bufsz                = LPORT_FRAME_SIZE;
    cfg.bufcnt               = DEFAULT_MBUF_COUNT;
    cfg.rx_nb_desc           = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg.tx_nb_desc           = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    cfg.pi =
        pktmbuf_pool_create(mmap_addr(ctx->mmap), DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, 0, NULL);

    ctx->lport = pktdev_port_setup(&cfg);
    if (ctx->lport < 0)
        CNE_ERR_RET("Failed to create TAP device\n");

    if (netdev_set_link_up(TAP_NAME) < 0)
        CNE_ERR_RET("netdev_set_link_up(%d) failed\n", ctx->lport);

    return 0;
}

static void
punt_ether_kernel_node_fini(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    punt_ether_kernel_node_ctx_t *ctx = (punt_ether_kernel_node_ctx_t *)node->ctx;

    if (pktdev_close(ctx->lport) < 0)
        CNE_WARN("pktdev_close(%d) failed\n", ctx->lport);
    mmap_free(ctx->mmap);
}

static struct cne_node_register punt_ether_kernel_node_base = {
    .process = punt_ether_kernel_node_process,
    .name    = PUNT_ETHER_NODE_NAME,

    .init = punt_ether_kernel_node_init,
    .fini = punt_ether_kernel_node_fini,

};

struct cne_node_register *
punt_ether_kernel_node_get(void)
{
    return &punt_ether_kernel_node_base;
}

CNE_NODE_REGISTER(punt_ether_kernel_node_base);
