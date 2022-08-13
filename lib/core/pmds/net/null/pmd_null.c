/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation.
 */

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <cne_common.h>
#include <cne_lport.h>
#include <pktdev.h>
#include <pktdev_core.h>
#include <pktdev_driver.h>
#include <pktmbuf.h>
#include "pmd_null.h"

struct pmd_null_private {
    atomic_int_least64_t rx_pkts; /**< Received packets */
    atomic_int_least64_t tx_pkts; /**< Transmitted packets */
    pktmbuf_info_t *pi;           /**< Mempool for buffer allocation */
    uint16_t lport_id;            /**< Logical port */
};

static uint16_t
pmd_null_rx_burst(void *priv_, pktmbuf_t **bufs, uint16_t n_bufs)
{
    struct pmd_null_private *priv = priv_;
    int i;

    if (!priv || !bufs || !priv->pi)
        return 0;

    if (pktmbuf_alloc_bulk(priv->pi, bufs, n_bufs) <= 0)
        return 0;

    for (i = 0; i < n_bufs; i++) {
        bufs[i]->data_len = 64;
        bufs[i]->lport    = priv->lport_id;
    }

    atomic_fetch_add(&priv->rx_pkts, n_bufs);

    return n_bufs;
}

static uint16_t
pmd_null_tx_burst(void *priv_, pktmbuf_t **bufs, uint16_t n_bufs)
{
    struct pmd_null_private *priv = priv_;
    int i;

    if (!priv || !bufs)
        return 0;

    for (i = 0; i < n_bufs; i++)
        pktmbuf_free(bufs[i]);

    atomic_fetch_add(&priv->tx_pkts, n_bufs);

    return n_bufs;
}

static int
pmd_null_stats_get(struct cne_pktdev *dev, lport_stats_t *stats)
{
    struct pmd_null_private *priv;

    if (!dev || !stats)
        return -1;

    priv            = dev->data->dev_private;
    stats->ipackets = atomic_load_explicit(&priv->rx_pkts, memory_order_relaxed);
    stats->opackets = atomic_load_explicit(&priv->tx_pkts, memory_order_relaxed);

    return 0;
}

static int
pmd_null_stats_reset(struct cne_pktdev *dev)
{
    struct pmd_null_private *priv;

    if (!dev)
        return -1;

    priv = dev->data->dev_private;
    atomic_store_explicit(&priv->rx_pkts, 0, memory_order_relaxed);
    atomic_store_explicit(&priv->tx_pkts, 0, memory_order_relaxed);

    return 0;
}

static int
pmd_null_infos_get(struct cne_pktdev *dev, struct pktdev_info *dev_info)
{
    if (!dev || !dev_info)
        return -1;

    dev_info->driver_name = PMD_NET_NULL_NAME;
    return 0;
}

static void
pmd_null_close(struct cne_pktdev *dev)
{
    if (!dev)
        return;

    free(dev->data->dev_private);
    dev->data->dev_private = NULL;
}

static const struct pktdev_ops pmd_null_ops = {
    .dev_close     = pmd_null_close,
    .dev_infos_get = pmd_null_infos_get,
    .stats_get     = pmd_null_stats_get,
    .stats_reset   = pmd_null_stats_reset,
};

static int pmd_null_probe(lport_cfg_t *cfg);

static struct pktdev_driver null_drv = {
    .probe = pmd_null_probe,
};

PMD_REGISTER_DEV(net_null, null_drv)

static int
pmd_null_probe(lport_cfg_t *cfg)
{
    struct pmd_null_private *priv;
    struct cne_pktdev *dev;

    if (!cfg)
        return -1;

    dev = pktdev_allocate(cfg->name, NULL);
    if (!dev)
        return -1;
    dev->drv = &null_drv;

    priv = calloc(1, sizeof(*priv));
    if (!priv)
        return -1;

    /* copy lport_id to private data as its used in fast path */
    priv->lport_id = dev->data->lport_id;

    /* cfg->pi can be NULL, but no buffers will be allocated on rx */
    priv->pi = cfg->pi;

    /* rx_burst and tx_burst get the private data as their "queue" */
    dev->data->dev_private = priv;
    dev->data->rx_queue    = priv;
    dev->data->tx_queue    = priv;
    dev->dev_ops           = &pmd_null_ops;
    dev->rx_pkt_burst      = pmd_null_rx_burst;
    dev->tx_pkt_burst      = pmd_null_tx_burst;

    return dev->data->lport_id;
}
