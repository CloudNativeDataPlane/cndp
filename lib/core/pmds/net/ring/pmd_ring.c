/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <pktdev.h>               // for pktdev_info
#include <pktdev_driver.h>        // for pktdev_allocate, pktd...
#include <errno.h>                // for errno, ENODEV, ENOMEM, ENOSPC
#include <stdatomic.h>            // for memory_order_relaxed, atomic_fetch_add
#include <stdint.h>               // for uint16_t, uint32_t
#include <stdio.h>                // for NULL, snprintf
#include <stdlib.h>               // for calloc, free
#include <net/ethernet.h>         // for ether_addr
#include <bsd/string.h>           // for strlcpy
#include <net/if.h>               // for IF_NAMESIZE
#include <pktmbuf.h>              // for pktmbuf_t
#include <string.h>               // for memset

#include "pmd_ring.h"
#include "cne_common.h"          // for __cne_unused, CNE_PRIORITY_LAST
#include "cne_log.h"             // for cne_log, CNE_ERR, CNE_LOG_DEBUG, CNE_LOG_ERR
#include "cne_lport.h"           // for lport_cfg_t, lport_stats_t
#include "cne_ring.h"            // for cne_ring_t, CNE_RING_NAMESIZE
#include "pktdev_api.h"          // for pktdev_get_name_by_port, pktdev_portid
#include "pktdev_core.h"         // for pktdev_data, cne_pktdev, pktdev_ops
#include "cne_ring_api.h"        // for cne_ring_get_flags, cne_ring_create, cne_...

// IWYU pragma: no_forward_declare pktmbuf_s
// IWYU pragma: no_forward_declare cne_mempool

struct ring_internal_args {
    cne_ring_t *rxq;
    cne_ring_t *txq;
    void *addr; /* self addr for sanity check */
};

struct ring_queue {
    cne_ring_t *rng;
    union {
        atomic_int_least64_t rx_pkts;
        atomic_int_least64_t tx_pkts;
    };
};

struct pmd_internals {
    char if_name[CNE_RING_NAMESIZE];
    char pmd_name[IF_NAMESIZE];
    struct ring_queue rx_ring_queue;
    struct ring_queue tx_ring_queue;
    struct ether_addr address;
};

#define PMD_LOG(level, fmt, args...) cne_log(CNE_LOG_##level, __func__, __LINE__, fmt "\n", ##args)

static uint16_t
pmd_ring_rx(void *q, pktmbuf_t **bufs, uint16_t nb_bufs)
{
    void **ptrs          = (void *)&bufs[0];
    struct ring_queue *r = q;
    const uint16_t nb_rx = (uint16_t)cne_ring_dequeue_burst(r->rng, ptrs, nb_bufs, NULL);
    if (cne_ring_get_flags(r->rng) & RING_F_SC_DEQ)
        atomic_fetch_add_explicit(&(r->rx_pkts), nb_rx, memory_order_relaxed);
    else
        atomic_fetch_add(&(r->rx_pkts), nb_rx);
    return nb_rx;
}

static uint16_t
pmd_ring_tx(void *q, pktmbuf_t **bufs, uint16_t nb_bufs)
{
    void **ptrs          = (void *)&bufs[0];
    struct ring_queue *r = q;
    const uint16_t nb_tx = (uint16_t)cne_ring_enqueue_burst(r->rng, ptrs, nb_bufs, NULL);
    if (cne_ring_get_flags(r->rng) & RING_F_SP_ENQ)
        atomic_fetch_add_explicit(&(r->tx_pkts), nb_tx, memory_order_relaxed);
    else
        atomic_fetch_add(&(r->tx_pkts), nb_tx);
    return nb_tx;
}

static int
pmd_dev_info(struct cne_pktdev *dev, struct pktdev_info *dev_info)
{
    struct pmd_internals *internals = dev->data->dev_private;

    dev_info->driver_name    = internals->pmd_name;
    dev_info->max_rx_pktlen  = (uint32_t)-1;
    dev_info->min_rx_bufsize = 0;

    return 0;
}

static int
pmd_stats_get(struct cne_pktdev *dev, lport_stats_t *stats)
{
    unsigned long rx_total = 0, tx_total = 0;
    const struct pmd_internals *internal = dev->data->dev_private;

    rx_total = atomic_load_explicit(&(internal->rx_ring_queue.rx_pkts), memory_order_relaxed);

    tx_total = atomic_load_explicit(&(internal->tx_ring_queue.tx_pkts), memory_order_relaxed);

    stats->ipackets = rx_total;
    stats->opackets = tx_total;

    return 0;
}

static int
pmd_stats_reset(struct cne_pktdev *dev)
{
    struct pmd_internals *internal = dev->data->dev_private;

    atomic_store_explicit(&internal->rx_ring_queue.rx_pkts, 0, memory_order_relaxed);
    atomic_store_explicit(&internal->tx_ring_queue.tx_pkts, 0, memory_order_relaxed);

    return 0;
}

static int
pmd_link_update(struct cne_pktdev *dev __cne_unused, int wait_to_complete __cne_unused)
{
    return 0;
}

static int
pmd_mac_addr_set(struct cne_pktdev *dev __cne_unused, struct ether_addr *mac_addr __cne_unused)
{
    return 0;
}

static void
pmd_close(struct cne_pktdev *dev)
{
    struct pmd_internals *internal;

    if (!dev)
        return;

    internal = dev->data->dev_private;

    /*
     * it is only necessary to delete the rings in rx_queues because
     * they are the same used in tx_queues
     */
    if (internal->rx_ring_queue.rng)
        cne_ring_free(internal->rx_ring_queue.rng);

    return;
}

static const struct pktdev_ops ops = {
    .dev_infos_get = pmd_dev_info,
    .link_update   = pmd_link_update,
    .stats_get     = pmd_stats_get,
    .stats_reset   = pmd_stats_reset,
    .mac_addr_set  = pmd_mac_addr_set,
    .dev_close     = pmd_close,
};

static int pmd_ring_probe(lport_cfg_t *cfg);

static struct pktdev_driver ring_drv = {
    .probe = pmd_ring_probe,
};

PMD_REGISTER_DEV(net_ring, ring_drv)

static struct cne_pktdev *
do_pmd_ring_create(const char *name, struct ring_internal_args *args)
{
    struct pktdev_data *data        = NULL;
    struct pmd_internals *internals = NULL;
    struct cne_pktdev *dev          = NULL;

    PMD_LOG(DEBUG, "Creating rings-backed pktdev\n");

    internals = calloc(1, sizeof(*internals));
    if (!internals) {
        errno = ENOMEM;
        goto error;
    }

    /* reserve an pktdev entry */
    dev = pktdev_allocate(name, NULL);
    if (!dev) {
        errno = ENOSPC;
        CNE_ERR_GOTO(error, "Could not pktdev_allocate\n");
    }
    dev->drv = &ring_drv;

    /* now put it all together
     * - store queue data in internals,
     * - store numa_node info in pmd_dev_data
     * - point pmd_dev_data to internals
     * - and point pmd_dev structure to new pmd_dev_data structure
     */

    data              = dev->data;
    data->rx_queue    = &internals->rx_ring_queue;
    data->tx_queue    = &internals->tx_ring_queue;
    data->dev_private = internals;
    data->mac_addr    = &internals->address;
    dev->dev_ops      = &ops;

    strlcpy(internals->if_name, name, sizeof(internals->if_name));
    strlcpy(internals->pmd_name, "net_ring", sizeof(internals->pmd_name));

    internals->rx_ring_queue.rng = args->rxq;
    data->rx_queue               = &internals->rx_ring_queue;

    internals->tx_ring_queue.rng = args->txq;
    data->tx_queue               = &internals->tx_ring_queue;

    /* finally assign rx and tx ops */
    dev->rx_pkt_burst = pmd_ring_rx;
    dev->tx_pkt_burst = pmd_ring_tx;

    return dev;

error:
    free(internals);

    return NULL;
}

static struct cne_pktdev *
__pmd_ring_init(const char *name)
{
    /* rx and tx are so-called from point of view of first lport.
     * They are inverted from the point of view of second lport
     */
    cne_ring_t *rxtx;
    char rng_name[CNE_RING_NAMESIZE];
    int cc;

    PMD_LOG(DEBUG, "__pmd_ring_init(%s)", name);

    cc = snprintf(rng_name, sizeof(rng_name), "PKT_%s", name);
    if (cc >= (int)sizeof(rng_name)) {
        CNE_ERR("Ring Name is too long %d\n", cc);
        return NULL;
    }

    rxtx = cne_ring_create(rng_name, 0, 1024, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!rxtx) {
        CNE_ERR("Failed to create ring\n");
        return NULL;
    }

    struct ring_internal_args args = {.rxq = rxtx, .txq = rxtx, .addr = &args};

    return do_pmd_ring_create(name, &args);
}

static int
pmd_ring_probe(lport_cfg_t *cfg)
{
    struct cne_pktdev *dev;

    if (!cfg)
        return -1;

    PMD_LOG(DEBUG, "Initializing pmd_ring for %s", cfg->ifname);
    dev = __pmd_ring_init(cfg->ifname);
    if (!dev) {
        CNE_ERR("Failed to create RING PMD for %s", cfg->ifname);
        return -1;
    }

    return pktdev_portid(dev);
}
