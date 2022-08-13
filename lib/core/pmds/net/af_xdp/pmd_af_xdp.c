/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */
// IWYU pragma: no_include <asm/int-ll64.h>
#include <errno.h>             // for ENODEV
#include <stdlib.h>            // for NULL, calloc, free, size_t
#include <string.h>            // for memset
#include <poll.h>              // for pollfd
#include <net/if.h>            // for if_nametoindex, IF_NAMESIZE
#include <sys/socket.h>        // for AF_XDP, PF_XDP, SOL_XDP
#include <bsd/string.h>        // for strlcpy
#include <stdint.h>            // for uint16_t, uint64_t
#include <linux/bpf.h>         // for XDP_PACKET_HEADROOM
#if USE_LIBXDP
#include <xdp/xsk.h>
#else
#include <bpf/xsk.h>        // for XSK_RING_CONS__DEFAULT_NUM_DESCS, xsk_...
#endif
#include <net/ethernet.h>         // for ether_addr
#include <cne_common.h>           // for CNE_PRIORITY_LAST
#include <cne_log.h>              // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_ERR
#include <pktmbuf.h>              // for pktmbuf_t
#include <pktdev.h>               // for pktdev_info, pktdev_portconf
#include <pktdev_driver.h>        // for pktdev_allocate, pktdev_allocated, pkt...
#include <cne_lport.h>            // for lport_cfg_t, lport_stats_t
#include <xskdev.h>               // for xskdev_info_t, xskdev_rx_burst, xskdev...

#include "pmd_af_xdp.h"
#include "pktdev_api.h"          // for pktdev_get_name_by_port, pktdev_portid
#include "pktdev_core.h"         // for cne_pktdev, pktdev_data, pktdev_ops
#include "netdev_funcs.h"        // for netdev_get_mac_addr

#define ETH_AF_XDP_FRAME_SIZE           2048
#define ETH_AF_XDP_MBUF_OVERHEAD        sizeof(pktmbuf_t)
#define ETH_AF_XDP_DATA_HEADROOM        (XDP_PACKET_HEADROOM - ETH_AF_XDP_MBUF_OVERHEAD)
#define ETH_AF_XDP_DFLT_NUM_DESCS       XSK_RING_CONS__DEFAULT_NUM_DESCS
#define ETH_AF_XDP_DFLT_START_QUEUE_IDX 0

#define ETH_AF_XDP_RX_BATCH_SIZE 64
#define ETH_AF_XDP_TX_BATCH_SIZE 64

#define ETH_AF_XDP_MBUF_MASK ~(ETH_AF_XDP_FRAME_SIZE - 1)

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *umem_addr;
    void *umem_end;
};

struct pkt_rx_queue {
    struct xsk_ring_cons rx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    xskdev_info_t *info;
    struct pollfd fds;
    int qid;
};

struct pkt_tx_queue {
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    xskdev_info_t *info;
    int qid;
};

struct pmd_lport {
    char if_name[IF_NAMESIZE + 1];
    int qid;
    uint64_t umem_begin;
    size_t umem_size;
    unsigned int prog_id;
    xskdev_info_t *xi;
    struct ether_addr eth_addr;
    struct offloads off;

    struct pkt_rx_queue rxq;
    struct pkt_tx_queue txq;
};

static uint16_t
pmd_af_xdp_rx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    struct pkt_rx_queue *rxq = queue;

    return xskdev_rx_burst(rxq->info, (void **)bufs, nb_pkts);
}

static uint16_t
pmd_af_xdp_tx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    struct pkt_tx_queue *txq = queue;

    return xskdev_tx_burst(txq->info, (void **)bufs, nb_pkts);
}

static int
pmd_dev_info(struct cne_pktdev *dev, struct pktdev_info *dev_info)
{
    struct pmd_lport *lport = dev->data->dev_private;

    dev_info->driver_name   = PMD_NET_AF_XDP_NAME;
    dev_info->if_index      = if_nametoindex(lport->if_name);
    dev_info->max_rx_pktlen = ETH_FRAME_LEN;

    dev_info->min_mtu = ETH_MIN_MTU;
    dev_info->max_mtu = ETH_AF_XDP_FRAME_SIZE - ETH_AF_XDP_DATA_HEADROOM;

    dev_info->default_rxportconf.ring_size = ETH_AF_XDP_DFLT_NUM_DESCS;
    dev_info->default_txportconf.ring_size = ETH_AF_XDP_DFLT_NUM_DESCS;

    return 0;
}

static int
pmd_stats_get(struct cne_pktdev *dev, lport_stats_t *stats)
{
    struct pmd_lport *lport = dev->data->dev_private;

    return xskdev_stats_get(lport->xi, stats);
}

static int
pmd_stats_reset(struct cne_pktdev *dev)
{
    struct pmd_lport *lport = dev->data->dev_private;

    return xskdev_stats_reset(lport->xi);
}

static void
pmd_dev_close(struct cne_pktdev *dev)
{
    struct pmd_lport *lport = dev->data->dev_private;

    CNE_LOG(DEBUG, "Closing AF_XDP\n");

    if (lport->xi)
        xskdev_socket_destroy(lport->xi);

    free(dev->data->dev_private);

    dev->data->mac_addr = NULL;
}

static int
pmd_pkt_alloc(struct cne_pktdev *dev, pktmbuf_t **pkts, uint16_t nb_pkts)
{
    struct pmd_lport *lport = dev->data->dev_private;

    if (!lport)
        return -1;

    return pktmbuf_alloc_bulk(lport->xi->buf_mgmt.buf_arg, pkts, nb_pkts);
}

static const struct pktdev_ops ops = {
    .dev_close     = pmd_dev_close,
    .dev_infos_get = pmd_dev_info,
    .stats_get     = pmd_stats_get,
    .stats_reset   = pmd_stats_reset,
    .pkt_alloc     = pmd_pkt_alloc,
};

static int pmd_af_xdp_probe(lport_cfg_t *c);

static struct pktdev_driver af_xdp_drv = {
    .probe = pmd_af_xdp_probe,
};

PMD_REGISTER_DEV(net_af_xdp, af_xdp_drv);

static struct cne_pktdev *
init_lport(lport_cfg_t *c)
{
    struct pmd_lport *lport;
    struct cne_pktdev *dev;
    int ret;

    CNE_LOG(DEBUG, "Init %s\n", c->ifname);

    lport = calloc(1, sizeof(struct pmd_lport));
    if (lport == NULL)
        CNE_NULL_RET("Failed to allocate internal memory\n");

    strlcpy(lport->if_name, c->ifname, sizeof(lport->if_name));

    lport->umem_begin = (uint64_t)c->umem_addr;
    lport->umem_size  = c->umem_size;
    lport->rxq.qid    = c->qid;
    lport->txq.qid    = c->qid;

    ret = netdev_get_mac_addr(c->ifname, &lport->eth_addr);
    if (ret)
        CNE_ERR_GOTO(err_exit, "netdev_get_mac_addr() failed\n");

    ret = netdev_get_offloads(c->ifname, &lport->off);
    if (ret)
        CNE_ERR_GOTO(err_exit, "netdev_get_offloads() failed\n");

    dev = pktdev_allocate(c->name, c->ifname);
    if (dev == NULL)
        CNE_ERR_GOTO(err_exit, "pktdev_allocate(%s, %s) failed\n", c->name, c->ifname);
    dev->drv = &af_xdp_drv;

    dev->data->dev_private = lport;
    dev->data->mac_addr    = &lport->eth_addr;
    dev->data->offloads    = &lport->off;
    dev->dev_ops           = &ops;
    dev->rx_pkt_burst      = pmd_af_xdp_rx;
    dev->tx_pkt_burst      = pmd_af_xdp_tx;

    lport->xi = xskdev_socket_create(c);
    if (!lport->xi)
        CNE_ERR_GOTO(err_exit, "xskdev_socket_create() failed\n");

    dev->data->rx_queue = &lport->rxq;
    dev->data->tx_queue = &lport->txq;
    lport->rxq.info     = lport->xi;
    lport->txq.info     = lport->xi;

    return dev;

err_exit:
    free(lport);
    return NULL;
}

static int
pmd_af_xdp_probe(lport_cfg_t *c)
{
    struct cne_pktdev *dev;

    if (!c)
        return -1;

    CNE_LOG(DEBUG, "Initializing pmd_af_xdp for %s\n", c->ifname);
    CNE_LOG(DEBUG, "  UMEM @ %p, size %ld\n", c->umem_addr, c->umem_size);

    dev = init_lport(c);
    if (!dev)
        CNE_ERR_RET("Failed to init lport\n");

    return pktdev_portid(dev);
}
