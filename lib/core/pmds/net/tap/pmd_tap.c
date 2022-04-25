/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

#include <arpa/inet.h>              // for htons
#include <linux/if_packet.h>        // for sockaddr_ll, tpacket2, PACKET_RX_RING, PACKET_TX_RING
#include <net/if.h>                 // for if_nametoindex, IF_NAMESIZE
#include <bsd/string.h>             // for memset, strlcpy
#include <sys/mman.h>               // for mmap, munmap
#include <sys/ioctl.h>              // for ioctl
#include <stdint.h>                 // for uint16_t, uint64_t
#include <stdlib.h>                 // for NULL, calloc, free, size_t
#include <cne_log.h>                // for CNE_LOG, CNE_ERR_RET, CNE_ERR,GOTO, CNE_PTR_ADD
#include <cne_lport.h>              // for lport_cfg_t, lport_stats_t
#include <pktdev.h>                 // for pktdev_info
#include <pktdev_core.h>            // for cne_pktdev, pktdev_ops
#include <pktdev_driver.h>          // for pktdev_allocate, pktdev_create_done, pkt...
#include <pktmbuf.h>                // for pktmbuf_info_t, pktmbuf_t, pktmbuf...
#include "netdev_funcs.h"           // for netdev_get_mac_addr
#include <net/ethernet.h>           // for ether_addr
#include <sys/uio.h>
#include <linux/if_tun.h>        // for if_nametoindex, IF_NAMESIZE
#include <tun_alloc.h>

#include "pmd_tap.h"

struct tap_rx_q {
    int fd;
    struct iovec *rd;

    struct pmd_lport *lport;
    uint16_t lport_id;

    uint64_t n_pkts;
    uint64_t n_bytes;
};

struct tap_tx_q {
    int fd;
    struct iovec *rd;

    uint64_t n_pkts;
    uint64_t n_bytes;
};

struct pmd_lport {
    uint16_t lport_id;
    char if_name[IFNAMSIZ + 1];
    pktmbuf_info_t *pi;
    struct tap_info *ti;
    struct ether_addr eth_addr;

    struct tap_rx_q *rxq;
    struct tap_tx_q *txq;
};

static uint16_t
pmd_tuntap_rx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts, int tap_type __cne_unused)
{
    struct tap_rx_q *rxq = queue;
    int n_rx_pkts        = 0;
    int n_rx_bytes       = 0;
    struct tun_pi pi;
    uint16_t len;
    int nb_cnt = 0, k;

    if (!rxq || !bufs || nb_pkts == 0)
        return 0;

    if ((nb_cnt = pktmbuf_alloc_bulk(rxq->lport->pi, bufs, nb_pkts)) < 0)
        return 0;

    /* Read packets from the TAP socket & store in allocated mbuf */
    for (int i = 0; i < nb_cnt; i++) {
        pktmbuf_t *m = *bufs;
        struct iovec iov[2];

        k = 0;

        iov[k].iov_base  = &pi;
        iov[k++].iov_len = sizeof(struct tun_pi);
        iov[k].iov_base  = pktmbuf_mtod(m, void *);
        iov[k++].iov_len = pktmbuf_tailroom(m);

        len = readv(rxq->fd, iov, k);
        if (len < sizeof(struct tun_pi) || len == 0xFFFF)
            break;

        if (pi.flags & TUN_PKT_STRIP)
            continue;
        len -= sizeof(struct tun_pi);

        bufs++;

        pktmbuf_port(m)     = rxq->lport_id;
        pktmbuf_data_len(m) = len;

        n_rx_pkts++;
        n_rx_bytes += len;
    }

    if (n_rx_pkts < nb_cnt)
        pktmbuf_free_bulk(bufs, nb_cnt - n_rx_pkts);

    rxq->n_pkts += n_rx_pkts;
    rxq->n_bytes += n_rx_bytes;

    return n_rx_pkts;
}

static uint16_t
pmd_tap_rx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    return pmd_tuntap_rx(queue, bufs, nb_pkts, IFF_TAP);
}

static uint16_t
pmd_tun_rx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    return pmd_tuntap_rx(queue, bufs, nb_pkts, IFF_TUN);
}

static uint16_t
pmd_tuntap_tx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts, int tap_type)
{
    struct tap_tx_q *txq = queue;
    uint64_t tx_pkts = 0, tx_bytes = 0;

    if (!txq || !bufs)
        return 0;

    if (nb_pkts) {
        struct tun_pi pi = {.flags = 0, .proto = 0};
        struct iovec iov[2];
        int k;

        for (int i = 0; i < nb_pkts; i++) {
            pktmbuf_t *m = bufs[i];
            ssize_t len;

            pi.flags = 0;
            pi.proto = 0;
            if (tap_type == IFF_TUN) {
                char proto = *pktmbuf_mtod(m, char *);

                if (proto == 0x40)
                    pi.proto = htobe16(ETHERTYPE_IP);
                else if (proto == 0x60)
                    pi.proto = htobe16(ETHERTYPE_IPV6);
            }

            k = 0;

            iov[k].iov_base  = (void *)&pi;
            iov[k++].iov_len = sizeof(struct tun_pi);
            iov[k].iov_base  = pktmbuf_mtod(m, void *);
            iov[k++].iov_len = pktmbuf_data_len(m);

            if ((len = writev(txq->fd, iov, k)) < 0)
                break;

            tx_pkts++;
            tx_bytes += len;
        }
        txq->n_pkts += tx_pkts;
        txq->n_bytes += tx_bytes;

        pktmbuf_free_bulk(bufs, nb_pkts);
    }

    return tx_pkts;
}

static uint16_t
pmd_tap_tx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    return pmd_tuntap_tx(queue, bufs, nb_pkts, IFF_TAP);
}

static uint16_t
pmd_tun_tx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    return pmd_tuntap_tx(queue, bufs, nb_pkts, IFF_TUN);
}

static int
pmd_tap_dev_info(struct cne_pktdev *dev, struct pktdev_info *dev_info)
{
    struct pmd_lport *lport = dev->data->dev_private;

    dev_info->driver_name = PMD_NET_TAP_NAME;
    dev_info->if_index    = if_nametoindex(lport->if_name);

    return 0;
}

static int
pmd_tun_dev_info(struct cne_pktdev *dev, struct pktdev_info *dev_info)
{
    struct pmd_lport *lport = dev->data->dev_private;

    dev_info->driver_name = PMD_NET_TUN_NAME;
    dev_info->if_index    = if_nametoindex(lport->if_name);

    return 0;
}

static int
pmd_stats_get(struct cne_pktdev *dev, lport_stats_t *stats)
{
    struct pmd_lport *lport = dev->data->dev_private;
    struct tap_rx_q *rxq    = lport->rxq;
    struct tap_tx_q *txq    = lport->txq;

    /* RX stats */
    stats->ipackets = rxq->n_pkts;
    stats->ibytes   = rxq->n_bytes;

    /* TX stats */
    stats->opackets = txq->n_pkts;
    stats->obytes   = txq->n_bytes;

    return 0;
}

static void
pmd_dev_close(struct cne_pktdev *dev)
{
    struct pmd_lport *lport;

    CNE_LOG(DEBUG, "Closing TUN/TAP ethdev on socket\n");

    lport = dev->data->dev_private;
    tun_free(lport->ti);
    free(lport->rxq);
    free(lport->txq);
    free(lport);

    dev->data->mac_addr = NULL;
}

static int
pmd_pkt_alloc(struct cne_pktdev *dev, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    struct pmd_lport *lport = dev->data->dev_private;

    if (!lport)
        return -1;

    return pktmbuf_alloc_bulk(lport->pi, bufs, nb_pkts);
}

static const struct pktdev_ops tap_ops = {
    .dev_close     = pmd_dev_close,
    .dev_infos_get = pmd_tap_dev_info,
    .stats_get     = pmd_stats_get,
    .pkt_alloc     = pmd_pkt_alloc,
};

static const struct pktdev_ops tun_ops = {
    .dev_close     = pmd_dev_close,
    .dev_infos_get = pmd_tun_dev_info,
    .stats_get     = pmd_stats_get,
    .pkt_alloc     = pmd_pkt_alloc,
};

static int
_tap_probe(int tap_type, lport_cfg_t *c)
{
    struct pmd_lport *lport = NULL;
    struct cne_pktdev *dev  = NULL;
    struct tap_rx_q *rxq    = NULL;
    struct tap_tx_q *txq    = NULL;
    int ret                 = 0;

    if (!c || c->pi == NULL)
        return -1;

    CNE_LOG(DEBUG, "Init %s\n", c->name);

    lport = calloc(1, sizeof(struct pmd_lport));
    if (!lport)
        CNE_ERR_RET("Unable to allocate memory for %s\n", c->name);

    strlcpy(lport->if_name, c->name, sizeof(lport->if_name));

    dev = pktdev_allocate(c->name, c->name);
    if (!dev)
        CNE_ERR_GOTO(err_exit, "pktdev_allocate(%s, %s) failed\n", c->name, c->name);

    lport->lport_id = dev->data->lport_id;
    lport->pi       = c->pi;

    lport->ti = tun_alloc(tap_type, lport->if_name);
    if (lport->ti == NULL)
        CNE_ERR_GOTO(err_exit, "Unable to create %s\n", lport->if_name);

    lport->rxq = calloc(1, sizeof(struct tap_rx_q));
    lport->txq = calloc(1, sizeof(struct tap_tx_q));
    if (!lport->rxq || !lport->txq)
        CNE_ERR_GOTO(err_exit, "Failed to allocate rx_tx queue\n");

    rxq           = lport->rxq;
    rxq->lport    = lport;
    rxq->lport_id = lport->lport_id;
    rxq->fd       = tun_get_fd(lport->ti);
    txq           = lport->txq;
    txq->fd       = tun_get_fd(lport->ti);

    dev->data->dev_private = lport;
    dev->data->mac_addr    = &lport->eth_addr;
    dev->data->rx_queue    = lport->rxq;
    dev->data->tx_queue    = lport->txq;
    if (tap_type == IFF_TAP) {
        dev->dev_ops      = &tap_ops;
        dev->rx_pkt_burst = pmd_tap_rx;
        dev->tx_pkt_burst = pmd_tap_tx;
    } else {
        dev->dev_ops      = &tun_ops;
        dev->rx_pkt_burst = pmd_tun_rx;
        dev->tx_pkt_burst = pmd_tun_tx;
    }

    pktdev_create_done(dev);
    return pktdev_portid(dev);

err_exit:
    free(lport->rxq);
    free(lport->txq);

    tun_free(lport->ti);

    pktdev_release_port(dev);

    free(lport);

    return ret;
}

static int
pmd_tap_probe(lport_cfg_t *c)
{
    return _tap_probe(IFF_TAP, c);
}

static int
pmd_tun_probe(lport_cfg_t *c)
{
    return _tap_probe(IFF_TUN, c);
}

static int
pmd_tap_remove(int lport_id)
{
    struct cne_pktdev *dev;

    dev = pktdev_get(lport_id);
    if (!dev)
        return -1;

    pktdev_release_port(dev);
    return 0;
}

static struct pktdev_driver tap_drv = {
    .name   = PMD_NET_TAP_NAME,
    .probe  = pmd_tap_probe,
    .remove = pmd_tap_remove,
};

static struct pktdev_driver tun_drv = {
    .name   = PMD_NET_TUN_NAME,
    .probe  = pmd_tun_probe,
    .remove = pmd_tap_remove,
};

CNE_INIT(vdrvinit_tuntap)
{
    pktdev_register(&tap_drv);
    pktdev_register(&tun_drv);
}
