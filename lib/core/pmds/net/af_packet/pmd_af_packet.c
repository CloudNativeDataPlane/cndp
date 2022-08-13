/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation.
 */

#include <arpa/inet.h>              // for htons
#include <linux/if_packet.h>        // for sockaddr_ll, tpacket2, PACKET_RX_RING, PACKET_TX_RING
#include <net/if.h>                 // for if_nametoindex, IF_NAMESIZE
#include <bsd/string.h>             // for memset, strlcpy
#include <sys/mman.h>               // for mmap, munmap
#include <sys/ioctl.h>              // for ioctl
#include <sys/socket.h>             // for AF_PACKET, SOL_PACKET
#include <stdint.h>                 // for uint16_t, uint64_t
#include <stdlib.h>                 // for NULL, calloc, free, size_t
#include <cne_log.h>                // for CNE_LOG, CNE_ERR_RET, CNE_ERR,GOTO, CNE_PTR_ADD
#include <cne_lport.h>              // for lport_cfg_t, lport_stats_t
#include <pktdev.h>                 // for pktdev_info
#include <pktdev_core.h>            // for cne_pktdev, pktdev_ops
#include <pktdev_driver.h>          // for pktdev_allocate, pkt...
#include <pktmbuf.h>                // for pktmbuf_info_t, pktmbuf_t, pktmbuf...
#include "netdev_funcs.h"           // for netdev_get_mac_addr
#include <net/ethernet.h>           // for ether_addr

#include "pmd_af_packet.h"

#define FRAME_SZ  2048
#define BLK_SZ    4096
#define BLK_CNT   512
#define FRAME_CNT (BLK_CNT * BLK_SZ) / FRAME_SZ

struct af_pkt_rx_q {
    int fd;
    void *map;
    struct iovec *rd;

    size_t frame_num;
    size_t frame_cnt;

    struct pmd_lport *lport;
    uint16_t lport_id;

    uint64_t n_pkts;
    uint64_t n_bytes;
};

struct af_pkt_tx_q {
    int fd;
    void *map;
    struct iovec *rd;

    size_t frame_num;
    size_t frame_cnt;
    size_t data_sz;

    uint64_t n_pkts;
    uint64_t n_bytes;
};

struct pmd_lport {
    uint16_t lport_id;
    char if_name[IFNAMSIZ];
    int if_index;
    int fd;
    pktmbuf_info_t *pi;
    struct tpacket_req tp_req;
    struct ether_addr eth_addr;

    struct af_pkt_rx_q *rxq;
    struct af_pkt_tx_q *txq;
};

static uint16_t
pmd_af_packet_rx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    struct af_pkt_rx_q *rxq = queue;
    struct tpacket2_hdr *tp_hdr;
    pktmbuf_t *mbuf;
    uint8_t *pkt_buf;
    uint64_t n_rx_pkts  = 0;
    uint64_t n_rx_bytes = 0;
    size_t frame_cnt, frame_num, i;

    if (!queue || !bufs)
        return 0;

    if (unlikely(nb_pkts == 0))
        return 0;

    frame_num = rxq->frame_num;
    frame_cnt = rxq->frame_cnt;

    /* Read packets from the AF_PACKET socket & store in allocated mbuf */
    for (i = 0; i < nb_pkts; i++) {
        tp_hdr = (struct tpacket2_hdr *)rxq->rd[frame_num].iov_base; /*next frame to rx */
        if ((tp_hdr->tp_status & TP_STATUS_USER) == 0)
            break;
        /* Allocate mbuf */
        mbuf = pktmbuf_alloc(rxq->lport->pi);
        if (unlikely(mbuf == NULL))
            break;
        /* Rx incoming  packet */
        pktmbuf_data_len(mbuf) = tp_hdr->tp_snaplen;
        pkt_buf                = (uint8_t *)tp_hdr + tp_hdr->tp_mac;
        memcpy(pktmbuf_mtod(mbuf, void *), pkt_buf, pktmbuf_data_len(mbuf));

        /* Process incoming frame, advance buf*/
        tp_hdr->tp_status = TP_STATUS_KERNEL;
        if (++frame_num >= frame_cnt)
            frame_num = 0;
        mbuf->lport = rxq->lport_id;

        bufs[i] = mbuf;
        n_rx_pkts++;
        n_rx_bytes += mbuf->data_len;
    }
    rxq->frame_num = frame_num;

    rxq->n_pkts += n_rx_pkts;
    rxq->n_bytes += n_rx_bytes;

    return n_rx_pkts;
}

static uint16_t
pmd_af_packet_tx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    struct af_pkt_tx_q *txq = queue;
    struct tpacket2_hdr *tp_hdr;
    pktmbuf_t *mbuf;
    uint8_t *pkt_buf;
    uint64_t n_tx_pkts  = 0;
    uint64_t n_tx_bytes = 0;
    size_t frame_cnt, frame_num, i;

    if (!queue || !bufs)
        return 0;

    if (unlikely(nb_pkts == 0))
        return 0;

    frame_num = txq->frame_num;
    frame_cnt = txq->frame_cnt;

    tp_hdr = (struct tpacket2_hdr *)txq->rd[frame_num].iov_base; /*next frame to tx */
    for (i = 0; i < nb_pkts; i++) {
        mbuf = *bufs++;
        if (tp_hdr->tp_status != TP_STATUS_AVAILABLE)
            break;

        pkt_buf = (uint8_t *)tp_hdr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
        memcpy(pkt_buf, pktmbuf_mtod(mbuf, void *), pktmbuf_data_len(mbuf));

        tp_hdr->tp_len     = pktmbuf_data_len(mbuf);
        tp_hdr->tp_snaplen = pktmbuf_data_len(mbuf);
        tp_hdr->tp_status  = TP_STATUS_SEND_REQUEST;
        if (++frame_num >= frame_cnt)
            frame_num = 0;
        tp_hdr = (struct tpacket2_hdr *)txq->rd[frame_num].iov_base;
        n_tx_pkts++;
        n_tx_bytes += pktmbuf_data_len(mbuf);
        pktmbuf_free(mbuf);
    }
    if (sendto(txq->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) == -1 && errno != ENOBUFS &&
        errno != EAGAIN) {
        n_tx_pkts  = 0;
        n_tx_bytes = 0;
    }
    txq->frame_num = frame_num;

    txq->n_pkts += n_tx_pkts;
    txq->n_bytes += n_tx_bytes;

    return n_tx_pkts;
}

static int
pmd_dev_info(struct cne_pktdev *dev, struct pktdev_info *dev_info)
{
    struct pmd_lport *lport = dev->data->dev_private;

    dev_info->driver_name = PMD_NET_AF_PACKET_NAME;
    dev_info->if_index    = if_nametoindex(lport->if_name);

    return 0;
}

static int
pmd_stats_get(struct cne_pktdev *dev, lport_stats_t *stats)
{
    struct pmd_lport *lport = dev->data->dev_private;
    struct af_pkt_rx_q *rxq = lport->rxq;
    struct af_pkt_tx_q *txq = lport->txq;

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
    struct tpacket_req *rq;

    CNE_LOG(DEBUG, "Closing AF_PACKET on socket\n");

    lport = dev->data->dev_private;
    rq    = &lport->tp_req;

    munmap(lport->rxq->map, 2 * rq->tp_block_size * rq->tp_block_nr);
    free(lport->rxq->rd);
    free(lport->txq->rd);
    close(lport->fd);
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

static const struct pktdev_ops ops = {
    .dev_close     = pmd_dev_close,
    .dev_infos_get = pmd_dev_info,
    .stats_get     = pmd_stats_get,
    .pkt_alloc     = pmd_pkt_alloc,
};

static int pmd_af_packet_probe(lport_cfg_t *c);

static struct pktdev_driver af_packet_drv = {
    .probe = pmd_af_packet_probe,
};

PMD_REGISTER_DEV(net_af_packet, af_packet_drv);

static int
pmd_af_packet_probe(lport_cfg_t *c)
{
    struct sockaddr_ll addr;
    struct pmd_lport *lport;
    struct cne_pktdev *dev;
    struct tpacket_req *rq;
    struct af_pkt_rx_q *rxq;
    struct af_pkt_tx_q *txq;
    struct ifreq ifr;
    int fd = -1, ver, num_q = 1, ret = 0;
    size_t i, rd_sz, rq_sz;

    if (!c)
        return -1;

    CNE_LOG(DEBUG, "Init %s\n", c->ifname);

    lport = calloc(1, sizeof(struct pmd_lport));
    if (!lport)
        CNE_ERR_RET("Unable to allocate memory\n");

    strlcpy(lport->if_name, c->ifname, sizeof(lport->if_name));

    dev = pktdev_allocate(c->name, c->ifname);
    if (!dev)
        CNE_ERR_GOTO(err_exit, "pktdev_allocate(%s, %s) failed\n", c->name, c->ifname);
    dev->drv = &af_packet_drv;

    lport->lport_id = dev->data->lport_id;
    lport->pi       = c->pi;

    ret = netdev_get_mac_addr(c->ifname, &lport->eth_addr);
    if (ret)
        CNE_ERR_GOTO(err_exit, "netdev_get_mac_addr() failed\n");

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1)
        CNE_ERR_GOTO(err_exit, "Failed to open AF_PACKET socket for %s\n", c->ifname);

    strlcpy(ifr.ifr_name, lport->if_name, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
        CNE_ERR_GOTO(err_exit, "Err ioctl\n");
    lport->if_index = ifr.ifr_ifindex;

    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = lport->if_index;

    ret = bind(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1)
        CNE_ERR_GOTO(err_exit, "Err: Failed to bind AF_PACKET socket\n");

    lport->rxq = calloc(num_q, sizeof(struct af_pkt_rx_q));
    lport->txq = calloc(num_q, sizeof(struct af_pkt_tx_q));
    if (!(lport->rxq) || !(lport->txq))
        CNE_ERR_GOTO(err_exit, "Failed to allocate rx_tx queue\n");

    lport->rxq->map = MAP_FAILED;
    lport->txq->map = MAP_FAILED;
    lport->rxq->fd  = -1;
    lport->txq->fd  = -1;

    rq                = &(lport->tp_req);
    rq->tp_block_size = BLK_SZ;
    rq->tp_block_nr   = BLK_CNT;
    rq->tp_frame_size = FRAME_SZ;
    rq->tp_frame_nr   = FRAME_CNT;

    rq_sz     = rq->tp_block_size * rq->tp_block_nr;
    lport->fd = fd;
    ver       = TPACKET_V2;
    ret       = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
    if (ret == -1)
        CNE_ERR_GOTO(err_exit, "Err AF_PACKET: Failed to set PACKET_VERSION\n");

    ret = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, rq, sizeof(*rq));
    if (ret == -1)
        CNE_ERR_GOTO(err_exit, "Err AF_PACKET: Failed to set PACKET_RX_RING\n");

    ret = setsockopt(fd, SOL_PACKET, PACKET_TX_RING, rq, sizeof(*rq));
    if (ret == -1)
        CNE_ERR_GOTO(err_exit, "Err AF_PACKET: Failed to set PACKET_TX_RING\n");

    rxq            = lport->rxq;
    rxq->frame_cnt = rq->tp_frame_nr;
    rxq->map       = mmap(NULL, 2 * rq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
    if (rxq->map == MAP_FAILED)
        CNE_ERR_GOTO(err_exit, "Err AF_PACKET MMAP: Failed to get mmap on socket\n");

    rd_sz   = rq->tp_frame_nr * sizeof(*(rxq->rd));
    rxq->rd = calloc(1, rd_sz);
    if (rxq->rd == NULL)
        CNE_ERR_GOTO(err_exit, "Err iovec\n");

    for (i = 0; i < rq->tp_frame_nr; ++i) {
        rxq->rd[i].iov_base = CNE_PTR_ADD(rxq->map, (i * FRAME_SZ));
        rxq->rd[i].iov_len  = rq->tp_frame_size;
    }
    rxq->fd       = fd;
    rxq->lport    = lport;
    rxq->lport_id = lport->lport_id;

    txq            = lport->txq;
    txq->frame_cnt = rq->tp_frame_nr;
    txq->data_sz   = rq->tp_frame_size;
    txq->data_sz -= TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
    txq->map = CNE_PTR_ADD(rxq->map, rq_sz);

    txq->rd = calloc(1, rd_sz);
    if (txq->rd == NULL)
        CNE_ERR_GOTO(err_exit, "Err iovec\n");

    for (i = 0; i < rq->tp_frame_nr; ++i) {
        txq->rd[i].iov_base = CNE_PTR_ADD(txq->map, (i * FRAME_SZ));
        txq->rd[i].iov_len  = rq->tp_frame_size;
    }
    txq->fd = fd;

    dev->data->dev_private = lport;
    dev->data->mac_addr    = &lport->eth_addr;
    dev->data->rx_queue    = lport->rxq;
    dev->data->tx_queue    = lport->txq;
    dev->dev_ops           = &ops;
    dev->rx_pkt_burst      = pmd_af_packet_rx;
    dev->tx_pkt_burst      = pmd_af_packet_tx;

    return (pktdev_portid(dev));

err_exit:
    if (lport->rxq != NULL) {
        free(lport->rxq->rd);
        if (lport->rxq->map != MAP_FAILED)
            munmap(lport->rxq->map, 2 * lport->tp_req.tp_block_size * lport->tp_req.tp_block_nr);
        free(lport->rxq);
    }
    if (lport->txq != NULL) {
        free(lport->txq->rd);
        free(lport->txq);
    }

    if (fd != -1)
        close(fd);

    pktdev_release_port(dev);

    if (lport)
        free(lport);

    return ret;
}
