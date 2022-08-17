/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <asm/int-ll64.h>
#include <unistd.h>               // for close
#include <errno.h>                // for errno, EAGAIN, EOPNOTSUPP, EBUSY, EINTR
#include <stdlib.h>               // for calloc, free, exit, EXIT_FAILURE
#include <string.h>               // for strerror, memset, memcpy
#include <sys/socket.h>           // for getsockopt, send, socket, AF_INET, MSG...
#include <sys/ioctl.h>            // for ioctl
#include <bsd/string.h>           // for strlcpy
#include <stdint.h>               // for uint64_t, uint16_t, uint32_t
#include <bpf/libbpf.h>           // for bpf_get_link_xdp_id, bpf_set_link_xdp_fd
#include <stdbool.h>              // for bool, true
#include <linux/bpf.h>            // for XDP_PACKET_HEADROOM
#include <linux/if_xdp.h>         // for xdp_desc, xdp_statistics, XDP_STATISTICS
#include <linux/if_link.h>        // for XDP_FLAGS_UPDATE_IF_NOEXIST
#include <linux/ethtool.h>        // for ethtool_channels, ETHTOOL_GCHANNELS
#include <linux/sockios.h>        // for SIOCETHTOOL
#include <cne_common.h>           // for CNE_DEFAULT_SET, CNE_MAX_SET, CNE_PTR_SUB
#include <cne_log.h>              // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_ERR
#include <stdbool.h>              // for bool
#include <linux/sched.h>          // for sched_yield
#include <netdev_funcs.h>         // for netdev_get_ring_params
#include <cne_mutex_helper.h>

#include "xskdev.h"
#include "cne_lport.h"        // for lport_stats_t, lport_cfg, lport_cfg_t

#define FQ_ADD_BURST_COUNT 64
#define POLL_TIMEOUT       0
#define MAX_NUM_TRIES      1000

static bool xskdev_use_tx_lock = true;

static TAILQ_HEAD(cne_xskdev_list, xskdev_info) xskdev_list;
static pthread_mutex_t xskdev_list_mutex;

static inline void
xskdev_list_lock(void)
{
    int ret = pthread_mutex_lock(&xskdev_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static inline void
xskdev_list_unlock(void)
{
    int ret = pthread_mutex_unlock(&xskdev_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

/**
 * Preferred Busy Polling:
 *
 * The SO_PREFER_BUSY_POLL socket option was introduced in kernel v5.11. It can
 * deliver a performance improvement for sockets with heavy traffic loads and
 * can significantly improve single-core performance in this context.
 *
 * The feature is enabled by default in xskdev.
 *
 * The default 'busy_budget' is 256 and it represents the number of packets the
 * kernel will attempt to process in the netdev's NAPI context.
 *
 * It is also strongly recommended to set the following for optimal performance:
 *
 *    echo 2 | sudo tee /sys/class/net/ens786f1/napi_defer_hard_irqs
 *    echo 200000 | sudo tee /sys/class/net/ens786f1/gro_flush_timeout
 *
 * The above defers interrupts for interface ens786f1 and instead schedules its
 * NAPI context from a watchdog timer instead of from softirqs. More information
 * on this feature can be found at [1].
 *
 * [1] https://lwn.net/Articles/837010/
 */

static int
send_config_busy_poll_msg(int s, int fd, int busy_timeout, int busy_budget)
{
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg;
    struct iovec iov;
    char value[UDS_MAX_CMD_LEN] = {0};

    snprintf(value, sizeof(value), "%s,%d,%d", UDS_CFG_BUSY_POLL_MSG, busy_timeout, busy_budget);
    iov.iov_base = &value;
    iov.iov_len  = strnlen(value, sizeof(value));

    msg.msg_name       = NULL;
    msg.msg_namelen    = 0;
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_flags      = 0;
    msg.msg_control    = cmsgbuf;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));

    *(int *)CMSG_DATA(cmsg) = fd;
    int ret                 = sendmsg(s, &msg, 0);

    if (ret < 0)
        CNE_ERR_RET("sendmsg() returned error %s\n", strerror(errno));

    return 0;
}

/* Detect support for busy polling through setsockopt(). */
static int
configure_busy_poll(xskdev_info_t *xi)
{
    xskdev_rxq_t *rxq = &xi->rxq;
    int sock_opt      = 1;
    int fd            = xsk_socket__fd(rxq->xsk);
    int ret           = 0;

    if (!xi->busy_polling)
        return 0;

    if (xi->unprivileged) {
        int num_of_tries = 0;

        if (!xi->uds_info)
            return -1;

        xi->uds_info->priv = xi;
        if (send_config_busy_poll_msg(xi->uds_info->sock, fd, xi->busy_timeout, xi->busy_budget) <
            0)
            CNE_ERR_RET("send_config_busy_poll_msg() returned error\n");

        do {
            num_of_tries++;
            sleep(1);
        } while (xi->uds_info->xsk_uds_state != UDS_BUSY_POLL_ACK &&
                 xi->uds_info->xsk_uds_state != UDS_BUSY_POLL_NAK && num_of_tries < MAX_NUM_TRIES);

        if (xi->uds_info->xsk_uds_state == UDS_BUSY_POLL_ACK)
            return 0;

        CNE_ERR_RET("Failed to config busy poll\n");
    }

    ret = setsockopt(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt));
    if (ret < 0) {
        CNE_DEBUG("Failed to set SO_PREFER_BUSY_POLL\n");
        goto err_prefer;
    }

    sock_opt = xi->busy_timeout;
    ret      = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt));
    if (ret < 0) {
        CNE_DEBUG("Failed to set SO_BUSY_POLL\n");
        goto err_timeout;
    }

    sock_opt = xi->busy_budget;
    ret      = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, (void *)&sock_opt, sizeof(sock_opt));
    if (ret < 0)
        CNE_DEBUG("Failed to set SO_BUSY_POLL_BUDGET\n");
    else {
        CNE_INFO("Busy polling enabled: budget %u, timeout %u\n", xi->busy_budget,
                 xi->busy_timeout);
        return 0;
    }

    /* setsockopt failure - attempt to restore xsk to default state and
     * proceed without busy polling support.
     */
    sock_opt = 0;
    ret      = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt));
    if (ret < 0)
        CNE_ERR_RET("Failed to unset SO_BUSY_POLL\n");

err_timeout:
    sock_opt = 0;
    ret      = setsockopt(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt));
    if (ret < 0)
        CNE_ERR_RET("Failed to unset SO_PREFER_BUSY_POLL\n");

err_prefer:
    xi->busy_polling = false;
    return 0;
}

static int
fq_reserved(xskdev_info_t *xi, uint16_t size)
{
    struct xskdev_umem *ux   = xi->rxq.ux;
    struct xsk_ring_prod *fq = &ux->fq;
    void *bufs[size];
    uint16_t nb_bufs = size;
    uint32_t pos     = 0;
    int ret          = 0;

    ret = xsk_ring_prod__reserve(fq, nb_bufs, &pos);
    if (ret != nb_bufs)
        return -1;

    if (xskdev_buf_alloc(xi, bufs, nb_bufs) <= 0) {
        xi->stats.fq_alloc_failed++;
        return -1;
    }
    xi->stats.rx_buf_alloc += nb_bufs;

    for (int i = 0; i < nb_bufs; i++) {
        __u64 *fq_addr;
        void *buf       = bufs[i];
        uint64_t offset = (uint64_t)xskdev_buf_get_addr(xi, buf) - (uint64_t)xi->rxq.ux->umem_addr -
                          (uint64_t)xi->buf_mgmt.pool_header_sz;

        xskdev_buf_reset(xi, buf, xi->rxq.ux->obj_sz, xi->buf_mgmt.buf_headroom);

        fq_addr  = xsk_ring_prod__fill_addr(fq, pos++);
        *fq_addr = offset;
    }

    xsk_ring_prod__submit(fq, nb_bufs);

    return 0;
}

static int
fq_add(xskdev_info_t *xi)
{
    struct xskdev_umem *ux   = xi->rxq.ux;
    struct xsk_ring_prod *fq = &ux->fq;
    void *bufs[FQ_ADD_BURST_COUNT];
    uint16_t nb_bufs;
    uint32_t pos = 0;
    int nb;

    nb_bufs = FQ_ADD_BURST_COUNT;

    if (xskdev_buf_alloc(xi, (void **)bufs, nb_bufs) <= 0) {
        xi->stats.fq_alloc_failed++;
        return -1;
    }
    xi->stats.rx_buf_alloc += nb_bufs;

    nb = xsk_ring_prod__reserve(fq, nb_bufs, &pos);

    for (int i = 0; i < nb; i++) {
        void *buf       = bufs[i];
        uint64_t offset = (uint64_t)xskdev_buf_get_addr(xi, buf) - (uint64_t)ux->umem_addr -
                          (uint64_t)xi->buf_mgmt.pool_header_sz;

        xskdev_buf_reset(xi, buf, ux->obj_sz, xi->buf_mgmt.buf_headroom);

        *xsk_ring_prod__fill_addr(fq, pos++) = offset;
    }

    xsk_ring_prod__submit(fq, nb);

    if (nb != nb_bufs) {
        xskdev_buf_free(xi, &bufs[nb], nb_bufs - nb);
        xi->stats.fq_buf_freed += nb_bufs - nb;
    }
    xi->stats.fq_add_count += nb;

    return 0;
}

static __cne_always_inline uint16_t
__get_mbuf_rx_unaligned(void *_xi, void *umem_addr, const struct xdp_desc *d, void **bufs)
{
    xskdev_info_t *xi = _xi;
    uint64_t addr;
    uint64_t offset;

    addr   = d->addr; /* Get the offset to the buffer in umem */
    offset = xsk_umem__extract_offset((uint64_t)addr);
    addr   = xsk_umem__extract_addr((uint64_t)addr);

    /* Replace *bufs with the pointer to the umem packet data in umem */
    *bufs = (void *)xsk_umem__get_data(umem_addr, addr + xi->buf_mgmt.pool_header_sz);

    xskdev_buf_set_data_len(xi, *bufs, d->len);
    xskdev_buf_set_data(xi, *bufs, offset - xi->buf_mgmt.buf_headroom);

    return d->len;
}

static __cne_always_inline uint16_t
__get_mbuf_rx_aligned(void *_xi, void *umem_addr, const struct xdp_desc *d, void **bufs)
{
    xskdev_info_t *xi = _xi;
    void *addr;
    uint64_t offset, mask = (xi->buf_mgmt.frame_size - 1);

    addr   = (void *)d->addr; /* Get the offset to the buffer in umem */
    offset = (uint16_t)((uint64_t)addr & mask);
    addr   = CNE_PTR_SUB(addr, offset);

    /* Replace addr with the pointer to the umem packet data in umem */
    *bufs = xsk_umem__get_data(umem_addr, (uint64_t)addr + xi->buf_mgmt.pool_header_sz);

    xskdev_buf_set_data_len(xi, *bufs, d->len);
    xskdev_buf_set_data(xi, *bufs, offset - xi->buf_mgmt.buf_headroom);

    return d->len;
}

static __cne_always_inline int
__rx_burst(xskdev_info_t *xi, xskdev_rxq_t *rxq, void *umem_addr, uint32_t idx_rx, void **bufs,
           uint16_t rcvd)
{
    struct xsk_ring_cons *rx;
    const struct xdp_desc *rx_descs;
    int rx_bytes;
    void **p = bufs;

    rx = &rxq->rx;

    rx_bytes = 0;
    for (uint16_t n = 0; n < rcvd; n++) {
        rx_descs = xsk_ring_cons__rx_desc(rx, idx_rx++);
        rx_bytes += xi->__get_mbuf_rx(xi, umem_addr, rx_descs, p);
        p = xskdev_buf_inc_ptr(xi, p);
    }

    return rx_bytes;
}

static uint16_t
xskdev_rx_burst_default(void *_xi, void **bufs, uint16_t nb_pkts)
{
    xskdev_info_t *xi = (xskdev_info_t *)_xi;
    xskdev_rxq_t *rxq = &xi->rxq;
    struct xsk_ring_cons *rx;
    struct xskdev_umem *ux;
    uint64_t rx_bytes;
    void *umem_addr;
    unsigned int idx_rx;
    uint16_t rcvd;

    if ((ux = rxq->ux) == NULL)
        return 0;
    rx = &rxq->rx;

    xi->stats.rx_burst_called++;

    idx_rx = 0;
    rcvd   = xsk_ring_cons__peek(rx, nb_pkts, &idx_rx);
    if (!rcvd) {
        xi->stats.rx_ring_empty++;
        /*
         * Assuming a kernel >= 5.11 is used and busy_polling is enabled,
         * we can use the recvfrom() syscall for AF_XDP sockets.
         */
        if (xi->busy_polling) {
            xi->stats.rx_busypoll_wakeup++;
            (void)recvfrom(xsk_socket__fd(rxq->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        } else if (xi->needs_wakeup || xsk_ring_prod__needs_wakeup(&ux->fq)) {
            xi->stats.rx_poll_wakeup++;
            (void)poll(&rxq->fds, 1, POLL_TIMEOUT);
        }
        return 0;
    } else
        xi->stats.rx_rcvd_count += rcvd;

    umem_addr = ux->umem_addr;

    rx_bytes = 0;
    switch (rcvd) {
    case 256:
        rx_bytes += __rx_burst(xi, rxq, umem_addr, idx_rx, bufs, 256);
        break;
    case 128:
        rx_bytes += __rx_burst(xi, rxq, umem_addr, idx_rx, bufs, 128);
        break;
    case 64:
        rx_bytes += __rx_burst(xi, rxq, umem_addr, idx_rx, bufs, 64);
        break;
    case 32:
        rx_bytes += __rx_burst(xi, rxq, umem_addr, idx_rx, bufs, 32);
        break;
    case 16:
        rx_bytes += __rx_burst(xi, rxq, umem_addr, idx_rx, bufs, 16);
        break;
    case 8:
        rx_bytes += __rx_burst(xi, rxq, umem_addr, idx_rx, bufs, 8);
        break;
    default:
        rx_bytes += __rx_burst(xi, rxq, umem_addr, idx_rx, bufs, rcvd);
        break;
    }

    xi->stats.ipackets += rcvd;
    xi->stats.ibytes += rx_bytes;

    xsk_ring_cons__release(rx, rcvd);

    fq_add(xi);

    return (uint16_t)rcvd;
}

static __cne_always_inline void
kick_tx(xskdev_info_t *xi)
{
    xskdev_txq_t *txq = &xi->txq;

    if (xi->needs_wakeup || xsk_ring_prod__needs_wakeup(&txq->tx)) {
        xi->stats.tx_kicks++;

        if (unlikely(sendto(xsk_socket__fd(txq->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) < 0)) {

            if (errno == EAGAIN) {
                xi->stats.tx_kick_again++;

                if (sendto(xsk_socket__fd(txq->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0) < 0)
                    xi->stats.tx_kick_failed++;
            } else
                xi->stats.tx_kick_failed++;
        }
    }
}

#define uword_to_pointer(u, type) ((type)(uint64_t)(u))

static __cne_always_inline void *
__pull_cq_addr_unaligned(uint64_t addr, uint64_t umem_addr, __cne_unused uint64_t mask,
                         uint64_t pool_header_sz)
{
    return (void *)(umem_addr + xsk_umem__extract_addr(addr) + pool_header_sz);
}

static __cne_always_inline void *
__pull_cq_addr_aligned(uint64_t addr, uint64_t umem_addr, uint64_t mask,
                       __cne_unused uint64_t pool_header_sz)
{
    /* Trim off the lower bits of offset to get the mbuf offset in umem.
     * Add the offset to the umem start address to find the umem address. */
    return (void *)(umem_addr + (addr & mask) + pool_header_sz);
}

static void
pull_umem_cq(xskdev_info_t *xi)
{
    struct xskdev_umem *ux   = xi->txq.ux;
    struct xsk_ring_cons *cq = &ux->cq;
    void *mbufs[LPORT_TX_BATCH_SIZE + 1];
    unsigned int mbuf_cnt = LPORT_TX_BATCH_SIZE;
    uint64_t umem_addr    = (uint64_t)ux->umem_addr;
    uint64_t mask         = ~(xi->buf_mgmt.frame_size - 1);
    unsigned int n, idx_cq = 0;

    kick_tx(xi);

    n = xsk_ring_cons__peek(cq, mbuf_cnt, &idx_cq);
    if (unlikely(n == 0)) {
        xi->stats.cq_empty++;
        return;
    }

    for (uint32_t i = 0; i < n && i < mbuf_cnt; i++) {
        uint64_t offset = *xsk_ring_cons__comp_addr(cq, idx_cq++);

        mbufs[i] = xi->__pull_cq_addr(offset, umem_addr, mask, xi->buf_mgmt.pool_header_sz);
        xskdev_buf_reset(xi, mbufs[i], xi->rxq.ux->obj_sz, xi->buf_mgmt.buf_headroom);
    }

    xsk_ring_cons__release(cq, n);

    xskdev_buf_free(xi, mbufs, n);

    xi->stats.cq_buf_freed += n;
}

static __cne_always_inline uint64_t
__get_mbuf_addr_tx_unaligned(void *_xi, void *mb, uint64_t umem_addr)
{
    xskdev_info_t *xi = _xi;
    uint64_t addr, offset;

    addr   = xskdev_buf_get_addr(xi, mb) - umem_addr - (uint64_t)xi->buf_mgmt.pool_header_sz;
    addr   = xsk_umem__extract_addr((uint64_t)addr);
    offset = xskdev_buf_get_data(xi, mb) - xskdev_buf_get_addr(xi, mb) +
             (uint64_t)xi->buf_mgmt.pool_header_sz;
    offset = offset << XSK_UNALIGNED_BUF_OFFSET_SHIFT;

    return addr | offset;
}

static __cne_always_inline uint64_t
__get_mbuf_addr_tx_aligned(void *_xi, void *mb, uint64_t umem_addr)
{
    xskdev_info_t *xi = _xi;

    return (xskdev_buf_get_addr(xi, mb) - umem_addr - xi->buf_mgmt.pool_header_sz) +
           xskdev_buf_get_data(xi, mb);
}

static uint16_t
xskdev_tx_burst_locked(xskdev_info_t *xi, void **bufs, uint16_t nb_pkts)
{
    xskdev_txq_t *txq      = &xi->txq;
    struct xskdev_umem *ux = txq->ux;
    void **mbs             = bufs;
    uint32_t idx_tx        = 0;
    uint16_t nb_free       = 0;
    struct xdp_desc *desc;
    uint64_t tx_bytes = 0;
    uint64_t umem_addr;

    umem_addr = (uint64_t)ux->umem_addr;

    nb_free = xsk_ring_prod__reserve(&txq->tx, nb_pkts, &idx_tx);

    for (uint32_t j = 0; j < nb_free; j++) {
        desc       = xsk_ring_prod__tx_desc(&txq->tx, idx_tx++);
        desc->addr = xi->__get_mbuf_addr_tx(xi, *mbs, umem_addr);
        desc->len  = xskdev_buf_get_data_len(xi, *mbs);

        tx_bytes += xskdev_buf_get_data_len(xi, *mbs);
        mbs = xskdev_buf_inc_ptr(xi, mbs);
    }

    xsk_ring_prod__submit(&txq->tx, nb_free);

    pull_umem_cq(xi);

    xi->stats.opackets += nb_free;
    xi->stats.obytes += tx_bytes;

    return nb_free;
}

static uint16_t
xskdev_tx_burst_default(void *_xi, void **bufs, uint16_t nb_pkts)
{
    xskdev_info_t *xi = (xskdev_info_t *)_xi;
    uint16_t ret;

    if (xskdev_use_tx_lock) {
        int err;

        err = pthread_mutex_lock(&xi->tx_lock);
        if (err) {
            CNE_ERR("Failed to lock xskdev: %d: %s\n", err, strerror(err));
            return 0;
        }

        ret = xskdev_tx_burst_locked(xi, bufs, nb_pkts);

        err = pthread_mutex_unlock(&xi->tx_lock);
        if (err)
            CNE_ERR("Failed to unlock xskdev: %d: %s\n", err, strerror(err));
    } else {
        /* Lock is disabled, call tx_burst function directly. */
        ret = xskdev_tx_burst_locked(xi, bufs, nb_pkts);
    }

    return ret;
}

static struct xskdev_umem *
umem_create(lport_cfg_t *cfg)
{
    struct xskdev_umem *xu;
    struct xsk_umem_config umem_cfg = {0};
    uint32_t hw_rx_nb_desc          = 0;
    int ret;

    xu = calloc(1, sizeof(struct xskdev_umem));
    if (xu == NULL)
        CNE_ERR_GOTO(err, "Failed to allocate xskdev_umem structure\n");

    xu->umem_size = cfg->umem_size;
    xu->umem_addr = (void *)cfg->umem_addr;
    xu->obj_sz    = cfg->bufsz;

    /*
     * We recommend that you set the fill ring size >= HW RX ring size +
     * AF_XDP RX ring size. Make sure you fill up the fill ring
     * with buffers at regular intervals, and you will with this setting
     * avoid allocation failures in the driver. These are usually quite
     * expensive since drivers have not been written to assume that
     * allocation failures are common. For regular sockets, kernel
     * allocated memory is used that only runs out in OOM situations
     * that should be rare.
     */
    umem_cfg.fill_size      = (cfg->rx_nb_desc * 2);
    umem_cfg.comp_size      = cfg->tx_nb_desc;
    umem_cfg.frame_size     = cfg->bufsz;
    umem_cfg.frame_headroom = cfg->buf_mgmt.buf_headroom;

    if (cfg->flags & LPORT_UMEM_UNALIGNED_BUFFERS)
        umem_cfg.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;

    xu->fq_size = umem_cfg.fill_size;

    ret = netdev_get_ring_params(cfg->ifname, &hw_rx_nb_desc, NULL);
    if (ret)
        CNE_ERR("netdev_get_ring_params failure: %d\n", ret);
    else if (umem_cfg.fill_size < hw_rx_nb_desc + cfg->rx_nb_desc)
        CNE_INFO(
            "For %s recommend setting fill size (currently %d) to be >= HW RX ring size (%d) + "
            "AF_XDP Rx ring size (%d)\n",
            cfg->ifname, umem_cfg.fill_size, hw_rx_nb_desc, cfg->rx_nb_desc);

    ret = xsk_umem__create(&xu->umem, xu->umem_addr, xu->umem_size, &xu->fq, &xu->cq, &umem_cfg);
    if (ret)
        CNE_ERR_GOTO(err, "Failed to create umem '%s'\n", strerror(errno));

    return xu;

err:
    free(xu);
    return NULL;
}

static int
xskdev_get_channel(const char *if_name, int *max_queues, int *combined_queues)
{
    struct ethtool_channels channels;
    struct ifreq ifr;
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (void *)&channels;
    strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ret) {

        if (errno == EOPNOTSUPP) {
            ret = 0;
        } else {
            ret = -errno;
            goto out;
        }
    }

    if (channels.max_combined == 0 || errno == EOPNOTSUPP) {
        /* If the device says it has no channels, then all traffic
         * is sent to a single stream, so max queues = 1.
         */
        if (max_queues)
            *max_queues = 1;
        if (combined_queues)
            *combined_queues = 1;
    } else {
        if (max_queues)
            *max_queues = channels.max_combined;
        if (combined_queues)
            *combined_queues = channels.combined_count;
    }

out:
    close(fd);
    return ret;
}

static int
xskdev_recv_xsk_fd(xskdev_info_t *xi)
{
    char xsk_map_fd_msg[UDS_MAX_CMD_LEN];
    int len = 0;

    if (!xi || !xi->uds_info)
        return -1;

    xi->uds_info->priv = xi;

    CNE_DEBUG("Received %s msg \n", UDS_HOST_OK_MSG);
    strlcpy(xsk_map_fd_msg, UDS_XSK_MAP_FD_MSG, sizeof(xsk_map_fd_msg));
    strlcat(xsk_map_fd_msg, ",", sizeof(xsk_map_fd_msg));
    len = strlcat(xsk_map_fd_msg, xi->ifname, sizeof(xsk_map_fd_msg));

    if (send(xi->uds_info->sock, xsk_map_fd_msg, len, 0) <= 0)
        CNE_ERR_RET("Failed to send /xsk_map_fd message\n");
    else
        CNE_DEBUG("Sent %s msg\n", xsk_map_fd_msg);

    int num_of_tries = 0;

    do {
        num_of_tries++;
        sleep(1);
    } while (xi->uds_info->xsk_uds_state != UDS_GOT_FD &&
             xi->uds_info->xsk_uds_state != UDS_FD_NAK && num_of_tries < MAX_NUM_TRIES);
    CNE_DEBUG("waiting for the xsk_map_fd the num of tries is %d\n", num_of_tries);
    if (xi->uds_info->xsk_uds_state == UDS_GOT_FD) {
        xi->xsk_map_fd = xi->uds_info->xsk_map_fd;
        CNE_DEBUG("the xsk_map_fd is %d\n", xi->xsk_map_fd);
        xi->uds_info->xsk_uds_state = UDS_HOST_OK;        // reset for next lport
        return 0;
    }

    CNE_ERR_RET("Failed to receive fd\n");
}

static __cne_always_inline int
xskdev_buf_alloc_default(void *arg, void **bufs, uint16_t nb_bufs)
{
    pktmbuf_info_t *pi = (pktmbuf_info_t *)arg;
    pktmbuf_t **mbs    = (pktmbuf_t **)bufs;

    return pktmbuf_alloc_bulk(pi, mbs, nb_bufs);
}

static __cne_always_inline void
xskdev_buf_free_default(__cne_unused void *arg, void **bufs, uint16_t nb_bufs)
{
    pktmbuf_free_bulk((pktmbuf_t **)bufs, nb_bufs);
}

static __cne_always_inline void
xskdev_buf_set_data_len_default(void *mb, int len)
{
    pktmbuf_t *p = (pktmbuf_t *)mb;

    pktmbuf_data_len(p) = len;
}

static __cne_always_inline void
xskdev_buf_set_len_default(void *mb, int len)
{
    pktmbuf_t *p = (pktmbuf_t *)mb;

    pktmbuf_buf_len(p) = len;
}

static __cne_always_inline void
xskdev_buf_set_data_default(void *mb, uint64_t off)
{
    pktmbuf_t *p = (pktmbuf_t *)mb;

    pktmbuf_data_off(p) = off;
}

static __cne_always_inline void
xskdev_buf_reset_default(void *mb, uint32_t buf_len, size_t headroom)
{
    /* Buffer reset of data is done in pktmbuf_alloc() */
    CNE_SET_USED(mb);
    CNE_SET_USED(buf_len);
    CNE_SET_USED(headroom);
}

static __cne_always_inline uint16_t
xskdev_buf_get_data_len_default(void *mb)
{
    pktmbuf_t *p = (pktmbuf_t *)mb;

    return pktmbuf_data_len(p);
}

static __cne_always_inline uint64_t
xskdev_buf_get_data_default(void *mb)
{
    pktmbuf_t *p = (pktmbuf_t *)mb;

    return pktmbuf_data_off(p);
}

static __cne_always_inline uint64_t
xskdev_buf_get_addr_default(void *mb)
{
    pktmbuf_t *p = (pktmbuf_t *)mb;

    return (uint64_t)pktmbuf_buf_addr(p);
}

static __cne_always_inline void **
xskdev_buf_inc_ptr_default(void **mb)
{
    pktmbuf_t **p = (pktmbuf_t **)mb;

    return (void **)++p;
}

static void
xskdev_buf_set_buf_mgmt_ops(lport_buf_mgmt_t *dst, lport_buf_mgmt_t *src)
{
    if (dst && src)
        memcpy(dst, src, sizeof(lport_buf_mgmt_t));
}

xskdev_info_t *
xskdev_socket_create(struct lport_cfg *c)
{
    struct xsk_socket_config cfg = {0};
    struct xskdev_umem *umem     = NULL;
    xskdev_info_t *xi            = NULL;
    int ret, combined_queue_cnt = 0;
    unsigned int if_index;

    if_index = if_nametoindex(c->ifname);
    if (!if_index)
        CNE_ERR_GOTO(err, "if_nametoindex(%s) failed: %s\n", c->ifname, strerror(errno));

    if ((xi = calloc(1, sizeof(xskdev_info_t))) == NULL)
        CNE_ERR_GOTO(err, "Failed to allocate xskdev_info_t structure\n");

    strlcpy(xi->ifname, c->ifname, sizeof(xi->ifname));
    xi->xsk_map_fd = -1;

    if (c->flags & LPORT_UNPRIVILEGED) {
        /* If UDS is set then call xskdev_recv_xsk_fd to setup a UDS client
         * and receive the XSK_MAP_FD.
         * We will need (to wait) a flag or re checking of the value of the FD (latter preferred) to
         * indicate we have completed reception before moving onto the socket create stage
         */
        xi->uds_info = (uds_info_t *)c->xsk_uds;

        ret = xskdev_recv_xsk_fd(xi);
        if (ret < 0)
            CNE_ERR_GOTO(err, "Failed to receive xsk map fd\n");
    }

    if (xskdev_use_tx_lock) {
        ret = cne_mutex_create(&xi->tx_lock, 0);
        if (ret)
            CNE_ERR_GOTO(err, "Failed to initialize xskdev tx lock: %s\n", strerror(errno));
    }

    xi->if_index = if_index;

    if (xskdev_get_channel(xi->ifname, NULL, &combined_queue_cnt))
        CNE_ERR_GOTO(err, "Failed to get channel info of interface: %s\n", xi->ifname);

    if (c->qid >= combined_queue_cnt)
        CNE_ERR_GOTO(err, "Specified queue ID %d is larger than combined queue count %d.\n", c->qid,
                     combined_queue_cnt);

    /* Use default values when a field is zero */
    CNE_DEFAULT_SET(c->rx_nb_desc, 0, XSK_RING_PROD__DEFAULT_NUM_DESCS);
    CNE_DEFAULT_SET(c->tx_nb_desc, 0, XSK_RING_CONS__DEFAULT_NUM_DESCS);

    if (c->flags & LPORT_USER_MANAGED_BUFFERS) {
        if (!c->buf_mgmt.buf_arg || !c->buf_mgmt.buf_alloc || !c->buf_mgmt.buf_free)
            CNE_ERR_GOTO(err, "Buffer management alloc/free/arg pointers are not set\n");

        if (!c->buf_mgmt.buf_set_data || !c->buf_mgmt.buf_set_data_len)
            CNE_ERR_GOTO(err, "Buffer management pointers to set data are not set\n");

        if (!c->buf_mgmt.buf_get_data || !c->buf_mgmt.buf_get_data_len)
            CNE_ERR_GOTO(err, "Buffer management pointers to get data are not set\n");

        if (!c->buf_mgmt.buf_reset || !c->buf_mgmt.buf_inc_ptr)
            CNE_ERR_GOTO(err, "Buffer management pointers to reset/inc buffer a are not set\n");

        if (!c->buf_mgmt.buf_get_addr)
            CNE_ERR_GOTO(err, "Buffer management pointers to get buffer addr is are not set\n");

        if (c->buf_mgmt.frame_size == 0)
            CNE_ERR_GOTO(err, "Buffer management invalid frame size\n");

        if (c->buf_mgmt.buf_headroom == 0)
            CNE_ERR_GOTO(err, "Buffer management invalid headroom size\n");

        xskdev_buf_set_buf_mgmt_ops(&xi->buf_mgmt, &c->buf_mgmt);
    } else {
        xi->buf_mgmt.buf_arg = xi->pi = c->pi; /*Buffer pool*/
        xi->buf_mgmt.buf_alloc        = xskdev_buf_alloc_default;
        xi->buf_mgmt.buf_free         = xskdev_buf_free_default;
        xi->buf_mgmt.buf_set_len      = xskdev_buf_set_len_default;
        xi->buf_mgmt.buf_set_data_len = xskdev_buf_set_data_len_default;
        xi->buf_mgmt.buf_set_data     = xskdev_buf_set_data_default;
        xi->buf_mgmt.buf_get_data_len = xskdev_buf_get_data_len_default;
        xi->buf_mgmt.buf_get_data     = xskdev_buf_get_data_default;
        xi->buf_mgmt.buf_inc_ptr      = xskdev_buf_inc_ptr_default;
        xi->buf_mgmt.buf_headroom     = sizeof(pktmbuf_t);
        xi->buf_mgmt.buf_get_addr     = xskdev_buf_get_addr_default;
        xi->buf_mgmt.buf_reset        = xskdev_buf_reset_default;
        xi->buf_mgmt.frame_size       = c->bufsz;
        xi->buf_mgmt.pool_header_sz   = 0;
    }

    if (!c->buf_mgmt.buf_rx_burst || !c->buf_mgmt.buf_tx_burst) {
        /* If no external rx and tx functions were registered*/
        xi->buf_mgmt.buf_rx_burst = xskdev_rx_burst_default;
        xi->buf_mgmt.buf_tx_burst = xskdev_tx_burst_default;
    }

    if (!(c->flags & LPORT_UMEM_UNALIGNED_BUFFERS)) {
        xi->__get_mbuf_addr_tx = __get_mbuf_addr_tx_aligned;
        xi->__pull_cq_addr     = __pull_cq_addr_aligned;
        xi->__get_mbuf_rx      = __get_mbuf_rx_aligned;
    } else {
        xi->buf_mgmt.unaligned_buff = true;
        xi->__get_mbuf_addr_tx      = __get_mbuf_addr_tx_unaligned;
        xi->__pull_cq_addr          = __pull_cq_addr_unaligned;
        xi->__get_mbuf_rx           = __get_mbuf_rx_unaligned;
    }

    umem = umem_create(c);
    if (!umem)
        CNE_ERR_GOTO(err, "Failed to create UMEM\n");

    xi->rxq.ux = umem;
    xi->txq.ux = umem;

    xi->unprivileged = (c->flags & LPORT_UNPRIVILEGED) ? true : false;
    xi->needs_wakeup = (c->flags & LPORT_FORCE_WAKEUP) ? true : false;
    xi->busy_polling = (c->flags & LPORT_BUSY_POLLING) ? true : false;
    xi->skb_mode     = (c->flags & LPORT_SKB_MODE) ? true : false;
    xi->shared_umem  = (c->flags & LPORT_SHARED_UMEM) ? true : false;

    xi->xdp_flags    = XDP_FLAGS_UPDATE_IF_NOEXIST;
    xi->xdp_flags    = ((xi->skb_mode) ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE) | xi->xdp_flags;
    cfg.xdp_flags    = xi->xdp_flags;
    cfg.bind_flags   = (xi->skb_mode) ? XDP_COPY | XDP_USE_NEED_WAKEUP : XDP_USE_NEED_WAKEUP;
    cfg.rx_size      = c->rx_nb_desc;
    cfg.tx_size      = c->tx_nb_desc;
    cfg.libbpf_flags = xi->unprivileged ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0;

    if (xi->busy_polling) {
        xi->busy_budget  = (c->busy_budget) ? c->busy_budget : AF_XDP_DFLT_BUSY_BUDGET;
        xi->busy_timeout = (c->busy_timeout) ? c->busy_timeout : AF_XDP_DFLT_BUSY_TIMEOUT;
    }
#ifdef CAN_USE_XSK_UMEM_SHARED
    if (xi->shared_umem) {
        CNE_INFO("UMEM shared memory is enabled for %s\n", c->name);
        ret = xsk_socket__create_shared(&xi->rxq.xsk, xi->ifname, c->qid, umem->umem, &xi->rxq.rx,
                                        &xi->txq.tx, &xi->rxq.ux->fq, &xi->txq.ux->cq, &cfg);
    } else
        ret = xsk_socket__create(&xi->rxq.xsk, xi->ifname, c->qid, umem->umem, &xi->rxq.rx,
                                 &xi->txq.tx, &cfg);
    if (ret)
        CNE_ERR_GOTO(err, "Failed to create xsk socket. ret = %d %s\n", ret, strerror(errno));
#else
    if (xi->shared_umem)
        CNE_INFO("Shared UMEM is enabled, but not supported by kernel or libbpf\n");

    ret = xsk_socket__create(&xi->rxq.xsk, xi->ifname, c->qid, umem->umem, &xi->rxq.rx, &xi->txq.tx,
                             &cfg);
    if (ret)
        CNE_ERR_GOTO(err, "Failed to create xsk socket. ret = %d %s\n", ret, strerror(errno));
#endif

    xi->rxq.fds.fd     = xsk_socket__fd(xi->rxq.xsk);
    xi->rxq.fds.events = POLLIN;

    xi->txq.xsk        = xi->rxq.xsk;
    xi->txq.fds.fd     = xsk_socket__fd(xi->rxq.xsk);
    xi->txq.fds.events = POLLIN;

    if (xi->unprivileged) {
        ret = xsk_socket__update_xskmap(xi->rxq.xsk, xi->xsk_map_fd);
        if (ret)
            CNE_ERR_GOTO(err, "Update of BPF map failed. %s\n", strerror(errno));
    } else {
        /* Getting the program ID must be after the xdp_socket__create() call */
#if USE_LIBBPF_8
        if (bpf_xdp_query_id(xi->if_index, xi->xdp_flags, &xi->prog_id))
            CNE_ERR_GOTO(err, "bpf_get_link_xdp_id failed. %s\n", strerror(errno));
#else
        if (bpf_get_link_xdp_id(xi->if_index, &xi->prog_id, xi->xdp_flags))
            CNE_ERR_GOTO(err, "bpf_get_link_xdp_id failed. %s\n", strerror(errno));
#endif
    }

    CNE_DEBUG("Program ID %u, if_index %d, if_name '%s'\n", xi->prog_id, xi->if_index, xi->ifname);

    if (configure_busy_poll(xi))
        CNE_INFO("Busy polling is not supported\n");

    /* Fill fq ring with available fq size. */
    if (fq_reserved(xi, umem->fq_size) < 0)
        CNE_ERR_GOTO(err, "Failed reserved fill of FQ\n");

    xskdev_list_lock();
    TAILQ_INSERT_TAIL(&xskdev_list, xi, next);
    xskdev_list_unlock();

    return xi;
err:
    xskdev_socket_destroy(xi);
    return NULL;
}

void
xskdev_socket_destroy(xskdev_info_t *xi)
{
    uint32_t curr_prog_id = 0;

    if (xi) {
        CNE_DEBUG("ifindex %d, %s, prog_id %u\n", xi->if_index, xi->ifname, xi->prog_id);
        if (xi->if_index) {
            if (xi->unprivileged == 0) {
#if USE_LIBBPF_8
                if (bpf_xdp_query_id(xi->if_index, xi->xdp_flags, &curr_prog_id))
#else
                if (bpf_get_link_xdp_id(xi->if_index, &curr_prog_id, xi->xdp_flags))
#endif
                    CNE_ERR("bpf_get_link_xdp_id failed\n");
                else {
                    /* Try to remove the bpf program */
                    if (xi->prog_id == curr_prog_id)
#if USE_LIBBPF_8
                        bpf_xdp_detach(xi->if_index, xi->xdp_flags, NULL);
#else
                        bpf_set_link_xdp_fd(xi->if_index, -1, xi->xdp_flags);
#endif
                    else if (curr_prog_id)
                        CNE_INFO("program on interface changed %d, not removing\n", curr_prog_id);
                }
            }
            if (xi->rxq.xsk)
                xsk_socket__delete(xi->rxq.xsk);

            if (xi->rxq.ux && xi->rxq.ux->umem) {
                (void)xsk_umem__delete(xi->rxq.ux->umem);
                xi->rxq.ux->umem = NULL;
            }

            if (xskdev_use_tx_lock) {
                int err = cne_mutex_destroy(&xi->tx_lock);

                if (err)
                    CNE_ERR("Failed to destroy xskdev tx lock: %s\n", strerror(errno));
            }
            xskdev_list_lock();
            if (xi->next.tqe_prev)
                TAILQ_REMOVE(&xskdev_list, xi, next);
            xskdev_list_unlock();
        }
        free(xi);
    }
}

int
xskdev_stats_get(xskdev_info_t *xi, lport_stats_t *stats)
{
    struct xdp_statistics xdp_stats = {0};
    socklen_t optlen                = sizeof(struct xdp_statistics);
    int ret, fd;

    memcpy(stats, &xi->stats, sizeof(lport_stats_t));

    fd  = xsk_socket__fd(xi->rxq.xsk);
    ret = getsockopt(fd, SOL_XDP, XDP_STATISTICS, &xdp_stats, &optlen);
    if (ret != 0)
        CNE_ERR_RET("getsockopt() failed for XDP_STATISTICS for fd %d, %s, %d, %d.\n", fd,
                    xi->ifname, xi->prog_id, xi->if_index);

    /* Adjust statistics to be consistent after a xskdev_stats_reset() call */
    stats->imissed    = (xdp_stats.rx_dropped - xi->orig_stats.rx_dropped);
    stats->rx_invalid = (xdp_stats.rx_invalid_descs - xi->orig_stats.rx_invalid_descs);
    stats->tx_invalid = (xdp_stats.tx_invalid_descs - xi->orig_stats.tx_invalid_descs);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    stats->rx_ring_full = (xdp_stats.rx_ring_full - xi->orig_stats.rx_ring_full);
    stats->rx_fill_ring_empty =
        (xdp_stats.rx_fill_ring_empty_descs - xi->orig_stats.rx_fill_ring_empty_descs);
    stats->tx_ring_empty = (xdp_stats.tx_ring_empty_descs - xi->orig_stats.tx_ring_empty_descs);
#endif
    return 0;
}

int
xskdev_stats_reset(xskdev_info_t *xi)
{
    socklen_t optlen = sizeof(struct xdp_statistics);
    int ret, fd;

    if (!xi)
        return -1;

    memset(&xi->stats, 0, sizeof(lport_stats_t));

    /* Grab the new set of XDP stats to simulate a reset of the stats */
    fd  = xsk_socket__fd(xi->rxq.xsk);
    ret = getsockopt(fd, SOL_XDP, XDP_STATISTICS, &xi->orig_stats, &optlen);
    if (ret != 0)
        CNE_ERR_RET("getsockopt() failed for XDP_STATISTICS for fd %d, %s, %d, %d.\n", fd,
                    xi->ifname, xi->prog_id, xi->if_index);

    return 0;
}

static void
prt_stats(const char *msg, uint32_t prod, uint32_t cons, uint32_t size)
{
    cne_printf("[orange]%s [magenta]prod[]: [cyan]%12u [magenta]cons[]: [cyan]%12u "
               "[magenta]Delta[]: [cyan]%u[]\n",
               msg, prod, cons, (prod - (cons - size)));
}

void
xskdev_dump(xskdev_info_t *xi, uint32_t flags)
{
    if (!xi)
        return;

    xskdev_list_lock();
    cne_printf("[yellow]%-12s [magenta]if_index[]: [cyan]%d [magenta]BPF program ID[]: [cyan]%d ",
               xi->ifname, xi->if_index, xi->prog_id);

    struct xskdev_umem *ux = xi->rxq.ux;
    cne_printf("[magenta]umem_addr[]: [cyan]%p [magenta]umem_size [cyan]%'ld[]\n", ux->umem_addr,
               ux->umem_size);
    cne_printf("             [magenta]UMEM Count[]: [cyan]%ld [magenta]buffer size[]: [cyan]%d[]\n",
               ux->umem_size / ux->obj_sz, ux->obj_sz);

    if (flags & XSKDEV_STATS_FLAG) {
        lport_stats_t stats, *s = &stats;

        cne_printf("   [magenta]Stats[]:\n");
        memset(s, 0, sizeof(stats));

        xskdev_stats_get(xi, s);

        cne_printf("     [orange]RX [magenta]Pkts[]: [cyan]%'16lu [magenta]Bytes[]: [cyan]%'16lu "
                   "[magenta]Invalid[]: [cyan]%'lu[]\n",
                   s->ipackets, s->ibytes, s->rx_invalid);
        cne_printf("     [orange]TX [magenta]Pkts[]: [cyan]%'16lu [magenta]Bytes[]: [cyan]%'16lu "
                   "[magenta]Invalid[]: [cyan]%'lu[]\n",
                   s->opackets, s->obytes, s->tx_invalid);
        cne_printf("\n");
    }

    if (flags & XSKDEV_RX_FQ_TX_CQ_FLAG) {
        struct xskdev_queue *r, *t;
        struct xsk_ring_prod *p;
        struct xsk_ring_cons *c;

        r = &xi->rxq;
        t = &xi->txq;
        p = &xi->rxq.ux->fq;
        c = &xi->txq.ux->cq;

        cne_printf("  [magenta]Rings/Queues[]:\n");
        cne_printf("     [magenta]fd[]: [cyan]%d [magenta]umem[]: [cyan]%p [magenta]xsk socket[]: "
                   "[cyan]%p[]\n",
                   r->fds.fd, r->ux->umem, r->xsk);
        cne_printf(
            "     [orange]Rx[]: [cyan]%p [magenta]size[]: [cyan]%4u [magenta]mask[]: [cyan]%#x[]\n",
            r->rx.ring, r->rx.size, r->rx.mask);
        cne_printf(
            "     [orange]FQ[]: [cyan]%p [magenta]size[]: [cyan]%4u [magenta]mask[]: [cyan]%#x[]\n",
            p->ring, p->size, p->mask);
        cne_printf(
            "     [orange]Tx[]: [cyan]%p [magenta]size[]: [cyan]%4u [magenta]mask[]: [cyan]%#x[]\n",
            t->rx.ring, t->rx.size, t->rx.mask);
        cne_printf("     [orange]CQ[]: [cyan]%p [magenta]size[]: [cyan]%4u [magenta]mask[]: "
                   "[cyan]%#x[]\n\n",
                   c->ring, c->size, c->mask);

        cne_printf("  [magenta]Cached queue values[]:\n");
        prt_stats("     Rx", r->rx.cached_prod, r->rx.cached_cons, 0);
        prt_stats("     FQ", p->cached_prod, p->cached_cons, p->size);
        prt_stats("     Tx", t->tx.cached_prod, t->tx.cached_cons, t->tx.size);
        prt_stats("     CQ", c->cached_prod, c->cached_cons, 0);

        cne_printf("  [magenta]Uncached queue values[]:\n");
        prt_stats("     Rx", *r->rx.producer, *r->rx.consumer, 0);
        prt_stats("     FQ", *p->producer, *p->consumer, 0);
        prt_stats("     Tx", *t->tx.producer, *t->tx.consumer, 0);
        prt_stats("     CQ", *c->producer, *c->consumer, 0);
    }
    cne_printf("\n");
    xskdev_list_unlock();
}

void
xskdev_dump_all(uint32_t flags)
{
    xskdev_info_t *xi;

    xskdev_list_lock();
    TAILQ_FOREACH (xi, &xskdev_list, next) {
        xskdev_dump(xi, flags);
    }
    xskdev_list_unlock();
}

int
xskdev_print_stats(const char *name, lport_stats_t *s, bool dbg_stats)
{
    if (!name || !s)
        return -1;

    cne_printf("[yellow]----- [cyan]%s [beige]port stats [yellow]-----[]\n", name);
    cne_printf("[beige]ipackets           : [cyan]%'lu[]\n", s->ipackets);
    cne_printf("[beige]opackets           : [cyan]%'lu[]\n", s->opackets);
    cne_printf("[beige]ibytes             : [cyan]%'lu[]\n", s->ibytes);
    cne_printf("[beige]obytes             : [cyan]%'lu[]\n", s->obytes);
    cne_printf("[beige]ierrors            : [cyan]%'lu[]\n", s->ierrors);
    cne_printf("[beige]oerrors            : [cyan]%'lu[]\n", s->oerrors);
    cne_printf("[beige]imissed            : [cyan]%'lu[]\n", s->imissed);
    cne_printf("[beige]odropped           : [cyan]%'lu[]\n", s->odropped);
    cne_printf("[beige]rx_invalid         : [cyan]%'lu[]\n", s->rx_invalid);
    cne_printf("[beige]tx_invalid         : [cyan]%'lu[]\n", s->tx_invalid);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    cne_printf("[beige]rx_ring_full       : [cyan]%'lu[]\n", s->rx_ring_full);
    cne_printf("[beige]rx_fill_ring_empty : [cyan]%'lu[]\n", s->rx_fill_ring_empty);
    cne_printf("[beige]tx_ring_empty      : [cyan]%'lu[]\n", s->tx_ring_empty);
#endif

    if (dbg_stats) {
        cne_printf("[yellow]----- [cyan]Debug Stats [yellow]-----[]\n");
        cne_printf("[beige]rx_ring_empty      : [cyan]%'lu[]\n", s->rx_ring_empty);
        cne_printf("[beige]rx_buf_alloc       : [cyan]%'lu[]\n", s->rx_buf_alloc);
        cne_printf("[beige]rx_busypoll_wakeup : [cyan]%'lu[]\n", s->rx_busypoll_wakeup);
        cne_printf("[beige]rx_poll_wakeup     : [cyan]%'lu[]\n", s->rx_poll_wakeup);
        cne_printf("[beige]rx_rcvd_count      : [cyan]%'lu[]\n", s->rx_rcvd_count);
        cne_printf("[beige]rx_burst_called    : [cyan]%'lu[]\n", s->rx_burst_called);

        cne_printf("[beige]fq_add_count       : [cyan]%'lu[]\n", s->fq_add_count);
        cne_printf("[beige]fq_alloc_failed    : [cyan]%'lu[]\n", s->fq_alloc_failed);
        cne_printf("[beige]fq_buf_freed       : [cyan]%'lu[]\n", s->fq_buf_freed);

        cne_printf("[beige]tx_kicks           : [cyan]%'lu[]\n", s->tx_kicks);
        cne_printf("[beige]tx_kick_failed     : [cyan]%'lu[]\n", s->tx_kick_failed);
        cne_printf("[beige]tx_kick_again      : [cyan]%'lu[]\n", s->tx_kick_again);
        cne_printf("[beige]tx_ring_full       : [cyan]%'lu[]\n", s->tx_ring_full);
        cne_printf("[beige]tx_copied          : [cyan]%'lu[]\n", s->tx_copied);

        cne_printf("[beige]cq_empty           : [cyan]%'lu[]\n", s->cq_empty);
        cne_printf("[beige]cq_buf_freed       : [cyan]%'lu[]\n", s->cq_buf_freed);
    }

    cne_printf("\n");
    return 0;
}

CNE_INIT_PRIO(xskdev_constructor, START)
{
    TAILQ_INIT(&xskdev_list);

    if (cne_mutex_create(&xskdev_list_mutex, PTHREAD_MUTEX_RECURSIVE) < 0)
        CNE_RET("mutex init(xskdev_list_mutex) failed\n");
}
