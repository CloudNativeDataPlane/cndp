/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _XSKDEV_H_
#define _XSKDEV_H_

/**
 * @file
 *
 * CNE XSK low-level abstraction
 *
 * This file provides a low-level abstraction for applications to XSK APIs.
 */

#include <poll.h>           // for pollfd
#include <pthread.h>        // for pthread_mutex_t, pthread_mutex_init, pthre...
#include <stdint.h>         // for uint16_t, uint32_t
#include <stdio.h>          // for FILE, NULL, size_t
#if USE_LIBXDP
#include <xdp/xsk.h>
#else
#include <bpf/xsk.h>
#endif
#include <net/if.h>        // for IF_NAMESIZE

#include <cne_common.h>        // for CNDP_API, CNE_STD_C11
#include <cne_lport.h>         // for lport_stats_t, buf_alloc_t, buf_free_t
#include <pktmbuf.h>           // for pktmbuf_t
#include <uds.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#ifndef XDP_USE_NEED_WAKEUP
/* If this option is set, the driver might go sleep and in that case
 * the XDP_RING_NEED_WAKEUP flag in the fill and/or Tx rings will be
 * set. If it is set, the application need to explicitly wake up the
 * driver with a poll() (Rx and Tx) or sendto() (Tx only). If you are
 * running the driver and the application on the same core, you should
 * use this option so that the kernel will yield to the user space
 * application.
 */
#define XDP_USE_NEED_WAKEUP (1 << 3)
#endif

#define XSKDEV_STATS_FLAG       (1 << 0) /**< flag to xskdev_dump() to dump out the stats */
#define XSKDEV_RX_FQ_TX_CQ_FLAG (1 << 1) /**< Flag to dump the RX/FQ/TX/CQ rings/queues */

#define AF_XDP_DFLT_BUSY_BUDGET  64
#define AF_XDP_DFLT_BUSY_TIMEOUT 20

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif

typedef void *(*xskdev_pull_cq_addr_t)(uint64_t addr, uint64_t umem_addr, uint64_t mask,
                                       uint64_t pool_header_sz);
typedef uint64_t (*xskdev_get_mbuf_addr_tx_t)(void *xi, void *mb, uint64_t umem_addr);
typedef uint16_t (*xskdev_get_mbuf_t)(void *xi, void *umem_addr, const struct xdp_desc *d,
                                      void *buf);
typedef uint16_t (*xskdev_get_mbuf_rx_t)(void *xi, void *umem_addr, const struct xdp_desc *d,
                                         void **buf);

struct xskdev_umem {
    struct xsk_ring_prod fq; /**< The Fill Queue XSK structure */
    struct xsk_ring_cons cq; /**< The Completion Queue XSK  structure */
    struct xsk_umem *umem;   /**< XSK UMEM information */
    void *umem_addr;         /**< Address of the UMEM */
    size_t umem_size;        /**< Number of bytes in the UMEM */
    uint32_t obj_sz;         /**< Size of each buffer in the UMEM */
    uint32_t fq_size;        /**< Size of the fill queue ring */
};

struct xskdev_queue {
    CNE_STD_C11
    union {
        struct xsk_ring_cons rx; /**< RX Ring information */
        struct xsk_ring_prod tx; /**< TX Ring information */
    };
    struct xskdev_umem *ux; /**< xskdev UMEM information */
    struct xsk_socket *xsk; /**< xsk socket information */
    struct pollfd fds;      /**< File descriptor pollfd structure */
};

/* Defines to map the xskdev_queue to be Rx/Tx like queues */
typedef struct xskdev_queue xskdev_rxq_t;
typedef struct xskdev_queue xskdev_txq_t;

typedef struct xskdev_info {
    TAILQ_ENTRY(xskdev_info) next; /**< Next xskdev_info structure entry */
    char ifname[IF_NAMESIZE];      /**< Ifname string */
    unsigned int if_index;         /**< If_index of the interface */
    uint32_t prog_id;              /**< BPF program ID */
    pktmbuf_info_t *pi;            /**< The pktmbuf information structure pointer */
    xskdev_rxq_t rxq;              /**< RX queue */
    xskdev_txq_t txq;              /**< TX queue */
    lport_stats_t stats;           /**< Stats for the lport interface */
    pthread_mutex_t tx_lock;       /**< Ensure mutual exclusion to Tx resources */
    int xdp_flags;                 /**< Copy of the configuration flags */
    uint32_t busy_timeout;         /**< Busy polling timeout value */
    uint32_t busy_budget;          /**< Busy polling budget value */
    uds_info_t *uds_info;          /**< UDS info struct */
    int xsk_map_fd;                /**< xsk map file descriptor from UDS */

    /* byte flags to mirror the lport_cfg_t.flags bits */
    bool unprivileged; /**< Inhibit privileged ops (BPF program load & config of busy poll) */
    bool needs_wakeup; /**< Force the lport to use wakeup calls */
    bool skb_mode;     /**< Force lport to use SKB Copy mode */
    bool busy_polling; /**< Enable the lport to use busy polling if available */
    bool shared_umem;  /**< Enable Shared UMEM support */

    lport_buf_mgmt_t buf_mgmt; /**< Buffer management routines structure */
    xskdev_get_mbuf_addr_tx_t
        __get_mbuf_addr_tx;               /**< Internal function to set the mbuf address on tx */
    xskdev_get_mbuf_rx_t __get_mbuf_rx;   /**< Internal function to get the mbuf address on rx */
    xskdev_pull_cq_addr_t __pull_cq_addr; /**< Internal function to pull the complete queue */
    struct xdp_statistics orig_stats; /**< Internal XDP statistics structure of original stats */
} xskdev_info_t;

/**
 * Create a xsk socket helper routine using lport configuration
 *
 * @param c
 *   The lport configuration structure
 * @return
 *   The pointer to the xskdev_info_t structure or NULL on error
 */
CNDP_API xskdev_info_t *xskdev_socket_create(struct lport_cfg *c);

/**
 * Close the xsk socket and free resources.
 *
 * @param xi
 *    The xskdev_info_t structure returned by xskdev_socket_create() routine
 */
CNDP_API void xskdev_socket_destroy(xskdev_info_t *xi);

/**
 * Receive packets from the interface
 *
 * @param xi
 *   The void * type of xskdev_info_t structure
 * @param bufs
 *   The list or vector or pktmbufs structures to send on the interface.
 * @param nb_pkts
 *   The number of pktmbuf_t pointers in the list or vector bufs
 * @return
 *   The number of packet sent to the interface or 0 if RX is empty.
 */
CNDP_API __cne_always_inline uint16_t
xskdev_rx_burst(xskdev_info_t *xi, void **bufs, uint16_t nb_pkts)
{
    return xi->buf_mgmt.buf_rx_burst(xi, bufs, nb_pkts);
}

/**
 * Send buffers to be transmitted
 *
 * @param xi
 *   The void * type of xskdev_info_t structure
 * @param bufs
 *   The list or vector or pktmbufs structures to send on the interface.
 * @param nb_pkts
 *   The number of pktmbuf_t pointers in the list or vector bufs
 * @return
 *   The number of packet sent to the interface or 0 if RX is empty.
 */
CNDP_API __cne_always_inline uint16_t
xskdev_tx_burst(xskdev_info_t *xi, void **bufs, uint16_t nb_pkts)
{
    return xi->buf_mgmt.buf_tx_burst(xi, bufs, nb_pkts);
}

/**
 * Get the stats for the interface
 *
 * @param xi
 *   The xskdev_info_t structure pointer
 * @param stats
 *   The lport stats structure to fill in
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int xskdev_stats_get(xskdev_info_t *xi, lport_stats_t *stats);

/**
 * Reset or clear the stats for an interface
 *
 * @param xi
 *   The xskdev_info_t structure pointer
 * @return
 *   0 on success or -1 on error.
 */
CNDP_API int xskdev_stats_reset(xskdev_info_t *xi);

/**
 * Debug routine to dump out information about xskdev data
 *
 * @param xi
 *   The xskdev_info_t structure pointer
 * @param flags
 *   Flags used to control the amount of information dumped.
 */
CNDP_API void xskdev_dump(xskdev_info_t *xi, uint32_t flags);

/**
 * Debug routine dump all of the xskdev interfaces.
 *
 * @param flags
 *   Flags used to control the amount of information dumped.
 */
CNDP_API void xskdev_dump_all(uint32_t flags);

/**
 * Print the port statistics information.
 *
 * @param name
 *   A name used to identify the port.
 * @param s
 *   The pointer to the port statistics
 * @param dbg_stats
 *   Print debug statistics if true.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int xskdev_print_stats(const char *name, lport_stats_t *s, bool dbg_stats);

/**
 * Return the internal buffer management argument pointer.
 *
 * @param xi
 *   The xskdev_info_t structure pointer.
 * @return
 *   The void * used for buffer allocation and free routines.
 */
CNDP_API __cne_always_inline void *
xskdev_arg_get(xskdev_info_t *xi)
{
    return xi->buf_mgmt.buf_arg;
}

/**
 * Allocate the number of buffers requested.
 *
 * @param xi
 *    The pointer to the xskdev_info structure.
 * @param bufs
 *    The array of buffer pointers to store the allocated buffers.
 * @param nb_bufs
 *    The max number of buffers pointers to allocate.
 * @return
 *    The number of bufs allocated in the bufs array.
 */
CNDP_API __cne_always_inline int
xskdev_buf_alloc(xskdev_info_t *xi, void **bufs, uint16_t nb_bufs)
{
    return xi->buf_mgmt.buf_alloc(xskdev_arg_get(xi), bufs, nb_bufs);
}

/**
 * Free the number of buffers listed in the bufs array.
 *
 * @param xi
 *    The pointer to the xskdev_info struct.
 * @param bufs
 *    The array of buf pointers to free.
 * @param nb_bufs
 *    The max number of xbuf pointers to free in the array.
 */
CNDP_API __cne_always_inline void
xskdev_buf_free(xskdev_info_t *xi, void **bufs, uint16_t nb_bufs)
{
    xi->buf_mgmt.buf_free(xskdev_arg_get(xi), bufs, nb_bufs);
}

/**
 * Set the buffer Length.
 *
 * @param xi
 *    The pointer to the xskdev_info struct.
 * @param buf
 *    The buffer to set the length of.
 * @param len
 *    The length to set the buffer length to.
 */

CNDP_API __cne_always_inline void
xskdev_buf_set_len(xskdev_info_t *xi, void *buf, int len)
{
    xi->buf_mgmt.buf_set_len(buf, len);
}

/**
 * Set the buffer data Length.
 *
 * @param xi
 *    The pointer to the xskdev_info struct.
 * @param buf
 *    The buffer to set the data length of.
 * @param len
 *    The length to set the buffer data length to.
 */

CNDP_API __cne_always_inline void
xskdev_buf_set_data_len(xskdev_info_t *xi, void *buf, int len)
{
    xi->buf_mgmt.buf_set_data_len(buf, len);
}

/**
 * Set the buffer data pointer
 *
 * @param xi
 *    The pointer to the xskdev_info struct.
 * @param buf
 *    The buffer to set the data pointer of.
 * @param off
 *    The offset to set the data pointer to.
 */
CNDP_API __cne_always_inline void
xskdev_buf_set_data(xskdev_info_t *xi, void *buf, uint64_t off)
{
    xi->buf_mgmt.buf_set_data(buf, off);
}

/**
 * Get the buffer data length.
 *
 * @param xi
 *    The pointer to the xskdev_info struct.
 * @param buf
 *    The buffer to get the data length of.
 * @return
 *   The data length of the buffer.
 */
CNDP_API __cne_always_inline uint16_t
xskdev_buf_get_data_len(xskdev_info_t *xi, void *buf)
{
    return xi->buf_mgmt.buf_get_data_len(buf);
}

/**
 * Get the buffer data pointer.
 *
 * @param xi
 *    The pointer to the xskdev_info struct.
 * @param buf
 *    The array of xbuf pointers to free.
 * @return
 *   The address of the data pointer.
 */
CNDP_API __cne_always_inline uint64_t
xskdev_buf_get_data(xskdev_info_t *xi, void *buf)
{
    return xi->buf_mgmt.buf_get_data(buf);
}

/**
 * Get the virtual address of the segment buffer.
 *
 * @param xi
 *    The pointer to the xskdev_info struct.
 * @param buf
 *    The buffer to get the address of.
 * @return
 *   The the virtual address of the segment buffer.
 */
CNDP_API __cne_always_inline uint64_t
xskdev_buf_get_addr(xskdev_info_t *xi, void *buf)
{
    return xi->buf_mgmt.buf_get_addr(buf);
}

/**
 * Increment the buffer array pointer
 *
 * @param xi
 *    The pointer to the xskdev_info struct.
 * @param buf
 *    The buffer ptr to increment.
 */
CNDP_API __cne_always_inline void **
xskdev_buf_inc_ptr(xskdev_info_t *xi, void **buf)
{
    return xi->buf_mgmt.buf_inc_ptr(buf);
}

/**
 * Reset a buffer.
 *
 * @param xi
 *    The pointer to the xskdev_info struct.
 * @param buf
 *    The buffer to reset.
 * @param buf_len
 *    The max data length able to be contained in the buffer.
 *    If the buffer is 2K and it contains a mbuf like header then
 *    buf_len = (2K - sizeof(mbuf)).
 * @param headroom
 *    The buffer headroom to offset the data pointer by (if needed).
 */
CNDP_API __cne_always_inline void
xskdev_buf_reset(xskdev_info_t *xi, void *buf, uint32_t buf_len, size_t headroom)
{
    xi->buf_mgmt.buf_reset(buf, buf_len, headroom);
}

#ifdef __cplusplus
}
#endif

#endif /* _XSKDEV_H_ */
