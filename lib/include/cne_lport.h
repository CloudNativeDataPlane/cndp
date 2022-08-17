/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CNE_LPORT_H_
#define _CNE_LPORT_H_

/**
 * @file
 *
 * lport configuration structure and information on lports.
 */

#include <stdint.h>        // for uint16_t, uint32_t
#include <sys/types.h>
#include <stdbool.h>
#include <pktmbuf.h>

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LPORT_NAME_LEN             32
#define LPORT_FRAME_SIZE           2048
#define LPORT_MBUF_OVERHEAD        sizeof(struct pkt_buf)
#define LPORT_DATA_HEADROOM        XDP_PACKET_HEADROOM
#define LPORT_DFLT_RX_NUM_DESCS    XSK_RING_CONS__DEFAULT_NUM_DESCS
#define LPORT_DFLT_TX_NUM_DESCS    (XSK_RING_CONS__DEFAULT_NUM_DESCS * 2)
#define LPORT_FRAME_SHIFT          11 /* Log2(2048) of LPORT_FRAME_SIZE to avoid a divide */
#define LPORT_DFLT_START_QUEUE_IDX 0
#define LPORT_DFLT_QUEUE_COUNT     1
#define LPORT_RX_BATCH_SIZE        256
#define LPORT_TX_BATCH_SIZE        256

typedef int (*buf_alloc_t)(void *arg, void **bufs, uint16_t nb_pkts);
typedef void (*buf_free_t)(void *arg, void **bufs, uint16_t nb_pkts);
typedef void (*buf_set_len_t)(void *buf, int len);
typedef void (*buf_set_data_len_t)(void *buf, int len);
typedef void (*buf_set_data_t)(void *buf, uint64_t off);
typedef void (*buf_reset_t)(void *buf, uint32_t buf_len, size_t headroom);
typedef void **(*buf_inc_ptr_t)(void **buf);
typedef uint16_t (*buf_get_data_len_t)(void *buf);
typedef uint64_t (*buf_get_data_t)(void *buf);
typedef uint64_t (*buf_get_addr_t)(void *buf);
typedef uint16_t (*buf_rx_burst_t)(void *arg, void **bufs, uint16_t nb_pkts);
typedef uint16_t (*buf_tx_burst_t)(void *arg, void **bufs, uint16_t nb_pkts);

typedef struct lport_buf_mgmt {
    buf_alloc_t buf_alloc;               /**< Allocate buffer routine */
    buf_free_t buf_free;                 /**< Free buffer routine */
    buf_set_len_t buf_set_len;           /**< Set buffer length routine */
    buf_set_data_len_t buf_set_data_len; /**< Set buffer data length routine */
    buf_set_data_t buf_set_data;         /**< Set buffer data pointer routine */
    buf_reset_t buf_reset;               /**< Buffer reset function */
    buf_get_data_len_t buf_get_data_len; /**< Get buffer data length routine */
    buf_get_data_t buf_get_data;         /**< Get buffer data pointer routine */
    buf_get_addr_t buf_get_addr;         /**< Get buffer base address routine */
    buf_inc_ptr_t buf_inc_ptr;           /**< Increment the buffer pointer */
    uint32_t frame_size;                 /**< Frame size in umem */
    size_t buf_headroom;                 /**< Buffer headroom size */
    size_t pool_header_sz;               /**< Pool header size for external buffer pool*/
    void *buf_arg;                       /**< Argument for the buffer mgmt routines */
    buf_rx_burst_t buf_rx_burst;         /**< RX burst callback */
    buf_tx_burst_t buf_tx_burst;         /**< TX burst callback */
    bool unaligned_buff;                 /**< Unaligned buffer support */
} lport_buf_mgmt_t;

typedef struct lport_cfg {
    char name[LPORT_NAME_LEN];     /**< logical port name */
    char ifname[LPORT_NAME_LEN];   /**< Interface name or netdev name */
    char pmd_name[LPORT_NAME_LEN]; /**< Name of the PMD i.e. net_af_xdp, net_ring */
    uint16_t flags;                /**< Flags to configure the AF_XDP interface */
    uint16_t qid;                  /**< Queue ID */
    uint32_t bufcnt;               /**< Number of buffers in the pool */
    uint32_t bufsz;                /**< Size of the buffers in the UMEM space */
    uint32_t rx_nb_desc;           /**< Number of RX descriptor entries */
    uint32_t tx_nb_desc;           /**< Number of TX descriptor entries */
    uint16_t busy_timeout;         /**< 1-65535 or 0 - use default value, value in milliseconds */
    uint16_t busy_budget;          /**< -1 disabled, 0 use default, >0 budget value */
    void *addr;                    /**< Start address of the buffers */
    char *umem_addr;               /**< Address of the allocated UMEM area */
    char *pmd_opts;                /**< options string from jasonc file */
    size_t umem_size;              /**< Size of the umem region */
    pktmbuf_info_t *pi;            /**< pktmbuf_info_t structure pointer */
    void *xsk_uds;                 /**< The UDS to connect to get xsk FDs */
    lport_buf_mgmt_t buf_mgmt;     /**< Buffer management functions */
} lport_cfg_t;

/**< lport_cfg.flags configuration bits */
#define LPORT_UNPRIVILEGED           (1 << 0) /**< Inhibit Loading the BPF program & config of busy poll */
#define LPORT_FORCE_WAKEUP           (1 << 1) /**< Force a wakeup, for CVL NICs */
#define LPORT_SKB_MODE               (1 << 2) /**< Force the SKB_MODE or copy mode */
#define LPORT_BUSY_POLLING           (1 << 3) /**< Enable busy polling */
#define LPORT_SHARED_UMEM            (1 << 4) /**< Enable UMEM Shared mode if available */
#define LPORT_USER_MANAGED_BUFFERS   (1 << 5) /**< Enable Buffer Manager outside of CNDP */
#define LPORT_UMEM_UNALIGNED_BUFFERS (1 << 6) /**< Enable unaligned frame UMEM support */

typedef struct lport_stats {
    uint64_t ipackets;           /**< Total number of successfully received packets. */
    uint64_t opackets;           /**< Total number of successfully transmitted packets.*/
    uint64_t ibytes;             /**< Total number of successfully received bytes. */
    uint64_t obytes;             /**< Total number of successfully transmitted bytes. */
    uint64_t ierrors;            /**< Total number of erroneous received packets. */
    uint64_t oerrors;            /**< Total number of failed transmitted packets. */
    uint64_t imissed;            /**< Total number of missed RX packets */
    uint64_t odropped;           /**< Total number of dropped TX packets */
    uint64_t rx_invalid;         /**< Number of invalid RX descriptors */
    uint64_t tx_invalid;         /**< Number of invalid TX descriptors */
                                 /* RX debug stats */
    uint64_t rx_ring_empty;      /**< RX Ring is empty */
    uint64_t rx_buf_alloc;       /**< Number of buffers allocated */
    uint64_t rx_busypoll_wakeup; /**< Number times recvfrom is called for busy poll */
    uint64_t rx_poll_wakeup;     /**< Number of times poll() called */
    uint64_t rx_rcvd_count;      /**< Number of packets received */
    uint64_t rx_burst_called;    /**< Number of times rx_burst was called */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    uint64_t rx_ring_full;       /**< Number of times RX ring is full */
    uint64_t rx_fill_ring_empty; /**< Number of times the RX fill ring was empty */
    uint64_t tx_ring_empty;      /**< Number of times the TX ring is empty */
#endif
    /* FQ debug stats */
    uint64_t fq_add_count;    /**< Number of FQ buffers added */
    uint64_t fq_alloc_failed; /**< Number of buffer allocations failed */
    uint64_t fq_buf_freed;    /**< Number of buffers freed from FQ add */
                              /* TX debug stats */
    uint64_t tx_kicks;        /**< Number of times we need to do a tx kick */
    uint64_t tx_kick_failed;  /**< Number of times the tx kick failed */
    uint64_t tx_kick_again;   /**< Number of times tx kick needed to be restarted */
    uint64_t tx_ring_full;    /**< TX Ring is full */
    uint64_t tx_copied;       /**< TX packet was copied */
                              /* CQ debug stats */
    uint64_t cq_empty;        /**< CQ is empty counter */
    uint64_t cq_buf_freed;    /**< Number of buffers freed */
} lport_stats_t;

#ifdef __cplusplus
}
#endif

#endif /* _CNE_LPORT_H_ */
