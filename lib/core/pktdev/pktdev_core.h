/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef __PKTDEV_CORE_H_
#define __PKTDEV_CORE_H_

#include <stdbool.h>
/**
 * @file
 *
 * CNE Ethernet Device internal header.
 *
 * This header contains internal data types. But they are still part of the
 * public API because they are used by inline functions in the published API.
 *
 * Applications should not use these directly.
 */

/*
 * Definitions of all functions exported by an Ethernet driver through the
 * the generic structure of type *pktdev_ops* supplied in the *cne_pktdev*
 * structure associated with an Ethernet device.
 */
struct cne_pktdev;

typedef int (*pkt_dev_start_t)(struct cne_pktdev *dev);
/**< @internal Function used to start a configured Ethernet device. */

typedef void (*pkt_dev_stop_t)(struct cne_pktdev *dev);
/**< @internal Function used to stop a configured Ethernet device. */

typedef int (*pkt_dev_admin_st_up_t)(struct cne_pktdev *dev);
/**< @internal Function used to set up admin state of packet stream. */

typedef int (*pkt_dev_admin_st_down_t)(struct cne_pktdev *dev);
/**< @internal Function used to set down state of packet stream. */

typedef void (*pkt_dev_close_t)(struct cne_pktdev *dev);
/**< @internal Function used to close a configured Ethernet device. */

typedef int (*pkt_dev_infos_get_t)(struct cne_pktdev *dev, struct pktdev_info *dev_info);
/**< @internal Get specific information of an Ethernet device. */

typedef int (*eth_link_update_t)(struct cne_pktdev *dev, int wait_to_complete);
/**< @internal Get link speed, duplex mode and state (up/down) of an Ethernet device. */

typedef int (*eth_stats_get_t)(struct cne_pktdev *dev, lport_stats_t *igb_stats);
/**< @internal Get global I/O statistics of an Ethernet device. */

/**
 * @internal
 * Reset global I/O statistics of an Ethernet device to 0.
 *
 * @param dev
 *   pktdev handle of lport.
 *
 * @return
 *   Negative errno value on error, 0 on success.
 *
 * @retval 0
 *   Success, statistics has been reset.
 * @retval -ENOTSUP
 *   Resetting statistics is not supported.
 * @retval -EINVAL
 *   Resetting statistics is not valid.
 * @retval -ENOMEM
 *   Not enough memory to get the stats.
 */
typedef int (*eth_stats_reset_t)(struct cne_pktdev *dev);

/**
 * @internal Force mbufs to be from TX ring.
 *
 * @param txq
 *   The pointer to the TX queue structure.
 * @param free_cnt
 *   The number of packets to clean up
 * @return
 *   0 on success or -1 on error
 */
typedef int (*eth_tx_done_cleanup_t)(void *txq, uint32_t free_cnt);

/**
 * @internal Retrieve input packets from a receive queue of an Ethernet device.
 *
 * @param rxq
 *   The RX queue structure pointer
 * @param rx_pkts
 *   The array of mbuf pointers to receive
 * @param nb_pkts
 *   The number of mbufs to receive, also must be <= size of the rx_pkts array
 * @return
 *   The number of mbufs received
 */
typedef uint16_t (*eth_rx_burst_t)(void *rxq, pktmbuf_t **rx_pkts, uint16_t nb_pkts);

/**
 * @internal Send output packets on a transmit queue of an Ethernet device.
 *
 * @param rxq
 *   The TX queue structure pointer
 * @param tx_pkts
 *   The array of mbuf pointers to send
 * @param nb_pkts
 *   The number of mbufs to send, also must be <= size of the tx_pkts array
 * @return
 *   The number of mbufs sent
 */
typedef uint16_t (*eth_tx_burst_t)(void *txq, pktmbuf_t **tx_pkts, uint16_t nb_pkts);

/**
 * @internal Prepare output packets on a transmit queue of an Ethernet device.
 *
 * @param txq
 *   The TX queue pointer
 * @param tx_pkts
 *   Array of TX packets to process
 * @param nb_pkts
 *   The number of packets to process in tx_pkts array
 * @return
 *   0 on success or -1 on error
 */
typedef uint16_t (*eth_tx_prep_t)(void *txq, pktmbuf_t **tx_pkts, uint16_t nb_pkts);

/**
 * @internal Set a MAC address into Receive Address Register
 *
 * @param dev
 *   The pktdev device structure pointer
 * @param mac_addr
 *   The pointer to where the MAC address is located for the update.
 * @return
 *   0 on success or -1 on error
 */
typedef int (*eth_mac_addr_set_t)(struct cne_pktdev *dev, struct ether_addr *mac_addr);

/**
 * @internal Allocate mbufs from the PMD, e.g. used for sending a packet.
 *
 * @param dev
 *   The pktdev device structure pointer
 * @param bufs
 *   The array of mbuf pointers to place the allocated mbuf pointers
 * @param nb_pkts
 *   The number of mbufs to allocate, also must be <= size of the rx_pkts array
 * @return
 *   Number of mbufs allocated
 */
typedef int (*eth_pkt_alloc)(struct cne_pktdev *dev, pktmbuf_t **bufs, uint16_t nb_pkts);

/**
 * Possible states of an pktdev lport.
 */
enum pktdev_state {
    PKTDEV_UNUSED = 0, /** Device is unused before being probed. */
    PKTDEV_ACTIVE,     /** Device is active when allocated. */
};

/**
 * @internal A structure containing the functions exported by an Ethernet driver.
 */
struct pktdev_ops {
    pkt_dev_admin_st_up_t admin_state_up;     /**< Start pkt stream. */
    pkt_dev_admin_st_down_t admin_state_down; /**< Stop pkt stream. */
    pkt_dev_close_t dev_close;                /**< Close device. */
    pkt_dev_infos_get_t dev_infos_get;        /**< Get device info. */
    eth_mac_addr_set_t mac_addr_set;          /**< Set a MAC address. */
    eth_link_update_t link_update;            /**< Get device link state. */
    eth_stats_get_t stats_get;                /**< Get generic device statistics. */
    eth_stats_reset_t stats_reset;            /**< Reset generic device statistics. */
    eth_tx_done_cleanup_t tx_done_cleanup;    /**< Free tx ring mbufs */
    eth_pkt_alloc pkt_alloc;                  /**< Allocate pktmbuf_t function pointers */
};

/**
 * @internal
 * The generic data structure associated with each ethernet device.
 *
 * Pointers to burst-oriented packet receive and transmit functions are
 * located at the beginning of the structure, along with the pointer to
 * where all the data elements for the particular device are stored in shared
 * memory. This split allows the function pointer and driver data to be per-
 * process, while the actual configuration data for the device is shared.
 */
struct cne_pktdev {
    eth_rx_burst_t rx_pkt_burst;      /**< Pointer to PMD receive function */
    eth_tx_burst_t tx_pkt_burst;      /**< Pointer to PMD transmit function */
    eth_tx_prep_t tx_pkt_prepare;     /**< Pointer to PMD transmit prepare function */
    struct pktdev_data *data;         /**< Pointer to device data */
    struct pktdev_driver *drv;        /**< Pointer to driver data */
    void *process_private;            /**< Pointer to per-process device data */
    const struct pktdev_ops *dev_ops; /**< Functions exported by PMD */
    enum pktdev_state state;          /**< Flag indicating the lport state */
} __cne_cache_aligned;

extern struct cne_pktdev pktdev_devices[CNE_MAX_ETHPORTS];

#define PKTDEV_NAME_MAX_LEN 16
/**
 * @internal
 * The data part, with no function pointers, associated with each ethernet device.
 *
 * This structure is safe to place in shared memory to be common among different
 * processes in a multi-process configuration.
 */
struct pktdev_data {
    char name[PKTDEV_NAME_MAX_LEN];   /**< Unique identifier name */
    char ifname[PKTDEV_NAME_MAX_LEN]; /**< Netdev or interface name */
    void *rx_queue;                   /**< RX queue pointer */
    void *tx_queue;                   /**< TX queues pointer */
    bool admin_state;                 /**< Packet stream admin state */
    void *dev_private;                /**< PMD-specific private data. */
    uint32_t min_rx_buf_size;         /**< Common RX buffer size handled by all queues. */
    struct ether_addr *mac_addr;      /**< Ethernet MAC address if needed */
    uint16_t lport_id;                /**< Device [external] lport identifier. */
    uint16_t numa_node;               /**< NUMA node connection. */
    struct offloads *offloads;        /**< Checksum offload. */
} __cne_cache_aligned;

/**
 * @internal
 * The pool of *cne_pktdev* structures. The size of the pool
 * is configured at compile-time in the <pktdev.c> file.
 */
extern struct cne_pktdev cne_pktdevices[];

#endif /* __PKTDEV_CORE_H_ */
