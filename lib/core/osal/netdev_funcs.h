/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _NETDEV_FUNCS_H_
#define _NETDEV_FUNCS_H_

/**
 * @file
 * API for netdev modification like setting promiscuous mode, link up/down, etc.
 */

#include <stdint.h>            // for uint32_t, uint16_t
#include <cne_common.h>        // for CNDP_API

struct ether_addr;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A structure used to retrieve link-level information of an Ethernet port.
 */
__extension__ struct netdev_link {
    uint32_t link_speed;       /**< ETH_SPEED_NUM_ */
    uint16_t link_duplex : 1;  /**< ETH_LINK_[HALF/FULL]_DUPLEX */
    uint16_t link_autoneg : 1; /**< ETH_LINK_[AUTONEG/FIXED] */
    uint16_t link_status : 1;  /**< ETH_LINK_[DOWN/UP] */
} __attribute__((aligned(8))); /**< aligned for atomic64 read/write */

/* Utility constants */
#define ETH_LINK_HALF_DUPLEX 0 /**< Half-duplex connection (see link_duplex). */
#define ETH_LINK_FULL_DUPLEX 1 /**< Full-duplex connection (see link_duplex). */
#define ETH_LINK_DOWN        0 /**< Link is down (see link_status). */
#define ETH_LINK_UP          1 /**< Link is up (see link_status). */
#define ETH_LINK_FIXED       0 /**< No autonegotiation (see link_autoneg). */
#define ETH_LINK_AUTONEG     1 /**< Autonegotiated (see link_autoneg). */

/**
 * Ethernet numeric link speeds in Mbps
 */
#define CNE_ETH_SPEED_NUM_NONE    0          /**< Not defined */
#define CNE_ETH_SPEED_NUM_10M     10         /**<  10 Mbps */
#define CNE_ETH_SPEED_NUM_100M    100        /**< 100 Mbps */
#define CNE_ETH_SPEED_NUM_1G      1000       /**<   1 Gbps */
#define CNE_ETH_SPEED_NUM_2_5G    2500       /**< 2.5 Gbps */
#define CNE_ETH_SPEED_NUM_5G      5000       /**<   5 Gbps */
#define CNE_ETH_SPEED_NUM_10G     10000      /**<  10 Gbps */
#define CNE_ETH_SPEED_NUM_20G     20000      /**<  20 Gbps */
#define CNE_ETH_SPEED_NUM_25G     25000      /**<  25 Gbps */
#define CNE_ETH_SPEED_NUM_40G     40000      /**<  40 Gbps */
#define CNE_ETH_SPEED_NUM_50G     50000      /**<  50 Gbps */
#define CNE_ETH_SPEED_NUM_56G     56000      /**<  56 Gbps */
#define CNE_ETH_SPEED_NUM_100G    100000     /**< 100 Gbps */
#define CNE_ETH_SPEED_NUM_200G    200000     /**< 200 Gbps */
#define CNE_ETH_SPEED_NUM_400G    400000     /**< 400 Gbps */
#define CNE_ETH_SPEED_NUM_UNKNOWN UINT32_MAX /**< Unknown */

/**
 * A structure used to retrieve netdev offload information.
 */
__extension__ struct offloads {
    uint32_t tx_checksum_offload;
    uint32_t rx_checksum_offload;
};

/**
 * Set a netdev flags.
 *
 * @param if_name
 *   The lport identifier of the Ethernet device.
 * @param flags
 *   The flags to set in the netdev
 * @param mask
 *   The mask used to filter flags
 * @return
 *   (-1) on error or 0 on success
 */
CNDP_API int netdev_change_flags(const char *if_name, uint32_t flags, uint32_t mask);

/**
 * Enable promiscuous mode on the given netdev
 *
 * @param if_name
 *   The lport identifier of the Ethernet device.
 * @return
 *   0 success or -1 on error
 */
CNDP_API int netdev_promiscuous_enable(const char *if_name);

/**
 * Disable promiscuous mode on the given netdev
 *
 * @param if_name
 *   The lport identifier of the Ethernet device.
 * @return
 *   0 success or -1 on error
 */
CNDP_API int netdev_promiscuous_disable(const char *if_name);

/**
 * Return the value of promiscuous mode for an netdev device.
 *
 * @param if_name
 *   The lport identifier of the Ethernet device.
 * @return
 *   - (1) if promiscuous is enabled
 *   - (0) if promiscuous is disabled.
 *   - (-1) on error
 */
CNDP_API int netdev_promiscuous_get(const char *if_name);

/**
 * Link up an Ethernet device.
 *
 * @param if_name
 *   The port identifier of the Ethernet device.
 * @return
 *   0 success or -1 on error
 */
CNDP_API int netdev_set_link_up(const char *if_name);

/**
 * Link down an Ethernet device.
 *
 * @param if_name
 *   The port identifier of the Ethernet device.
 * @return
 *   0 success or -1 on error
 */
CNDP_API int netdev_set_link_down(const char *if_name);

/**
 * Get MAC address from interface name
 *
 * @param ifname
 *    The interface name string or if_name
 * @param eth_addr
 *    The location to return the MAC address if a valid address.
 * @return
 *    -1 on error or o on success
 */
CNDP_API int netdev_get_mac_addr(const char *ifname, struct ether_addr *eth_addr);

/**
 * Get link status
 *
 * @param ifname
 *    The interface name string or if_name
 * @param link
 *    The link info: speed, duplex, autoneg.
 * @return
 *    -1 on error or o on success
 */
CNDP_API int netdev_get_link(const char *ifname, struct netdev_link *link);

/**
 * Get offloads status
 *
 * @param ifname
 *    The interface name string or if_name
 * @param off
 *    The offloads info: checksum...
 * @return
 *    -1 on error or o on success
 */
CNDP_API int netdev_get_offloads(const char *ifname, struct offloads *off);

/**
 * Get the number of channels/queues on a device
 *
 * @param ifname
 *    The interface name string or if_name
 * @return
 *    negative error number on error or number of channels on success
 */
CNDP_API int netdev_get_channels(const char *ifname);

/**
 * Get the number of descriptors in a ring
 *
 * @param ifname
 *    The interface name string or if_name
 * @param rx_nb_desc
 *    The location to return the number of RX descriptors (maybe NULL)
 * @param tx_nb_desc
 *    The location to return the number of TX descriptors (maybe NULL)
 *    Either rx_nb_desc or tx_nb_desc maybe NULL but not both
 * @return
 *    negative error number on error or 0 success
 */
CNDP_API int netdev_get_ring_params(const char *ifname, uint32_t *rx_nb_desc, uint32_t *tx_nb_desc);

#ifdef __cplusplus
}
#endif

#endif /* _NETDEV_FUNCS_H_ */
