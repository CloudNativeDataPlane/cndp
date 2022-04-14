/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */
#ifndef __INCLUDE_IP4_REWRITE_PRIV_H__
#define __INCLUDE_IP4_REWRITE_PRIV_H__

#include <net/ethernet.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <cne_common.h>

#define CNE_GRAPH_IP4_REWRITE_MAX_NH  64
#define CNE_GRAPH_IP4_REWRITE_MAX_LEN 56

/**
 * @internal
 *
 * Ipv4 rewrite next hop header data structure. Used to store port specific
 * rewrite data.
 */
struct ip4_rewrite_nh_header {
    uint16_t rewrite_len; /**< Header rewrite length. */
    uint16_t tx_node;     /**< Tx node next index identifier. */
    uint16_t enabled;     /**< NH enable flag */
    uint16_t rsvd;
    union {
        struct {
            struct ether_addr dst;
            /**< Destination mac address. */
            struct ether_addr src;
            /**< Source mac address. */
        };
        uint8_t rewrite_data[CNE_GRAPH_IP4_REWRITE_MAX_LEN];
        /**< Generic rewrite data */
    };
};

/**
 * @internal
 *
 * Ipv4 node main data structure.
 */
struct ip4_rewrite_node_main {
    struct ip4_rewrite_nh_header nh[CNE_GRAPH_IP4_REWRITE_MAX_NH];
    /**< Array of next hop header data */
    uint16_t next_index[CNE_MAX_ETHPORTS];
    /**< Next index of each configured port. */
};

/**
 * @internal
 *
 * Get the ipv4 rewrite node.
 *
 * @retrun
 *   Pointer to the ipv4 rewrite node.
 */
struct cne_node_register *ip4_rewrite_node_get(void);

/**
 * @internal
 *
 * Set the Edge index of a given port_id.
 *
 * @param port_id
 *   Ethernet port identifier.
 * @param next_index
 *   Edge index of the Given Tx node.
 */
int ip4_rewrite_set_next(uint16_t port_id, uint16_t next_index);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_REWRITE_PRIV_H__ */
