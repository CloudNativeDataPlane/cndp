/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
 */
#ifndef __INCLUDE_ETH_RX_PRIV_H__
#define __INCLUDE_ETH_RX_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct eth_rx_node_elem;
struct eth_rx_node_ctx;

/**
 * @internal
 *
 * Ethernet device Rx node context structure.
 */
typedef struct eth_rx_node_ctx {
    uint16_t port_id; /**< Port identifier of the Rx node. */
} eth_rx_node_ctx_t;

/**
 * @internal
 *
 * Ethernet device Rx node list element structure.
 */
typedef struct eth_rx_node_elem {
    struct eth_rx_node_elem *next; /**< Pointer to the next Rx node element. */
    struct eth_rx_node_ctx ctx;    /**< Rx node context. */
    cne_node_t nid;                /**< Node identifier of the Rx node. */
} eth_rx_node_elem_t;

enum eth_rx_next_nodes {
    ETH_RX_NEXT_PTYPE,
    ETH_RX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Rx node main structure.
 */
struct eth_rx_node_main {
    eth_rx_node_elem_t *head; /**< Pointer to the head Rx node element. */
};

/**
 * @internal
 *
 * Get the Ethernet Rx node data.
 *
 * @return
 *   Pointer to Ethernet Rx node data.
 */
struct eth_rx_node_main *eth_rx_get_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Rx node.
 *
 * @return
 *   Pointer to the Ethernet Rx node.
 */
struct cne_node_register *eth_rx_node_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ETH_RX_PRIV_H__ */
