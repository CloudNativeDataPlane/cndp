/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */
#ifndef __INCLUDE_PKTDEV_RX_PRIV_H__
#define __INCLUDE_PKTDEV_RX_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <cne_common.h>

struct pktdev_rx_node_elem;
struct pktdev_rx_node_ctx;
typedef struct pktdev_rx_node_elem pktdev_rx_node_elem_t;
typedef struct pktdev_rx_node_ctx pktdev_rx_node_ctx_t;

/**
 * @internal
 *
 * Ethernet device Rx node context structure.
 */
struct pktdev_rx_node_ctx {
    uint16_t port_id; /**< Port identifier of the Rx node. */
    uint16_t cls_next;
};

/**
 * @internal
 *
 * Ethernet device Rx node list element structure.
 */
struct pktdev_rx_node_elem {
    struct pktdev_rx_node_elem *next;
    /**< Pointer to the next Rx node element. */
    struct pktdev_rx_node_ctx ctx;
    /**< Rx node context. */
    cne_node_t nid;
    /**< Node identifier of the Rx node. */
};

enum pktdev_rx_next_nodes {
    PKTDEV_RX_NEXT_IP4_LOOKUP,
    PKTDEV_RX_NEXT_PKT_CLS,
    PKTDEV_RX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Rx node main structure.
 */
struct pktdev_rx_node_main {
    pktdev_rx_node_elem_t *head;
    /**< Pointer to the head Rx node element. */
};

/**
 * @internal
 *
 * Get the Ethernet Rx node data.
 *
 * @return
 *   Pointer to Ethernet Rx node data.
 */
struct pktdev_rx_node_main *pktdev_rx_get_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Rx node.
 *
 * @retrun
 *   Pointer to the Ethernet Rx node.
 */
struct cne_node_register *pktdev_rx_node_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_PKTDEV_RX_PRIV_H__ */
