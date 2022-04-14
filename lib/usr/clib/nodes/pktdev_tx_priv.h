/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */
#ifndef __INCLUDE_PKTDEV_TX_PRIV_H__
#define __INCLUDE_PKTDEV_TX_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

struct pktdev_tx_node_ctx;
typedef struct pktdev_tx_node_ctx pktdev_tx_node_ctx_t;

enum pktdev_tx_next_nodes {
    PKTDEV_TX_NEXT_PKT_DROP,
    PKTDEV_TX_NEXT_MAX,
};

/**
 * @internal
 *
 * Ethernet Tx node context structure.
 */
struct pktdev_tx_node_ctx {
    uint16_t port;  /**< Port identifier of the Ethernet Tx node. */
    uint16_t queue; /**< Queue identifier of the Ethernet Tx node. */
};

/**
 * @internal
 *
 * Ethernet Tx node main structure.
 */
struct pktdev_tx_node_main {
    uint32_t nodes[CNE_MAX_ETHPORTS]; /**< Tx nodes for each ethdev port. */
};

/**
 * @internal
 *
 * Get the Ethernet Tx node data.
 *
 * @return
 *   Pointer to Ethernet Tx node data.
 */
struct pktdev_tx_node_main *pktdev_tx_node_data_get(void);

/**
 * @internal
 *
 * Get the Ethernet Tx node.
 *
 * @retrun
 *   Pointer to the Ethernet Tx node.
 */
struct cne_node_register *pktdev_tx_node_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_PKTDEV_TX_PRIV_H__ */
