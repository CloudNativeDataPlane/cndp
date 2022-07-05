/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#ifndef __INCLUDE_CNE_NODE_ETH_API_H__
#define __INCLUDE_CNE_NODE_ETH_API_H__

/**
 * @file
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * This API allows to setup pktdev_rx and pktdev_tx nodes
 * and its queue associations.
 */

#include <cne_common.h>
#include <mempool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Port config for pktdev_rx and pktdev_tx node.
 */
struct cne_node_pktdev_config {
    uint16_t port_id; /**< Port identifier */
};

/**
 * Initializes device nodes.
 *
 * @param cfg
 *   Array of device configs that identifies which port's
 *   pktdev_rx and pktdev_tx nodes need to be created
 *   and queue association.
 * @param cnt
 *   Size of cfg array.
 *
 * @return
 *   0 on successful initialization, negative otherwise.
 */
int cne_node_eth_config(struct cne_node_pktdev_config *cfg, uint16_t cnt);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_CNE_NODE_ETH_API_H__ */
