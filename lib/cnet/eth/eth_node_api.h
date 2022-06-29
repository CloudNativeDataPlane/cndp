/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
 */

#ifndef __INCLUDE_ETH_NODE_API_H__
#define __INCLUDE_ETH_NODE_API_H__

/**
 * @file
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
 * Port config for rx and tx node.
 */
struct pkt_eth_node_config {
    uint16_t port_id; /**< Port identifier */
};

/**
 * Initializes ethernet nodes.
 *
 * @param cfg
 *   Array of ethernet config that identifies which port's
 *   eth_rx and eth_tx nodes need to be created
 *   and queue association.
 * @param cnt
 *   Size of cfg array.
 *
 * @return
 *   0 on successful initialization, negative otherwise.
 */
CNDP_API int cnet_eth_node_config(struct pkt_eth_node_config *cfg, uint16_t cnt);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ETH_NODE_API_H__ */
