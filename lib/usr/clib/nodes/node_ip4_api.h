/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#ifndef __INCLUDE_CNE_NODE_IP4_API_H__
#define __INCLUDE_CNE_NODE_IP4_API_H__

/**
 * @file
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * This API allows to do control path functions of ip4_* nodes
 * like ip4_lookup, ip4_rewrite.
 */

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IP4 lookup next nodes.
 */
enum cne_node_ip4_lookup_next {
    CNE_NODE_IP4_LOOKUP_NEXT_REWRITE,
    /**< Rewrite node. */
    CNE_NODE_IP4_LOOKUP_NEXT_PKT_DROP,
    /**< Packet drop node. */
    CNE_NODE_IP4_LOOKUP_NEXT_MAX,
    /**< Number of next nodes of lookup node. */
};

/**
 * Add ipv4 route to lookup table.
 *
 * @param ip
 *   IP address of route to be added.
 * @param depth
 *   Depth of the rule to be added.
 * @param next_hop
 *   Next hop id of the rule result to be added.
 * @param next_node
 *   Next node to redirect traffic to.
 *
 * @return
 *   0 on success, negative otherwise.
 */
int cne_node_ip4_route_add(uint32_t ip, uint8_t depth, uint16_t next_hop,
                           enum cne_node_ip4_lookup_next next_node);

/**
 * Add a next hop's rewrite data.
 *
 * @param next_hop
 *   Next hop id to add rewrite data to.
 * @param rewrite_data
 *   Rewrite data.
 * @param rewrite_len
 *   Length of rewrite data.
 * @param dst_port
 *   Destination port to redirect traffic to.
 *
 * @return
 *   0 on success, negative otherwise.
 */
int cne_node_ip4_rewrite_add(uint16_t next_hop, uint8_t *rewrite_data, uint8_t rewrite_len,
                             uint16_t dst_port);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_CNE_NODE_IP4_API_H__ */
