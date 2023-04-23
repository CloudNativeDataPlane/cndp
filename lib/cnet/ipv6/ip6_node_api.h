/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __INCLUDE_IP6_NODE_API_H__
#define __INCLUDE_IP6_NODE_API_H__

/**
 * @file ip6_node_api.h
 *
 * This API allows to do control path functions of ip6_* nodes
 * like ip6_input, ip6_forward, ip6_proto, ...
 */
#include <cne_common.h>
#include <cne_fib6.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Add an address to FIB table.
 *
 * @param fib
 *   Pointer to FIB structure.
 * @param ip
 *   IPv6 address.
 * @param depth
 *   IPv6 depth size
 * @param idx
 *   Index into the hop2rt table.
 *
 * @return
 *   0 on success, negative otherwise.
 */
CNDP_API int cne_node_ip6_add_input(struct cne_fib6 *fib, const uint8_t ip[CNE_FIB6_IPV6_ADDR_SIZE],
                                    uint8_t depth, uint32_t idx);

/**
 * Get the ipv6 forward node.
 *
 * @return
 *   Pointer to the ipv6 forward node.
 */
CNDP_API struct cne_node_register *ip6_forward_node_get(void);

/**
 * Set the Edge index of a given port_id.
 *
 * @param port_id
 *   Ethernet port identifier.
 * @param next_index
 *   Edge index of the Given Tx node.
 */
CNDP_API int ip6_forward_set_next(uint16_t port_id, uint16_t next_index);

/**
 * Get the ipv6 output node.
 *
 * @return
 *   Pointer to the ipv6 output node.
 */
CNDP_API struct cne_node_register *ip6_output_node_get(void);

/**
 * Set the Edge index of a given port_id.
 *
 * @param port_id
 *   Ethernet port identifier.
 * @param next_index
 *   Edge index of the Given Tx node.
 */
CNDP_API int ip6_output_set_next(uint16_t port_id, uint16_t next_index);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_NODE_API_H__ */
