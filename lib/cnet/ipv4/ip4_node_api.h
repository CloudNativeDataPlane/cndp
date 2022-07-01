/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
 */

#ifndef __INCLUDE_IP4_NODE_API_H__
#define __INCLUDE_IP4_NODE_API_H__

/**
 * @file ip4_node_api.h
 *
 * This API allows to do control path functions of ip4_* nodes
 * like ip4_input, ip4_forward, ip4_proto, ...
 */
#include <cne_common.h>
#include <cne_fib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Add an address to FIB table.
 *
 * @param fib
 *   Pointer to FIB structure.
 * @param ip
 *   IPv4 address.
 * @param depth
 *   IPv4 depth size
 * @param idx
 *   Index into the hop2rt table.
 *
 * @return
 *   0 on success, negative otherwise.
 */
CNDP_API int cne_node_ip4_add_input(struct cne_fib *fib, uint32_t ip, uint8_t depth, uint32_t idx);

/**
 * Get the ipv4 forward node.
 *
 * @return
 *   Pointer to the ipv4 forward node.
 */
CNDP_API struct cne_node_register *ip4_forward_node_get(void);

/**
 * Set the Edge index of a given port_id.
 *
 * @param port_id
 *   Ethernet port identifier.
 * @param next_index
 *   Edge index of the Given Tx node.
 */
CNDP_API int ip4_forward_set_next(uint16_t port_id, uint16_t next_index);

/**
 * Get the ipv4 output node.
 *
 * @return
 *   Pointer to the ipv4 output node.
 */
CNDP_API struct cne_node_register *ip4_output_node_get(void);

/**
 * Set the Edge index of a given port_id.
 *
 * @param port_id
 *   Ethernet port identifier.
 * @param next_index
 *   Edge index of the Given Tx node.
 */
CNDP_API int ip4_output_set_next(uint16_t port_id, uint16_t next_index);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_NODE_API_H__ */
