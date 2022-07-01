/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
 */

#ifndef __INCLUDE_IP4_OUTPUT_PRIV_H__
#define __INCLUDE_IP4_OUTPUT_PRIV_H__

/**
 * @file ip4_node_output.h
 *
 * This API allows to do control path functions of ip4_* nodes
 * like ip4_output, ip4_forward, ip4_proto, ...
 *
 */
#include <cne_common.h>
#include <cne_fib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IP4 output next nodes.
 */
enum cne_node_ip4_output_next {
    IP4_OUTPUT_NEXT_PKT_DROP,    /**< Packet drop node. */
    IP4_OUTPUT_NEXT_ARP_REQUEST, /**< Packet ARP request node. */
    IP4_OUTPUT_NEXT_MAX,         /**< Number of next nodes of lookup node. */
};

/**
 * @internal
 *
 * Ipv4 output node main data structure.
 */
struct ip4_output_node_main {
    uint16_t next_index[CNE_MAX_ETHPORTS]; /**< Next index of each configured port. */
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_OUTPUT_PRIV_H__ */
