/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __INCLUDE_IP6_OUTPUT_PRIV_H__
#define __INCLUDE_IP6_OUTPUT_PRIV_H__

/**
 * @file ip6_node_output.h
 *
 * This API allows to do control path functions of ip6_* nodes
 * like ip6_output, ip6_forward, ip6_proto, ...
 *
 */
#include <cne_common.h>
#include <cne_fib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IP6 output next nodes.
 */
enum cne_node_ip6_output_next {
    IP6_OUTPUT_NEXT_PKT_DROP,    /**< Packet drop node. */
    IP6_OUTPUT_NEXT_ND6_REQUEST, /**< Packet NDP 6 request node. */
    IP6_OUTPUT_NEXT_MAX,         /**< Number of next nodes of lookup node. */
};

/**
 * @internal
 *
 * Ipv6 output node main data structure.
 */
struct ip6_output_node_main {
    uint16_t next_index[CNE_MAX_ETHPORTS]; /**< Next index of each configured port. */
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_OUTPUT_PRIV_H__ */
