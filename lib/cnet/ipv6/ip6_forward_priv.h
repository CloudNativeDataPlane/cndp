/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __INCLUDE_IP6_FORWARD_PRIV_H__
#define __INCLUDE_IP6_FORWARD_PRIV_H__

#include <net/ethernet.h>

/**
 * @file ip6_forward_priv.h
 *
 * This API allows to do control path functions of ip6_* nodes
 * like ip6_input, ip6_forward, ip6_proto.
 *
 */
#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IP6 forward next nodes.
 */
enum ip6_forward_output_next {
    NODE_IP6_FORWARD_PKT_DROP,
    NODE_IP6_FORWARD_ND6_REQUEST,
    NODE_IP6_FORWARD_OUTPUT_OFFSET
};

/**
 * @internal
 *
 * Ipv6 node main data structure.
 */
struct ip6_forward_node_main {
    uint16_t next_index[CNE_MAX_ETHPORTS]; /**< Next index of each configured port. */
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_FORWARD_PRIV_H__ */
