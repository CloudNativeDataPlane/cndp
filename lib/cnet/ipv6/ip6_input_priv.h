/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __INCLUDE_IP6_INPUT_PRIV_H__
#define __INCLUDE_IP6_INPUT_PRIV_H__

/**
 * @file ip6_input_priv.h
 *
 * This API allows to do control path functions of ip6_* nodes
 * like ip6_input, ip6_forward, ip6_proto.
 *
 */
#include <cne_common.h>
#include <cne_fib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IP6 lookup next nodes.
 */
enum cne_node_ip6_input_next {
    CNE_NODE_IP6_INPUT_NEXT_PKT_DROP, /**< Packet drop node. */
    CNE_NODE_IP6_INPUT_NEXT_FORWARD,  /**< Forward node. */
    CNE_NODE_IP6_INPUT_NEXT_PROTO,    /**< Protocol node. */
    CNE_NODE_IP6_INPUT_NEXT_MAX,      /**< Number of next nodes of lookup node. */
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_INPUT_PRIV_H__ */
