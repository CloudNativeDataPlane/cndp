/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __INCLUDE_IP6_PROTO_PRIV_H__
#define __INCLUDE_IP6_PROTO_PRIV_H__

/**
 * @file ip6_proto_priv.h
 *
 * This API allows to do control path functions of ip6_* nodes
 * like ip6_proto, ip6_input, ip6_forward.
 *
 */

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum cne_node_ip6_proto_next {
    CNE_NODE_IP6_INPUT_PROTO_DROP, /**< Packet drop node. */
    CNE_NODE_IP6_INPUT_PROTO_UDP,  /**< UDP protocol. */
#if CNET_ENABLE_TCP
    CNE_NODE_IP6_INPUT_PROTO_TCP, /**< TCP protocol. */
#endif
    CNE_NODE_IP6_INPUT_PROTO_ICMP6, /**< ICMPv6 protocol. */
    CNE_NODE_IP6_INPUT_PROTO_MAX,   /**< Number of next nodes of protocol node.*/
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP6_PROTO_PRIV_H__ */
