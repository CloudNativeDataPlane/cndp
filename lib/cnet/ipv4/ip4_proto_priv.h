/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

#ifndef __INCLUDE_IP4_PROTO_PRIV_H__
#define __INCLUDE_IP4_PROTO_PRIV_H__

/**
 * @file ip4_proto_priv.h
 *
 * This API allows to do control path functions of ip4_* nodes
 * like ip4_proto, ip4_input, ip4_forward.
 *
 */

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum cne_node_ip4_proto_next {
    CNE_NODE_IP4_INPUT_PROTO_DROP, /**< Packet drop node. */
    CNE_NODE_IP4_INPUT_PROTO_UDP,  /**< UDP protocol. */
#if CNET_ENABLE_TCP
    CNE_NODE_IP4_INPUT_PROTO_TCP, /**< TCP protocol. */
#endif
    CNE_NODE_IP4_INPUT_PROTO_MAX, /**< Number of next nodes of protocol node.*/
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_PROTO_PRIV_H__ */
