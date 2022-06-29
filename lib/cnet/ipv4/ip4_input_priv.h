/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
 */

#ifndef __INCLUDE_IP4_INPUT_PRIV_H__
#define __INCLUDE_IP4_INPUT_PRIV_H__

/**
 * @file ip4_input_priv.h
 *
 * This API allows to do control path functions of ip4_* nodes
 * like ip4_input, ip4_forward, ip4_proto.
 *
 */
#include <cne_common.h>
#include <cne_fib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IP4 lookup next nodes.
 */
enum cne_node_ip4_input_next {
    CNE_NODE_IP4_INPUT_NEXT_PKT_DROP, /**< Packet drop node. */
    CNE_NODE_IP4_INPUT_NEXT_FORWARD,  /**< Forward node. */
    CNE_NODE_IP4_INPUT_NEXT_PROTO,    /**< Protocol node. */
    CNE_NODE_IP4_INPUT_NEXT_MAX,      /**< Number of next nodes of lookup node. */
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_INPUT_PRIV_H__ */
