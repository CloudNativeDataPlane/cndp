/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
 */
#ifndef __INCLUDE_IP4_FORWARD_PRIV_H__
#define __INCLUDE_IP4_FORWARD_PRIV_H__

#include <net/ethernet.h>

/**
 * @file ip4_forward_priv.h
 *
 * This API allows to do control path functions of ip4_* nodes
 * like ip4_input, ip4_forward, ip4_proto.
 *
 */
#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * IP4 forward next nodes.
 */
enum ip4_forward_output_next {
    NODE_IP4_FORWARD_PKT_DROP,
    NODE_IP4_FORWARD_ARP_REQUEST,
    NODE_IP4_FORWARD_OUTPUT_OFFSET
};

/**
 * @internal
 *
 * Ipv4 node main data structure.
 */
struct ip4_forward_node_main {
    uint16_t next_index[CNE_MAX_ETHPORTS]; /**< Next index of each configured port. */
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IP4_FORWARD_PRIV_H__ */
