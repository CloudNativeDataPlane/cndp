/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */
#ifndef __INCLUDE_TCP_SEND_PRIV_H__
#define __INCLUDE_TCP_SEND_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <cne_common.h>

struct tcp_send_node_elem;
struct tcp_send_node_ctx;
typedef struct tcp_send_node_elem tcp_send_node_elem_t;

/**
 * @internal
 *
 * TCP Rx node context structure.
 */
typedef struct tcp_send_node_ctx {
    uint64_t interval;
} tcp_send_node_ctx_t;

/**
 * @internal
 *
 * TCP node list element structure.
 */
struct tcp_send_node_elem {
    struct tcp_send_node_elem *next; /**< Pointer to the next Rx node element. */
    struct tcp_send_node_ctx ctx;    /**< Rx node context. */
    cne_node_t nid;                  /**< Node identifier of the Rx node. */
};

enum tcp_send_next_nodes {
    TCP_SEND_NEXT_PKT_DROP,
    TCP_SEND_NEXT_IP4_OUTPUT,
    TCP_SEND_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_TCP_OUTPUT_PRIV_H__ */
