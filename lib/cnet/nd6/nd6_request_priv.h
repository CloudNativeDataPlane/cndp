/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __INCLUDE_ND6_REQUEST_PRIV_H__
#define __INCLUDE_ND6_REQUEST_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nd6_request_node_elem;
struct nd6_request_node_ctx;
typedef struct nd6_request_node_elem nd6_request_node_elem_t;

/**
 * @internal
 *
 * ND6 Request node context structure.
 */
typedef struct nd6_request_node_ctx {
    int s6; /* RAW socket FD */
} nd6_request_node_ctx_t;

/**
 * @internal
 *
 * Ethernet device ND6 node list element structure.
 */
struct nd6_request_node_elem {
    struct nd6_request_node_elem *next; /**< Pointer to the next node element. */
    struct nd6_request_node_ctx *ctx;   /**< ND6 node context. */
    cne_node_t nid;                     /**< Node identifier of the Rx node. */
};

enum nd6_rx_next_nodes {
    ND6_REQUEST_NEXT_PKT_DROP,
    ND6_REQUEST_NEXT_MAX,
};

/**
 * @internal
 *
 * ND6 node main structure.
 */
struct nd6_request_node_main {
    nd6_request_node_elem_t *head; /**< Pointer to the head ND6 node element. */
};

/**
 * @internal
 *
 * Get the Ethernet Rx node.
 *
 * @return
 *   Pointer to the Ethernet Rx node.
 */
CNDP_API struct cne_node_register *nd6_request_node_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ND6_REQUEST_PRIV_H__ */
