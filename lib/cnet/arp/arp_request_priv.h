/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */
#ifndef __INCLUDE_ARP_REQUEST_PRIV_H__
#define __INCLUDE_ARP_REQUEST_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct arp_request_node_elem;
struct arp_request_node_ctx;
typedef struct arp_request_node_elem arp_request_node_elem_t;

/**
 * @internal
 *
 * ARP Request node context structure.
 */
typedef struct arp_request_node_ctx {
    int s; /* RAW socket FD */
} arp_request_node_ctx_t;

/**
 * @internal
 *
 * Ethernet device ARP node list element structure.
 */
struct arp_request_node_elem {
    struct arp_request_node_elem *next; /**< Pointer to the next node element. */
    struct arp_request_node_ctx *ctx;   /**< ARP node context. */
    cne_node_t nid;                     /**< Node identifier of the Rx node. */
};

enum arp_rx_next_nodes {
    ARP_REQUEST_NEXT_PKT_DROP,
    ARP_REQUEST_NEXT_MAX,
};

/**
 * @internal
 *
 * ARP node main structure.
 */
struct arp_request_node_main {
    arp_request_node_elem_t *head; /**< Pointer to the head ARP node element. */
};

/**
 * @internal
 *
 * Get the Ethernet Rx node.
 *
 * @return
 *   Pointer to the Ethernet Rx node.
 */
CNDP_API struct cne_node_register *arp_request_node_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ARP_REQUEST_PRIV_H__ */
