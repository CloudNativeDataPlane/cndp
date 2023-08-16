/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Red Hat Inc.
 * Copyright (c) 2023 Intel Corporation
 */
#ifndef __INCLUDE_PUNT_ETHER_KERNEL_PRIV_H__
#define __INCLUDE_PUNT_ETHER_KERNEL_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TAP_NAME "punt_ether"

struct punt_ether_kernel_node_elem;
struct punt_ether_kernel_node_ctx;
typedef struct punt_ether_kernel_node_elem punt_ether_kernel_node_elem_t;

/**
 * @internal
 *
 * PUNT Ether Kernel node context structure.
 */
typedef struct punt_ether_kernel_node_ctx {
    int sock;
    int lport;
    mmap_t *mmap;
} punt_ether_kernel_node_ctx_t;

/**
 * @internal
 *
 * PUNT Ether Kernel node list element structure.
 */
struct punt_ether_kernel_node_elem {
    struct punt_ether_kernel_node_elem *next; /**< Pointer to the next node element. */
    struct punt_ether_kernel_node_ctx *ctx;   /**< node context. */
    cne_node_t nid;                           /**< Node identifier of the PUNT ether Kernel node. */
};

/**
 * @internal
 *
 * PUNT Ether Kernel node main structure.
 */
struct punt_ether_kernel_node_main {
    punt_ether_kernel_node_elem_t *head; /**< Pointer to the head node element. */
};

/**
 * @internal
 *
 * Get the PUNT Ether Kernel node.
 *
 * @return
 *   Pointer to the PUNT Ether Kernel node.
 */
CNDP_API struct cne_node_register *punt_ether_kernel_node_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_PUNT_ETHER_KERNEL_PRIV_H__ */
