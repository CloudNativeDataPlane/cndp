/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */
#ifndef __INCLUDE_KERNEL_RECV_PRIV_H__
#define __INCLUDE_KERNEL_RECV_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <cne_common.h>

struct kernel_recv_node_elem;
struct kernel_recv_node_ctx;

#define KERN_RECV_MBUF_COUNT (4 * 1024) /**< Number of mbufs for kernel receive */

/**
 * @internal
 *
 * Kernel Recv node context structure.
 */
typedef struct kernel_recv_node_ctx {
    struct tap_info *tinfo;
    pktmbuf_info_t *pi;
} kernel_recv_node_ctx_t;

/**
 * @internal
 *
 * Kernel Recv node list element structure.
 */
typedef struct kernel_recv_node_elem {
    struct kernel_recv_node_elem *next; /**< Pointer to the next node element. */
    struct kernel_recv_node_ctx ctx;    /**< Kernel Recv node context. */
    cne_node_t nid;                     /**< Node identifier of the Kernel Recv node. */
} kernel_recv_node_elem_t;

enum kernel_recv_next_nodes {
    KERNEL_RECV_NEXT_PTYPE,
    KERNEL_RECV_NEXT_MAX,
};

/**
 * @internal
 *
 * Kernel Recv node main structure.
 */
struct kernel_recv_node_main {
    kernel_recv_node_elem_t *head; /**< Pointer to the head node element. */
};

/**
 * @internal
 *
 * Get the Ethernet Rx node data.
 *
 * @return
 *   Pointer to Ethernet Rx node data.
 */
struct kernel_recv_node_main *kernel_recv_get_node_data_get(void);

/**
 * @internal
 *
 * Get the Kernel Recv node.
 *
 * @retrun
 *   Pointer to the Kernel Recv node.
 */
CNDP_API struct cne_node_register *kernel_recv_node_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_KERNEL_RECV_PRIV_H__ */
