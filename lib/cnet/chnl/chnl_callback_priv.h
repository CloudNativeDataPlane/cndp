/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2024 Intel Corporation
 */

#ifndef __INCLUDE_CHNL_CALLBACK_PRIV_H__
#define __INCLUDE_CHNL_CALLBACK_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

struct chnl_callback_node_ctx;
typedef struct chnl_callback_node_ctx chnl_callback_node_ctx_t;

/**
 * @internal
 *
 * Types of source nodes
 */
typedef enum chnl_callback_source_node {
    CHNL_CALLBACK_SOURCE_ETH_TX,
    CHNL_CALLBACK_SOURCE_CHNL_RECV,
} chnl_callback_source_node_t;

/**
 * @internal
 *
 * Chnl Callback node context structure.
 */
struct chnl_callback_node_ctx {
    chnl_callback_source_node_t source; /**< Source Node of CHNL Callback */
};

void chnl_callback_node_set_source(struct cne_node *node, chnl_callback_source_node_t source);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_CHNL_CALLBACK_PRIV_H__ */
