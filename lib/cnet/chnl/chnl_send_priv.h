/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */
#ifndef __INCLUDE_CHNL_SEND_PRIV_H__
#define __INCLUDE_CHNL_SEND_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <cne_common.h>

/**
 * @internal
 *
 * CHNL output node context structure.
 */
struct chnl_send_node_ctx {
    uint16_t last_next;
};

enum chnl_send_next_nodes {
    CHNL_SEND_NEXT_PKT_DROP,
    CHNL_SEND_NEXT_UDP_OUTPUT,
#if CNET_ENABLE_TCP
    CHNL_SEND_NEXT_TCP_OUTPUT,
#endif
    CHNL_SEND_NEXT_MAX,
};

CNDP_API struct cne_node_register *chnl_send_node_get(void);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_CHNL_SEND_PRIV_H__ */
