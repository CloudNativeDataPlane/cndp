/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation.
 * Copyright (c) 2020 Marvell.
 */
#ifndef __INCLUDE_GTPU_PRIV_H__
#define __INCLUDE_GTPU_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gtpu_node_ctx {
    uint16_t last_type;
};

enum gtpu_next_nodes {
    GTPU_NEXT_PKT_DROP,
    GTPU_NEXT_IP4_INPUT,
    GTPU_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_GTPU_PRIV_H__ */
