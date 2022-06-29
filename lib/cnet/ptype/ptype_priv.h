/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation.
 * Copyright (c) 2020 Marvell.
 */
#ifndef __INCLUDE_PTYPE_PRIV_H__
#define __INCLUDE_PTYPE_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ptype_node_ctx {
    uint16_t last_type;
};

enum ptype_next_nodes {
    PTYPE_NEXT_PKT_DROP,
    PTYPE_NEXT_IP4_INPUT,
    PTYPE_NEXT_GTPU_INPUT,
    PTYPE_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_PTYPE_PRIV_H__ */
