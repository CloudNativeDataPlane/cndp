/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */
#ifndef __INCLUDE_TCP_OUTPUT_PRIV_H__
#define __INCLUDE_TCP_OUTPUT_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tcp_output_next_nodes {
    TCP_OUTPUT_NEXT_PKT_DROP,
    TCP_OUTPUT_NEXT_IP4_OUTPUT,
#if CNET_ENABLE_IP6
    TCP_OUTPUT_NEXT_IP6_OUTPUT,
#endif
    TCP_OUTPUT_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_TCP_OUTPUT_PRIV_H__ */
