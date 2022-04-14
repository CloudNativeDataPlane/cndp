/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */
#ifndef __INCLUDE_TCP_OUTPUT_PRIV_H__
#define __INCLUDE_TCP_OUTPUT_PRIV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <cne_common.h>

enum tcp_output_next_nodes {
    TCP_OUTPUT_NEXT_PKT_DROP,
    TCP_OUTPUT_NEXT_IP4_OUTPUT,
    TCP_OUTPUT_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_TCP_OUTPUT_PRIV_H__ */
