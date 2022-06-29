/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */
#ifndef __INCLUDE_TCP_INPUT_PRIV_H__
#define __INCLUDE_TCP_INPUT_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tcp_input_next_nodes {
    TCP_INPUT_NEXT_PKT_DROP,
    TCP_INPUT_NEXT_CHNL_RECV,
    TCP_INPUT_NEXT_PKT_PUNT,
    TCP_INPUT_NEXT_MAX,
};

/** Use TCP_INPUT_NEXT_MAX to call tcp_output in the cnet_tcp_input() */
#define TCP_CHECK_OUTPUT_AND_DROP TCP_INPUT_NEXT_MAX

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_TCP_INPUT_PRIV_H__ */
