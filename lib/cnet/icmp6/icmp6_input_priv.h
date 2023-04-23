/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */
#ifndef __INCLUDE_ICMP6_INPUT_PRIV_H__
#define __INCLUDE_ICMP6_INPUT_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum icmp6_input_next_nodes {
    ICMP6_INPUT_NEXT_PKT_DROP,
    ICMP6_INPUT_NEXT_CHNL_RECV,
    ICMP6_INPUT_NEXT_PKT_PUNT,
    ICMP6_INPUT_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ICMP6_INPUT_PRIV_H__ */
