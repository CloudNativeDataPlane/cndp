/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation.
 */
#ifndef __INCLUDE_UDP_INPUT_PRIV_H__
#define __INCLUDE_UDP_INPUT_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum udp_input_next_nodes {
    UDP_INPUT_NEXT_PKT_DROP,
    UDP_INPUT_NEXT_CHNL_RECV,
    UDP_INPUT_NEXT_PKT_PUNT,
    UDP_INPUT_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_UDP_INPUT_PRIV_H__ */
