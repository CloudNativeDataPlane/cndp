/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation.
 */
#ifndef __INCLUDE_UDP_OUTPUT_PRIV_H__
#define __INCLUDE_UDP_OUTPUT_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum udp_output_next_nodes {
    UDP_OUTPUT_NEXT_PKT_DROP,
    UDP_OUTPUT_NEXT_IP4_OUTPUT,
    UDP_OUTPUT_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_UDP_OUTPUT_PRIV_H__ */
