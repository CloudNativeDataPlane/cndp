/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */
#ifndef __INCLUDE_CHNL_RECV_PRIV_H__
#define __INCLUDE_CHNL_RECV_PRIV_H__

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum chnl_recv_next_nodes {
    CHNL_RECV_NEXT_PKT_DROP,
    CHNL_RECV_NEXT_PKT_CALLBACK,
    CHNL_RECV_NEXT_MAX,
};

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_CHNL_RECV_PRIV_H__ */
