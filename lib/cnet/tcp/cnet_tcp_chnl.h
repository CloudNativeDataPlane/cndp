/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
 */

#ifndef __CNET_TCP_CHNL
#define __CNET_TCP_CHNL

/**
 * @file
 * CNET TCP Channel routines and constants.
 */

#include <stdint.h>        // for int32_t

struct chnl;
struct chnl_buf;
struct tcb_entry;
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set the TCP connection to a new scaling value for the receiving channel.
 *
 * @param tcb
 *   The TCP Control Block pointer.
 * @param ch
 *   The Chnl pointer.
 * @return
 *   N/A
 */
CNDP_API void cnet_tcp_chnl_scale_set(struct tcb_entry *tcb, struct chnl *ch);

/**
 * Drop the acked data in the given channel buffer.
 *
 * @param cb
 *   The channel buffer pointer
 * @param acked
 *   The amount of data to be acked.
 * @return
 *   N/A
 */
CNDP_API void cnet_drop_acked_data(struct chnl_buf *cb, int32_t acked);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_TCP_CHNL */
