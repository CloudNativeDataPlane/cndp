/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2025 Intel Corporation
 */

#include <sys/queue.h>

#ifndef __CNET_RTSHOW_H
#define __CNET_RTSHOW_H

/**
 * @file
 * CNET route show routines.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Show/modify routing information for a given stack instance.
 *
 * @param ip4
 *   Display route information for IPv4.
 * @param ip6
 *   Display route information for IPv6.
 * @return
 *   -1 on error, 0 on success.
 */
CNDP_API int cnet_rtshow(int ip4, int ip6);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_RTSHOW_H */
