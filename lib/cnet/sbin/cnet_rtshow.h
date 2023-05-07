/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
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
 * @param stk
 *   The current stack instance.
 * @param argc
 *   The number of arguments to be passed to the stack instance.
 * @param argv
 *   The arguments to be passed to the stack instance.
 * @return
 *   -1 on error, 0 on success.
 */
CNDP_API int cnet_rtshow(stk_t *stk, int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_RTSHOW_H */
