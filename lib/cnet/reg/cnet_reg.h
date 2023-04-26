/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
 */

#ifndef __CNET_REG_H
#define __CNET_REG_H

/**
 * @file
 * CNET Registration routines.
 */

#include <stdint.h>        // for int32_t

#include "cnet_const.h"        // for cfunc_t
#include "cne_common.h"        // for CNDP_API

struct stk_s;
#ifdef __cplusplus
extern "C" {
#endif

typedef struct cnet_register {
    const char *name;  /**< name of the registered entry */
    cfunc_t s_create;  /**< create function for stack instances */
    cfunc_t s_destroy; /**< destroy function for stack instances */
    int32_t priority;  /**< Priority for function calling */
    int32_t reserved;
} cnet_register_t;

/**
 * Add a stack instance function call for each stack instance created.
 *
 * @param name
 *   The name for the function to call
 * @param pri
 *   The priority of this function call. The lower 16 bits is split up into two 8 bit values
 *   to define the priority level and subpriority level.
 * @param create
 *   The stack instance create function to call prototype int (*func)(stk_t *stk)
 * @param destroy
 *   The stack instance destroy function to call prototype int (*func)(stk_t *stk)
 * @return
 *   0 on success or -1 on error
 */
CNDP_API void cnet_add_instance(const char *name, int pri, cfunc_t create, cfunc_t destroy);

/**
 * Call all of the singleton instance functions
 *
 * @param stk
 *   The stack instance pointer
 * @param type
 *   The type of call INIT or STOP
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cnet_do_instance_calls(struct stk_s *stk, int type);

/**
 * Dump the stack instance information
 *
 */
CNDP_API void cne_register_dump(void);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_REG_H */
