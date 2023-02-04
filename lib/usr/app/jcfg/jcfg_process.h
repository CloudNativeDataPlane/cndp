/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation.
 */

#ifndef _JCFG_PROCESS_H_
#define _JCFG_PROCESS_H_

#include <jcfg.h>        // for jcfg_parse_cb_t, jcfg_info_t

#include "cne_common.h"        // for CNDP_API

/**
 * @file
 *
 * JSON-C configuration routines
 *
 * This file provides a standard JSON-C interface routines for CNDP.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Process the json configuration information and callback user routine.
 *
 * @param jinfo
 *   The jcfg_info_t pointer
 * @param flags
 *   The flags used to help parse the JSON-C file
 * @param cb
 *   The callback function to be called for each jcfg object type.
 * @param cb_arg
 *   The argument from the caller passed to the callback function
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_process(jcfg_info_t *jinfo, int flags, jcfg_parse_cb_t *cb, void *cb_arg);

#ifdef __cplusplus
}
#endif

#endif /* _JCFG_PROCESS_H_ */
