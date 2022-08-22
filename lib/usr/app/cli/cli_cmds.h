/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _CLI_CMDS_H_
#define _CLI_CMDS_H_

#include "cne_common.h"        // for CNDP_API
/**
 * @file
 * CNE Command line interface
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Add the default set of directories and commands
 *
 * @note Uses a thread variable called this_cli
 *
 * @return
 *   0 is ok, -1 is error
 */
CNDP_API int cli_default_tree_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _CLI_CMDS_H_ */
