/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _CLI_AUTO_COMPLETE_H_
#define _CLI_AUTO_COMPLETE_H_

/**
 * @file
 * Command line interface auto complete routines.
 *
 */

#include "cli.h"
#include "cne_common.h"        // for CNDP_API

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Handle the tab key for auto complete (Internal)
 *
 * @return
 *   N/A
 */
CNDP_API void cli_auto_complete(void);

#ifdef __cplusplus
}
#endif

#endif /* _CLI_AUTO_COMPLETE_H_ */
