/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _PARSE_ARGS_H_
#define _PARSE_ARGS_H_

#ifdef __cplusplus
extern "C" {
#endif

#define NO_METRICS_TAG "no-metrics" /**< json tag for no-metrics */
#define NO_RESTAPI_TAG "no-restapi" /**< json tag for no-restapi */
#define ENABLE_CLI_TAG "cli"        /**< json tag to enable/disable CLI */

struct fwd_port {
    int lport; /**< PKTDEV lport id */
};

/**
 *
 * Main parsing routine for the command line.
 *
 * DESCRIPTION
 * Main parsing routine for the command line.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
int parse_args(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* _PARSE_ARGS_H_ */
