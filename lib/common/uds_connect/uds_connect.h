/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

/**
 * @file
 *
 * uds-related utility functions to connect to a local domain socket.
 */

#ifndef _UDS_CONNECT_H_
#define _UDS_CONNECT_H_

#include "cne_common.h"        // for CNDP_API
#include "uds.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Perform handshake between the cndp app and the UDS
 *
 * @param uds_name
 *   The name of the unix domain socket to connect to
 * @return
 *   NULL if not successful or the uds_info pointer.
 */
CNDP_API uds_info_t *udsc_handshake(const char *uds_name);

/**
 * Close the connection between the cndp app and the UDS
 *
 * @param info
 *   The uds_info_t pointer
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int udsc_close(uds_info_t *info);

#ifdef __cplusplus
}
#endif

#endif /* _UDS_CONNECT_H_ */
