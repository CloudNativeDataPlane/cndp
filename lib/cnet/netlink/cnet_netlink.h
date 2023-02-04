/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
 */

#include <net/if.h>

#ifndef __CNET_NETLINK_H
#define __CNET_NETLINK_H

/**
 * @file
 * CNET Netlink routines.
 */

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int netlink_debug;

struct cnet;

/**
 * @brief Create the netlink base instance.
 *
 * @param cnet
 *   The cnet instance pointer to the netlink base
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netlink_create(struct cnet *cnet);

/**
 * @brief Destroy the netlink base instance and free resources.
 *
 * @param cnet
 *   The cnet instance pointer to the netlink base
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netlink_destroy(struct cnet *cnet);

/**
 * @brief Start the netlink thread running to monitor netlink communication.
 *
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netlink_start(void);

/**
 * @brief Add a netlink information, links, to internal tables.
 *
 * @param _info
 *   A void * pointer the generic netlink information structure.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netlink_add_links(void *_info);

/**
 * @brief Add netlink address information internal tables.
 *
 * @param _info
 *   A void * pointer the generic netlink information structure.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netlink_add_addrs(void *_info);

/**
 * @brief Add netlink route information to internal tables.
 *
 * @param _info
 *   A void * pointer the generic netlink information structure.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netlink_add_routes(void *_info);

/**
 * @brief Add neighbor information to the internal netlink tables.
 *
 * @param _info
 *   A void * pointer the generic netlink information structure.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netlink_add_neighs(void *_info);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_NETLINK_H */
