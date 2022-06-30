/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

#ifndef __INC_TUN_ALLOC_H__
#define __INC_TUN_ALLOC_H__

/**
 * @file
 * TUN/TAP allocate routines, defines and structures.
 */

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TUN_TAP_DEV_PATH "/dev/net/tun"

#define CNE_TAP_MAX_QUEUES 16

struct tap_info {
    char name[IFNAMSIZ + 1];    /**< Internal Tap device name */
    struct ether_addr eth_addr; /**< Mac address of the device port */
    int if_index;               /**< IF_INDEX for the port */
    uint32_t features;          /**< Features used in creating the interface */
    int flags;                  /**< Flags used in creating the interface */
    int fd;                     /**< TUN/TAP file descriptor */
    int sock;                   /**< socket for ioctl calls */
};

/**
 * Allocate and setup a TUN/TAP interface
 *
 * @param tun_flags
 *   Flags to help create the interface
 * @param if_name
 *   Name of the interface to create
 * @return
 *   NULL on error or pointer to struct tap_info structure
 */
CNDP_API struct tap_info *tun_alloc(int tun_flags, const char *if_name);

/**
 * Free resources for a given tun/tap interface.
 *
 * @param ti
 *   The struct tap_info structure pointer to free.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int tun_free(struct tap_info *ti);

/**
 * Dump out the information of a tun/tap interface
 *
 * @param msg
 *   User supplied message to identify this dump
 * @param ti
 *   The struct tap_info structure pointer to dump.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int tun_dump(const char *msg, struct tap_info *ti);

/**
 * Return the tun/tap file descriptor value
 *
 * @param ti
 *   Pointer to the tap_info structure
 * @return
 *   -1 on error or tun/tap fd
 */
static inline int
tun_get_fd(struct tap_info *ti)
{
    if (ti)
        return ti->fd;
    return -1;
}

/**
 * Get tun/tap interface name
 *
 * @param ti
 *   Pointer to the tap_info structure
 * @return
 *   NULL on error or pointer to tun/tap interface name
 */
static inline const char *
tun_get_name(struct tap_info *ti)
{
    if (ti)
        return ti->name;
    return NULL;
}

/**
 * Get tun/tap MAC address
 *
 * @param ti
 *   Pointer to the tap_info structure
 * @return
 *   NULL on error or pointer to tun/tap MAC address
 */
static inline const struct ether_addr *
tun_get_ether_addr(struct tap_info *ti)
{
    if (ti)
        return &ti->eth_addr;
    return NULL;
}

/**
 * Get tun/tap ifindex value
 *
 * @param ti
 *   Pointer to the tap_info structure
 * @return
 *   -1 on error or tun/tap ifindex value
 */
static inline int
tun_get_if_index(struct tap_info *ti)
{
    if (ti)
        return ti->if_index;
    return -1;
}

#ifdef __cplusplus
}
#endif

#endif /* __INC_TUN_ALLOC_H__ */
