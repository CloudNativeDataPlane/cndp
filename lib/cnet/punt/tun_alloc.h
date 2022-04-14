/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */
#ifndef __INCLUDE_TUN_ALLOC_H__
#define __INCLUDE_TUN_ALLOC_H__

/**
 * @file
 * CNET TUN/TAP PUNT routines and values.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <cne_common.h>

#define TUN_TAP_DEV_PATH "/dev/net/tun"

/* Specifies on what netdevices the ioctl should be applied */
enum ioctl_mode {
    LOCAL_AND_REMOTE,
    LOCAL_ONLY,
    REMOTE_ONLY,
};

enum {
    TUN_DEVICE_TYPE = 0x00,
    TAP_DEVICE_TYPE = 0x01,
    TAP_KEEP_ALIVE  = 0x02,
};

#define TAP_MAX_QUEUES 16

#ifdef IFF_MULTI_QUEUE
#define CNE_TAP_MAX_QUEUES TAP_MAX_QUEUES
#else
#define CNE_TAP_MAX_QUEUES 1
#endif
#define MAX_GSO_MBUFS 64

struct tap_info {
    int flags;                         /**< Flags used in creating the interface */
    unsigned int features;             /**< Features used in creating the interface */
    char tun_name[IFNAMSIZ];           /**< Internal Tap device name */
    char remote_iface[IFNAMSIZ];       /**< Remote netdevice name */
    struct ether_addr eth_addr;        /**< Mac address of the device port */
    struct ifreq remote_initial_flags; /**< Remote netdevice flags on init */
    int remote_if_index;               /**< remote netdevice IF_INDEX */
    int if_index;                      /**< IF_INDEX for the port */
    int tun_fd;                        /**< TUN/TAP file descriptor */
    int ioctl_sock;                    /**< socket for ioctl calls */
    int ka_fd;                         /**< keep-alive file descriptor */
};

struct tap_info *tun_alloc(int tun_flags, const char *if_name);
int tun_free(struct tap_info *ti);
int tun_dump(const char *msg, struct tap_info *ti);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_TUN_ALLOC_H__ */
