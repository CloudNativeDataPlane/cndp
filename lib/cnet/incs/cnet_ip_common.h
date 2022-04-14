/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_IP_COMMON_H
#define __CNET_IP_COMMON_H

/**
 * @file
 * CNET IP common routines and constants.
 */

#include <cnet_ipv4.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Common defines for Ethernet */
enum {
    ETH_HW_TYPE        = 1, /**< Ethernet hardware type */
    ETH_VLAN_ENCAP_LEN = 4  /**< 802.1Q VLAN encap. length */
};

/* Extra EtherTypes */
enum {
    ETHER_TYPE_MPLS_UNICAST   = 0x8847, /**< MPLS Unicast */
    ETHER_TYPE_MPLS_MULTICAST = 0x8848, /**< MPLS Multicast */
    ETHER_TYPE_Q_IN_Q         = 0x88A8, /**< QnQ ether type */
    ETHER_TYPE_TRANSP_ETH_BR  = 0x6558  /**< Transparent Ethernet Bridge */
};

#if 0
struct ip_info {
    struct in_caddr laddr; /**< local address */
    struct in_caddr faddr; /**< foreign address */
};
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CNET_IP_COMMON_H */
