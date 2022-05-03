/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_NETIF_H
#define __CNET_NETIF_H

/**
 * @file
 * CNET Network Interface routines and constants.
 */

#include <net/if.h>
#include <cne_atomic.h>
#include <pktdev.h>
#include <cne_inet.h>        // for inet_addr_mask_cmp, inet_ntop4
#include <stddef.h>          // for NULL
#include <stdint.h>          // for uint64_t, uint8_t, uint16_t, uint32_t, int32_t

#include "cne_common.h"        // for __cne_cache_aligned
#include "cne_log.h"           // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_WARNING
#include "cne_lport.h"         // for lport_stats
#include "cne_vec.h"           // for vec_at_index, vec_pool_free
#include "cnet_const.h"        // for iofunc_t
#include "cne_inet.h"          // for _in_addr, _in6_addr
#include "cnet_stk.h"          // for stk_entry, per_thread_stk, this_stk
#include "mempool.h"           // for mempool_get, mempool_obj_iter, mempool_put
#include "pktmbuf.h"           // for pktmbuf_t

#ifdef __cplusplus
extern "C" {
#endif

enum { NETIF_IFNAME_TYPE, NETIF_NETDEV_NAME_TYPE };

enum { PRIMARY_IPADDR = 0, DEFAULT_FORWARDING_STATE = 1, NUM_IP_ADDRS = 8 };

/* Network interface flags */
enum {
    _IFF_UP           = 0x00000001, /* interface link is up */
    _IFF_BROADCAST    = 0x00000002, /* broadcast address valid */
    _IFF_DEBUG        = 0x00000004, /* turn on debugging */
    _IFF_LOOPBACK     = 0x00000008, /* is a loopback net */
    _IFF_POINTOPOINT  = 0x00000010, /* interface is p2p link */
    _IFF_SMART        = 0x00000020, /* interface manages own routes */
    _IFF_RUNNING      = 0x00000040, /* resources allocated */
    _IFF_NOARP        = 0x00000080, /* no address resolution protocol */
    _IFF_PROMISC      = 0x00000100, /* receive all packets */
    _IFF_ALLMULTI     = 0x00000200, /* receive all multicast packets */
    _IFF_OACTIVE      = 0x00000400, /* transmission in progress */
    _IFF_SIMPLEX      = 0x00000800, /* can't hear own transmissions */
    _IFF_LINK0        = 0x00001000, /* forwarding disabled */
    _IFF_LINK1        = 0x00002000, /* per link layer defined bit */
    _IFF_LINK2        = 0x00004000, /* per link layer defined bit */
    _IFF_MULTICAST    = 0x00008000, /* supports multicast */
    _IFF_NOTRAILERS   = 0x00020000, /* avoid use of trailers */
    _IFF_INET_UP      = 0x00040000, /* interface is up for ipv4 */
    _IFF_INET6_UP     = 0x00080000, /* interface is up for ipv6 */
    _IFF_RARP         = 0x00100000, /* RARP enabled on this interface */
    _IFF_DONT_FORWARD = 0x00200000  /* Not allowed to forward packets */
};

struct netif;
struct drv_entry;

/* Structure to contain all of the IPv4 Addresses */
struct inet4_addr {
    uint16_t valid;
    uint16_t prefixlen;
    struct in_addr ip;
    struct in_addr netmask;
    struct in_addr broadcast;
};

struct netif {
    int16_t netif_idx;                         /**< Index number in cnet->netifs[] */
    uint16_t lpid;                             /**< logical port ID */
    int ifflags;                               /**< Interface flags for network interface */
    int ifindex;                               /**< Ifindex value of network interfaces */
    uint16_t ip_ident;                         /**< IP identification value */
    uint16_t family;                           /**< Interface family */
    uint16_t mtu;                              /**< Max Transmission Unit */
    char ifname[IF_NAMESIZE + 1];              /**< ifname of interface */
    char netdev_name[IF_NAMESIZE + 1];         /**< netdev name of interface */
    struct drv_entry *drv;                     /**< Driver interface structure */
    struct rt4_entry *rt_cached;               /**< Route Cache */
    struct inet4_addr ip4_addrs[NUM_IP_ADDRS]; /**< Multiple IP addresses for Interface */
    struct ether_addr mac;                     /**< MAC address of interface */
} __cne_cache_aligned;

#define _IFF_UP           0x00000001 /**< interface link is up */
#define _IFF_BROADCAST    0x00000002 /**< broadcast address valid */
#define _IFF_DEBUG        0x00000004 /**< turn on debugging */
#define _IFF_LOOPBACK     0x00000008 /**< is a loopback net */
#define _IFF_POINTOPOINT  0x00000010 /**< interface is p2p link */
#define _IFF_SMART        0x00000020 /**< interface manages own routes */
#define _IFF_RUNNING      0x00000040 /**< resources allocated */
#define _IFF_NOARP        0x00000080 /**< no address resolution protocol */
#define _IFF_PROMISC      0x00000100 /**< receive all packets */
#define _IFF_ALLMULTI     0x00000200 /**< receive all multicast packets */
#define _IFF_OACTIVE      0x00000400 /**< transmission in progress */
#define _IFF_SIMPLEX      0x00000800 /**< can't hear own transmissions */
#define _IFF_LINK0        0x00001000 /**< forwarding disabled */
#define _IFF_LINK1        0x00002000 /**< per link layer defined bit */
#define _IFF_LINK2        0x00004000 /**< per link layer defined bit */
#define _IFF_MULTICAST    0x00008000 /**< supports multicast */
#define _IFF_NOTRAILERS   0x00020000 /**< avoid use of trailers */
#define _IFF_INET_UP      0x00040000 /**< interface is up for ipv4 */
#define _IFF_INET6_UP     0x00080000 /**< interface is up for ipv6 */
#define _IFF_RARP         0x00100000 /**< RARP enabled on this interface */
#define _IFF_DONT_FORWARD 0x00200000 /**< Not allowed to forward packets */

#define _ipv4_broadcast_compare(_i)                                  \
    do {                                                             \
        if (netif->ip4_addrs[_i].ip.s_addr) {                        \
            if (ip->s_addr == netif->ip4_addrs[_i].broadcast.s_addr) \
                return _i;                                           \
        }                                                            \
    } while (/*CONSTCOND*/ 0)

/**
 * Check if an IP address matches one of the netif subnets.
 */
static inline int
cnet_ipv4_broadcast(struct netif *netif, struct in_addr *ip)
{
    if (NUM_IP_ADDRS == 4) {
        _ipv4_broadcast_compare(0);
        _ipv4_broadcast_compare(1);
        _ipv4_broadcast_compare(2);
        _ipv4_broadcast_compare(3);
        return -1;
    }
    for (int i = 0; i < NUM_IP_ADDRS; i++)
        _ipv4_broadcast_compare(i);
    return -1;
}

#define _ipv4_compare(_i)                         \
    do {                                          \
        struct in_addr *ip2, *mask;               \
        ip2  = &netif->ip4_addrs[_i].ip;          \
        mask = &netif->ip4_addrs[_i].netmask;     \
        if (inet_addr_mask_cmp(&addr, ip2, mask)) \
            return _i;                            \
    } while (/*CONSTCOND*/ 0)

static inline int
cnet_ipv4_compare(struct netif *netif, struct in_addr *ip)
{
    struct in_addr addr;

    addr.s_addr = ntohl(ip->s_addr);
    if (NUM_IP_ADDRS == 4) {
        _ipv4_compare(0);
        _ipv4_compare(1);
        _ipv4_compare(2);
        _ipv4_compare(3);
        return -1;
    }
    for (int i = 0; i < NUM_IP_ADDRS; i++)
        _ipv4_compare(i);

    return -1;
}

/**
 * Using the netif index return the netif structure pointer.
 */
static inline struct netif *
cnet_netif_from_index(uint8_t idx)
{
    return vec_at_index(this_cnet->netifs, idx);
}

/**
 * Locate the closest matching IP address in all of the netif structures.
 */
static inline struct netif *
cnet_netif_match_subnet(struct in_addr *ipaddr)
{
    struct netif **netif;

    vec_foreach (netif, this_cnet->netifs) {
        if (cnet_ipv4_compare(*netif, ipaddr) != -1)
            return *netif;
    }
    return NULL;
}

/**
 * Free the given netif pointer back to the netif free list.
 */
static inline void
cnet_netif_free(struct netif *netif)
{
    if (netif) {
        if (netif->netif_idx >= 0 && netif->netif_idx < CNE_MAX_ETHPORTS)
            vec_at_index(this_cnet->netifs, netif->netif_idx) = NULL;
        free(netif);
    }
}

/**
 * Allocate a netif structure and return the pointer.
 */
static inline struct netif *
cnet_netif_alloc(uint16_t lpid)
{
    struct netif *netif = NULL;

    netif = calloc(1, sizeof(struct netif));
    if (!netif)
        return NULL;

    netif->netif_idx = -1;
    netif->ifindex   = -1;
    netif->lpid      = lpid;
    netif->ip_ident  = (uint16_t)(cne_rdtsc() & 0xFFFF);

    return netif;
}

/**
 * Get the flags for the given netif structure pointer.
 */
static inline int
cnet_netif_get_flags(struct netif *netif, uint32_t *flags)
{
    if (!flags || !netif)
        return -1;

    *flags = netif->ifflags;

    return 0;
}

/**
 * @brief Register lport, ifname and netdev to create a netif structure
 *
 * @param lpid
 *   The lport value to register
 * @param ifname
 *   The interface name
 * @param netdev
 *   The netdev name to assign to the netif structure
 * @return
 *   -1 on failure or 0 on success
 */
CNDP_API int cnet_netif_register(uint16_t lpid, char *ifname, char *netdev);

/**
 * @brief Attach ports to CNET and the netif structures
 *
 * @param cnet
 *   The CNET structure pointer
 * @return
 *   -1 on failure or 0 on success
 */
CNDP_API int cnet_netif_attach_ports(struct cnet *cnet);

/**
 * @brief Locate the netif for the given interface name.
 *
 * @param name
 *   The name of the interface to find
 * @param typ
 *   The type of netif to find.
 * @return
 *   NULL on error or pointer to netif structure
 */
CNDP_API struct netif *cnet_netif_from_name(const char *name, int typ);

/**
 * @brief Set the MTU for a given netif structure
 *
 * @param netif
 *   The netif structure pointer
 * @param mtu
 *   The MTU value to set
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netif_set_mtu(struct netif *netif, uint16_t mtu);

/**
 * @brief look over all netif structures calling the specified function
 *
 * @param func
 *   The function to call
 * @param arg
 *   The argument to pass to the function
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netif_foreach(int (*func)(struct netif *netif, void *arg), void *arg);

/**
 * @brief Find the given IPv4 address in a given netif structure
 *
 * @param netif
 *   The netif structure to search for the giben IPv4 address
 * @param ip
 *   The IPv4 address to search
 * @return
 *   NULL on error or pointer to inet4_addr structure
 */
CNDP_API struct inet4_addr *cnet_ipv4_ipaddr_find(struct netif *netif, struct in_addr *ip);

/**
 * @brief Delete the given IPv4 address from the given netif structure
 *
 * @param netif
 *   The netif structure to search for the giben IPv4 address
 * @param ip
 *   The IPv4 address to search
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_ipv4_ipaddr_delete(struct netif *netif, struct in_addr *ip);

/**
 * @brief Add a new IPv4 address to the given netif structure
 *
 * @param netif
 *   The netif structure to search for the giben IPv4 address
 * @param ip
 *   The IPv4 address to search
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_ipv4_ipaddr_add(struct netif *netif, struct inet4_addr *ip);

/**
 * @brief Add flags or set the flags to a netif structure
 *
 * @param netif
 *   The netif structure to search for the giben IPv4 address
 * @param flags
 *   The flags to set in the netif structure
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_netif_set_flags(struct netif *netif, uint32_t flags);

/**
 * @brief Find the netif structure for the given interface name
 *
 * @param ifname
 *   The interface name to search for in the system
 * @return
 *   NULL on error or pointer to netif structure
 */
CNDP_API struct netif *cnet_netif_find_by_name(char *ifname);

/**
 * @brief Locate the netif structure by the ifindex value
 *
 * @param ifindex
 *   The ifindex value for the netif structure
 * @return
 *   NULL on error or pointer to netif structure
 */
CNDP_API struct netif *cnet_netif_find_by_ifindex(int ifindex);

/**
 * @brief Find the netif structure by the netdev name
 *
 * @param netdev_name
 *   The netdev name to search for in system
 * @return
 *   NULL on error or pointer to netif structure
 */
CNDP_API struct netif *cnet_netif_find_by_netdev(char *netdev_name);

/**
 * @brief Find the netif structure by the lport id.
 *
 * @param lport
 *   The lport id value to help locate the netif pointer.
 * @return
 *   NULL on error or pointer to netif structure.
 */
CNDP_API struct netif *cnet_netif_find_by_lport(int lport);

/**
 * @brief Is the ifname a valid interface name
 *
 * @param ifname
 *   Locate and see if the interface name is known
 * @return
 *   0 on not found or 1 on found
 */
CNDP_API int cnet_is_ifname_valid(char *ifname);

/**
 * @brief Is the netdev name a valid netdev
 *
 * @param netdev_name
 *   Locate and see if the netdev name is known
 * @return
 *   0 on not found or 1 on found
 */
CNDP_API int cnet_is_netdev_valid(char *netdev_name);

/**
 * @brief Is the ifindex valid interface index
 *
 * @param ifindex
 *   The ifindex to validate
 * @return
 *   0 on not found or 1 on found
 */
CNDP_API int cnet_is_ifindex_valid(int ifindex);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_NETIF_H */
