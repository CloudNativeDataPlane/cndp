/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2025 Intel Corporation
 */

#include <stdio.h>         // for stdout, NULL
#include <stdint.h>        // for uint16_t, uint64_t, uint8_t, int32_t
#include <stdlib.h>        // for atoi
#include <string.h>        // for strcmp, strerror
#include <linux/netlink.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bsd/string.h>

#include <cne_common.h>
#include <net/cne_ether.h>

#include <cnet_const.h>
#include <cnet_reg.h>
#include <cnet_stk.h>
#include <cne_inet.h>
#include <cnet_netif.h>
#include <cnet_arp.h>
#include <cnet_nd6.h>

#include <netlink/route/addr.h>

#include <pthread.h>

#include <cne_log.h>        // for cne_panic
#include <hexdump.h>
#include <cne_rwlock.h>

#include "cnet_netif.h"
#include "cnet_netlink.h"
#include "cnet_route4.h"
#include "cnet_route6.h"
#include "netlink_private.h"

void
__nl_addr(struct netlink_info *info, struct nl_object *obj, int action)
{
    struct rtnl_addr *addr = nl_object_priv(obj);
    struct netif *netif;
    struct nl_addr *a;
    struct inet4_addr ip4 = {0};
    struct inet6_addr ip6 = {0};
    struct ether_addr mac = {0};
    int ifindex, a_family;

    ifindex = rtnl_addr_get_ifindex(addr);

    if (!cnet_is_ifindex_valid(ifindex))
        return;

    if (rtnl_addr_get_family(addr) != AF_INET && rtnl_addr_get_family(addr) != AF_INET)
        return;

    netif = cnet_netif_find_by_ifindex(ifindex);
    if (!netif)
        return;

    netif->family      = rtnl_addr_get_family(addr);
    ip4.prefixlen      = rtnl_addr_get_prefixlen(addr);
    ip4.netmask.s_addr = (0xFFFFFFFF << (32 - ip4.prefixlen));
    memcpy(&mac, &netif->mac, sizeof(struct ether_addr));

    a = rtnl_addr_get_local(addr);
    if (!a)
        CNE_RET("Failed to get local address\n");

    a_family = nl_addr_get_family(a);
    if (a_family == AF_INET6) {
        memcpy(&ip6.ip, nl_addr_get_binary_addr(a), nl_addr_get_len(a));
        inet6_addr_ntoh(&ip6.ip, &ip6.ip);
    } else /* IPv4 */ {
        memcpy(&ip4.ip.s_addr, nl_addr_get_binary_addr(a), nl_addr_get_len(a));
        ip4.ip.s_addr = be32toh(ip4.ip.s_addr);
    }

    a = rtnl_addr_get_broadcast(addr);
    if (a) {
        if (nl_addr_get_family(a) == AF_INET6) {
            memcpy(&ip6.broadcast, nl_addr_get_binary_addr(a), nl_addr_get_len(a));
            inet6_addr_ntoh(&ip6.broadcast, &ip6.broadcast);
        } else /* IPv4 */ {
            memcpy(&ip4.broadcast.s_addr, nl_addr_get_binary_addr(a), nl_addr_get_len(a));
            ip4.broadcast.s_addr = be32toh(ip4.broadcast.s_addr);
        }
    }

    switch (action) {
    case NL_ACT_NEW:
        NL_DEBUG("New:\n   ");
        NL_OBJ_DUMP(obj);

        if (a_family == AF_INET6) {
            if (cnet_ipv6_ipaddr_add(netif, &ip6) < 0)
                CNE_WARN("Unable to set address for %s\n", netif->ifname);

            if (cnet_nd6_add(netif->netif_idx, &ip6.ip, &mac, ND_REACHABLE) == NULL)
                CNE_WARN("Unable to set ND6 entry for %s\n", netif->ifname);

            __size_to_mask6(128, &ip6.netmask);
            if (cnet_route6_insert(netif->netif_idx, &ip6.ip, &ip6.netmask, NULL, 16, 0) < 0)
                CNE_WARN("Unable to insert route for %s\n", netif->ifname);

        } else /* IPv4 */ {
            if (cnet_ipv4_ipaddr_add(netif, &ip4) < 0)
                CNE_WARN("Unable to set address for %s\n", netif->ifname);

            if (cnet_arp_add(netif->netif_idx, &ip4.ip, &mac, 1) == NULL)
                CNE_WARN("Unable to set ARP for %s\n", netif->ifname);

            ip4.netmask.s_addr = 0xFFFFFFFF;
            if (cnet_route4_insert(netif->netif_idx, &ip4.ip, &ip4.netmask, NULL, 16, 0) < 0)
                CNE_WARN("Unable to insert route for %s\n", netif->ifname);
        }
        break;

    case NL_ACT_CHANGE:
        NL_DEBUG("Change:\n   ");
        NL_OBJ_DUMP(obj);

        if (a_family == AF_INET6) {
            if (cnet_ipv6_ipaddr_add(netif, &ip6) < 0)
                CNE_WARN("Unable to set address for %s\n", netif->ifname);
        } else /* IPv4 */ {
            if (cnet_ipv4_ipaddr_add(netif, &ip4) < 0)
                CNE_WARN("Unable to set address for %s\n", netif->ifname);
        }
        break;

    case NL_ACT_DEL:
        NL_DEBUG("Delete:\n   ");
        NL_OBJ_DUMP(obj);

        if (a_family == AF_INET6) {
            if (cnet_ipv6_ipaddr_delete(netif, &ip6.ip) < 0)
                CNE_WARN("Unable to delete address for %s\n", netif->ifname);

            if (cnet_nd6_delete(&ip6.ip) < 0)
                CNE_WARN("Unable to delete ND6 entry for %s\n", netif->ifname);

            if (cnet_route6_delete(&ip6.ip) < 0)
                CNE_WARN("Unable to delete route for %s\n", netif->ifname);

        } else /* IPv4 */ {
            if (cnet_ipv4_ipaddr_delete(netif, &ip4.ip) < 0)
                CNE_WARN("Unable to delete address for %s\n", netif->ifname);

            if (cnet_arp_delete(&ip4.ip) < 0)
                CNE_WARN("Unable to delete ARP for %s\n", netif->ifname);

            if (cnet_route4_delete(&ip4.ip) < 0)
                CNE_WARN("Unable to delete route for %s\n", netif->ifname);
        }
        break;
    }
}

static void
addr_walk(struct nl_object *obj, void *arg)
{
    struct netlink_info *info = arg;

    __nl_addr(info, obj, NL_ACT_NEW);
}

int
cnet_netlink_add_addrs(void *_info)
{
    struct netlink_info *info = _info;
    struct nl_cache *cache;

    NL_DEBUG("[magenta]Process [orange]route/addr[]\n");

    cache = nl_cache_mngt_require_safe("route/addr");
    if (!cache)
        CNE_ERR_RET("Failed to require route/addr\n");

    nl_cache_foreach(cache, addr_walk, info);

    if (cache)
        nl_cache_put(cache);
    return 0;
}
