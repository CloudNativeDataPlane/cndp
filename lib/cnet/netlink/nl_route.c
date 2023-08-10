/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
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
#include <cnet_route.h>
#include <cnet_route4.h>

#include <netlink/route/route.h>

#include <pthread.h>

#include <cne_log.h>        // for cne_panic
#include <hexdump.h>
#include <cne_rwlock.h>

#include <cnet_netif.h>

#include "cnet_netlink.h"
#include "netlink_private.h"

void
__nl_route(struct netlink_info *info, struct nl_object *obj, int action)
{
    struct rtnl_route *route = nl_object_priv(obj);
    struct rtnl_nexthop *first;
    struct nl_addr *nexthop = NULL, *gate = NULL;
    struct in_addr ipaddr, netmask, gateway;
    struct in6_addr ipaddr6, netmask6, gateway6;
    struct netif *netif;
    int ifindex = 0, rtype;

    if (rtnl_route_get_family(route) != AF_INET)
        return;

    first = rtnl_route_nexthop_n(route, 0);
    if (!first)
        CNE_RET("Failed to get nexthop (%d)\n", rtnl_route_get_nnexthops(route));

    ifindex = rtnl_route_nh_get_ifindex(first);
    if (!cnet_is_ifindex_valid(ifindex))
        return;
    netif = cnet_netif_find_by_ifindex(ifindex);
    if (!netif)
        CNE_RET("Failed to find netif by ifinex %d\n", ifindex);

    nexthop = rtnl_route_get_dst(route);
    if (!nexthop)
        return;

    gate = rtnl_route_nh_get_gateway(first);

    rtype = rtnl_route_get_type(route);
    if (netlink_debug) {
        char rtype_str[32];

        CNE_INFO("[magenta]Route Type[]: [cyan]%s[]\n",
                 nl_rtntype2str(rtype, rtype_str, sizeof(rtype_str)));
    }
    if (rtype != RTN_UNICAST /*&& rtype != RTN_BROADCAST && rtype != RTN_LOCAL*/)
        return;

    if (netlink_debug > 1) {
        char nexthop_str[32], gate_str[32], type_str[32];
        uint8_t typ = rtnl_route_get_type(route);

        cne_printf("[magenta]Route [cyan]%-10s[]: [orange]%-18s[] [magenta]GW [orange]%-18s "
                   "[magenta]Type [cyan]%-10s[] [magenta]Prefixlen [cyan]%u[]\n",
                   netif->ifname, nl_addr2str(nexthop, nexthop_str, sizeof(nexthop_str)),
                   nl_addr2str(gate, gate_str, sizeof(gate_str)),
                   nl_rtntype2str(typ, type_str, sizeof(type_str)), nl_addr_get_prefixlen(nexthop));
    }

    if (nl_addr_get_family(nexthop) == AF_INET6) {
        inet6_addr_zero(&ipaddr6);
        inet6_addr_zero(&gateway6);

        __size_to_mask6(nl_addr_get_prefixlen(nexthop), &netmask6);
        memcpy(&ipaddr6, nl_addr_get_binary_addr(nexthop), nl_addr_get_len(nexthop));
        if (gate)
            memcpy(&gateway6, nl_addr_get_binary_addr(gate), nl_addr_get_len(gate));

        inet6_addr_ntoh(&ipaddr6, &ipaddr6);
        inet6_addr_ntoh(&gateway6, &gateway6);
    } else /* IPv4 */ {
        ipaddr.s_addr  = 0;
        gateway.s_addr = 0;

        netmask.s_addr = 0xFFFFFFFFUL << (32 - nl_addr_get_prefixlen(nexthop));
        memcpy(&ipaddr.s_addr, nl_addr_get_binary_addr(nexthop), nl_addr_get_len(nexthop));
        if (gate)
            memcpy(&gateway.s_addr, nl_addr_get_binary_addr(gate), nl_addr_get_len(gate));

        ipaddr.s_addr  = be32toh(ipaddr.s_addr);
        gateway.s_addr = be32toh(gateway.s_addr);
    }

    switch (action) {
    case NL_ACT_NEW:
        NL_DEBUG("New:\n   ");
        NL_OBJ_DUMP(obj);

        if (nl_addr_get_family(nexthop) == AF_INET6) {
            if (cnet_route6_insert(netif->netif_idx, &ipaddr6, &netmask6, NULL, RTM_INFINITY, 0) <
                0)
                CNE_RET("Unable to insert route\n");
        } else /* IPv4 */ {
            if (cnet_route4_insert(netif->netif_idx, &ipaddr, &netmask, NULL, RTM_INFINITY, 0) < 0)
                CNE_RET("Unable to insert route\n");
        }
        break;

    case NL_ACT_CHANGE:
        NL_DEBUG("Change:\n   ");
        NL_OBJ_DUMP(obj);
        break;

    case NL_ACT_DEL:
        NL_DEBUG("Delete:\n   ");
        NL_OBJ_DUMP(obj);

        if (nl_addr_get_family(nexthop) == AF_INET6) {
            if (cnet_route6_delete(&ipaddr6) < 0)
                CNE_RET("Unable to delete route\n");
        } else /* IPv4 */ {
            if (cnet_route4_delete(&ipaddr) < 0)
                CNE_RET("Unable to delete route\n");
        }
        break;
    }
    if (netlink_debug)
        cne_printf("\n");
}

static void
route_walk(struct nl_object *obj, void *arg)
{
    struct netlink_info *info = arg;

    __nl_route(info, obj, NL_ACT_NEW);
}

int
cnet_netlink_add_routes(void *_info)
{
    struct netlink_info *info = _info;
    struct nl_cache *cache;

    NL_DEBUG("[magenta]Process [orange]route/route[]\n");

    cache = nl_cache_mngt_require_safe("route/route");
    if (!cache)
        CNE_ERR_RET("Failed to require route/route\n");

    nl_cache_foreach(cache, route_walk, info);

    if (cache)
        nl_cache_put(cache);
    return 0;
}
