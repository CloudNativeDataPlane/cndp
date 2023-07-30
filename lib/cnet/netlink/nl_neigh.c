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
#include <cnet_nd6.h>

#include <netlink/route/neighbour.h>

#include <pthread.h>

#include <cne_log.h>        // for cne_panic
#include <hexdump.h>
#include <cne_rwlock.h>

#include <cnet_netif.h>

#include "cnet_netlink.h"
#include "netlink_private.h"

void
__nl_neigh(struct netlink_info *info, struct nl_object *obj, int action)
{
    struct rtnl_neigh *neigh = nl_object_priv(obj);
    struct nl_addr *dst = NULL, *lladdr = NULL;
    struct in_addr in   = {0};
    struct in6_addr in6 = {0};
    struct netif *netif;
    struct ether_addr mac = {0};
    int ifindex, state;

    ifindex = rtnl_neigh_get_ifindex(neigh);
    if (netlink_debug > 0) {
        struct nl_dump_params dp = DUMP_PARAMS_INIT(info, NL_DUMP_LINE);

        cne_printf("[magenta]Interface [orange]%d [magenta]dump[]: ", ifindex);
        nl_object_dump(obj, &dp);
    }

    netif = cnet_netif_find_by_ifindex(ifindex);
    if (!netif) {
        NL_DEBUG("Network interface %d not found\n", ifindex);
        return;
    }

    if (netlink_debug > 1) {
        struct nl_dump_params dp = DUMP_PARAMS_INIT(info, NL_DUMP_LINE);

        nl_object_dump(obj, &dp);
    }
    state = rtnl_neigh_get_state(neigh);

    if (netlink_debug > 1) {
        char state_str[32];

        CNE_INFO("[magenta]State[]: [orange]%s[]\n",
                 rtnl_neigh_state2str(state, state_str, sizeof(state_str)));
    }

    lladdr = rtnl_neigh_get_lladdr(neigh);
    dst    = rtnl_neigh_get_dst(neigh);
    if (!dst)
        CNE_RET("Neighbour dst is not available\n");

    if (state & NUD_NOARP) {
        NL_DEBUG("Interface %d has NOARP set\n", ifindex);
        return;
    }

    if (nl_addr_get_family(dst) == AF_INET6) {
        memcpy(&in6.s6_addr, nl_addr_get_binary_addr(dst), nl_addr_get_len(dst));
        inet6_addr_ntoh(&in6, &in6);
    } else /* IPv4 */ {
        memcpy(&in.s_addr, nl_addr_get_binary_addr(dst), nl_addr_get_len(dst));
        in.s_addr = be32toh(in.s_addr);
    }

    if (lladdr)
        memcpy(&mac, nl_addr_get_binary_addr(lladdr), nl_addr_get_len(lladdr));

    switch (action) {
    case NL_ACT_NEW:
        NL_DEBUG("New:\n   ");
        NL_OBJ_DUMP(obj);

        if (nl_addr_get_family(dst) == AF_INET6) {
            if (CNET_ENABLE_IP6 && cnet_nd6_add(netif->netif_idx, &in6, &mac, ND_REACHABLE) == 0)
                CNE_RET("Unable to add ND6 entry\n");
        } else /* IPv4 */ {
            if (cnet_arp_add(netif->netif_idx, &in, &mac, 0) == 0)
                CNE_RET("Unable to add ARP address\n");
        }
        break;

    case NL_ACT_CHANGE:
        NL_DEBUG("Change:\n   ");
        NL_OBJ_DUMP(obj);

        if (nl_addr_get_family(dst) == AF_INET6) {
            if (CNET_ENABLE_IP6 && cnet_nd6_add(netif->netif_idx, &in6, &mac, ND_REACHABLE) == 0)
                CNE_RET("Unable to add ND6 entry\n");
        } else /* IPv4 */ {
            if (cnet_arp_add(netif->netif_idx, &in, &mac, 0) == 0)
                CNE_RET("Unable to add ARP address\n");
        }
        break;

    case NL_ACT_DEL:
        NL_DEBUG("Delete:\n   ");
        NL_OBJ_DUMP(obj);

        if (nl_addr_get_family(dst) == AF_INET6) {
            if (CNET_ENABLE_IP6 && cnet_nd6_delete(&in6) < 0)
                CNE_RET("Unable to delete ND6 entry\n");
        } else /* IPv4 */ {
            if (cnet_arp_delete(&in) < 0)
                CNE_RET("Unable to delete ARP address\n");
        }
        break;
    default:
        CNE_WARN("Unknown action %d\n", action);
        break;
    }
}

static void
neigh_walk(struct nl_object *obj, void *arg)
{
    struct netlink_info *info = arg;

    __nl_neigh(info, obj, NL_ACT_NEW);
}

int
cnet_netlink_add_neighs(void *_info)
{
    struct netlink_info *info = _info;
    struct nl_cache *cache;

    NL_DEBUG("[magenta]Process [orange]route/neigh[]\n");

    cache = nl_cache_mngt_require_safe("route/neigh");
    if (!cache)
        CNE_ERR_RET("Failed to require route/neigh\n");

    nl_cache_foreach(cache, neigh_walk, info);

    if (cache)
        nl_cache_put(cache);
    return 0;
}
