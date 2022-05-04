/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
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

#include <netlink/route/addr.h>

#include <pthread.h>

#include <cne_log.h>        // for cne_panic
#include <hexdump.h>
#include <cne_rwlock.h>

#include "cnet_netlink.h"
#include "netlink_private.h"

void
__nl_link(struct netlink_info *info, struct nl_object *obj, int action)
{
    struct rtnl_link *link = nl_object_priv(obj);
    struct nl_cache *cache = NULL;
    struct nl_addr *a;
    struct netif *netif;
    char *ifname, link_str[IF_NAMESIZE + 1] = {0};
    int flags, ifindex;

    if ((cache = nl_cache_mngt_require_safe("route/link")) == NULL)
        return;

    if (rtnl_link_get_family(link) != AF_UNSPEC)
        goto leave;

    ifindex = rtnl_link_get_ifindex(link);
    ifname  = rtnl_link_i2name(cache, ifindex, link_str, IF_NAMESIZE);
    if (!ifname)
        goto leave;

    netif = cnet_netif_find_by_netdev(ifname);
    if (!netif) {
        if (netlink_debug > 1) {
            struct nl_dump_params dp = DUMP_PARAMS_INIT(info, NL_DUMP_LINE);

            nl_object_dump(obj, &dp);
        }
        goto leave;
    }
    netif->ifindex = ifindex;

    flags = rtnl_link_get_flags(link);

    switch (action) {
    case NL_ACT_NEW:
        NL_DEBUG("New:\n   ");
        NL_OBJ_DUMP(obj);

        if (cnet_netif_set_flags(netif, flags) < 0)
            CNE_ERR_GOTO(leave, "Unable to set ifflags\n");

        /* Get MAC address */
        a = rtnl_link_get_addr(link);
        memcpy(&netif->mac, nl_addr_get_binary_addr(a), sizeof(netif->mac));
        break;

    case NL_ACT_CHANGE:
        NL_DEBUG("Change:\n   ");
        NL_OBJ_DUMP(obj);

        if (cnet_netif_set_flags(netif, flags) < 0)
            CNE_ERR_GOTO(leave, "Unable to set ifflags\n");
        break;

    case NL_ACT_DEL:
        NL_DEBUG("Delete:\n   ");
        NL_OBJ_DUMP(obj);
        break;
    }
leave:
    if (cache)
        nl_cache_put(cache);
}

static void
link_walk(struct nl_object *obj, void *arg)
{
    struct netlink_info *info = arg;

    __nl_link(info, obj, NL_ACT_NEW);
}

int
cnet_netlink_add_links(void *_info)
{
    struct netlink_info *info = _info;
    struct nl_cache *cache;

    NL_DEBUG("[magenta]Process [orange]route/link[]\n");

    cache = nl_cache_mngt_require_safe("route/link");
    if (!cache)
        CNE_ERR_RET("Unable to require route/link\n");

    nl_cache_foreach(cache, link_walk, info);

    if (cache)
        nl_cache_put(cache);
    return 0;
}
