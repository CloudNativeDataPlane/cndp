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
#include <cne_thread.h>

#include <cnet_const.h>
#include <cnet_reg.h>
#include <cnet_stk.h>
#include <cne_inet.h>
#include <cnet_netif.h>
#include <cnet_arp.h>

#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/nexthop.h>

#include <pthread.h>

#include <cne_log.h>        // for cne_panic
#include <hexdump.h>
#include <cne_rwlock.h>

#include "cnet_netlink.h"
#include "netlink_private.h"

int netlink_debug = 0;

static void
__nl_invalid(struct netlink_info *info, struct nl_object *obj, int action __cne_unused)
{
    struct nl_dump_params dp = DUMP_PARAMS_INIT(info, NL_DUMP_LINE);

    CNE_WARN("[magenta]%-8s [red]%d[]: ", "Unknown", nl_object_get_msgtype(obj));

    nl_object_dump(obj, &dp);
}

// clang-format off
cache_info_t cache_info[] = {
    { .name = "route/link",   .func = __nl_link },
    { .name = "route/addr",   .func = __nl_addr },
    { .name = "route/neigh",  .func = __nl_neigh },
    { .name = "route/route",  .func = __nl_route },
    { .name = "CacheUnknown", .func = __nl_invalid }
};
// clang-format on

static void
netlink_callback(struct nl_cache *cache, struct nl_object *obj, int action, void *data)
{
    struct netlink_info *info = data;

    if (action == NL_ACT_NEW || action == NL_ACT_CHANGE || action == NL_ACT_DEL) {
        cache_info_t *ci = cache_find_by_ptr(cache);

        if (ci->cache == NULL) {
            NL_DEBUG("[magenta]Cache[]: [orange]%s[]\n", ci->name);
            return;
        }

        /* Call the netlink handler routine */
        ci->func(info, obj, action);
    }
}

static void
netlink_thread(void *arg)
{
    struct netlink_info *info = arg;
    int ret;

    while (!info->quit) {
        /* Poll the netlink caches handled by the netlink manager */
        ret = nl_cache_mngr_poll(info->mngr, 250);

        if (ret < 0 && ret != -NLE_INTR)
            CNE_RET("Polling failed: %s", nl_geterror(ret));
    }
    nl_cache_mngr_free(info->mngr);
    info->mngr = NULL;
    info->quit = 0; /* signal the thread has stopped */
}

static int
netlink_destroy(struct cnet *cnet)
{
    struct netlink_info *info;

    info = cnet->netlink_info;

    if (info) {
        int timo = 1000; /* Wait for 1 second for thread to die */

        cnet->netlink_info = NULL;
        info->quit         = 1;

        while (--timo && (info->quit == 1))
            usleep(1000); /* Wait a bit for the thread to die */

        if (info->sock)
            nl_socket_free(info->sock);
        free(info);
    }
    return 0;
}

static int
netlink_create(struct cnet *cnet)
{
    struct netlink_info *info;

    info = calloc(1, sizeof(struct netlink_info));
    if (info) {
        cnet->netlink_info = info;

        info->sock = nl_socket_alloc();
        if (!info->sock)
            CNE_ERR_GOTO(err, "Unable to allocate netlink_info structure\n");

        if (nl_cache_mngr_alloc(info->sock, NETLINK_ROUTE, NL_AUTO_PROVIDE, &info->mngr) < 0)
            CNE_ERR_GOTO(err, "unable to allocate manager route/link\n");

        for (int i = 0; i < CACHE_INFO_MAX; i++) {
            if (nl_cache_mngr_add(info->mngr, cache_info[i].name, netlink_callback, info,
                                  &cache_info[i].cache) < 0)
                CNE_ERR_GOTO(err, "unable to add manager %s\n", cache_info[i].name);
        }
    }
    return 0;
err:
    netlink_destroy(cnet);
    return -1;
}

int
cnet_netlink_start(void)
{
    struct cnet *cnet = this_cnet;
    struct netlink_info *info;

    if (!cnet)
        CNE_ERR_RET("struct cnet pointer is NULL\n");

    info = cnet->netlink_info;
    if (!info)
        CNE_ERR_RET("struct netlink_info pointer is NULL\n");

    if (thread_create("cnet-netlink", netlink_thread, info) < 0)
        CNE_ERR_RET("Unable to start netlink thread\n");

    return 0;
}

int
cnet_netlink_create(struct cnet *cnet)
{
    if (!cnet)
        return -1;

    if (netlink_create(cnet) < 0)
        CNE_ERR_RET("Unable to create netlink\n");

    if (cnet_netlink_add_links(cnet->netlink_info) < 0)
        CNE_ERR_RET("Unable to add links\n");

    if (cnet_netlink_add_addrs(cnet->netlink_info) < 0)
        CNE_ERR_RET("Unable to add addrs\n");

    if (cnet_netlink_add_routes(cnet->netlink_info) < 0)
        CNE_ERR_RET("Unable to add routes\n");

    if (cnet_netlink_add_neighs(cnet->netlink_info) < 0)
        CNE_ERR_RET("Unable to add neighbours\n");

    return 0;
}

int
cnet_netlink_destroy(struct cnet *cnet)
{
    if (!cnet)
        return -1;

    return netlink_destroy(cnet);
}
