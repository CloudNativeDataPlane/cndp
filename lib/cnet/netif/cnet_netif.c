/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <net/cne_ether.h>        // for CNE_ETHER_TYPE_ARP, CNE_ETHER_TYPE_IPV4, CNE...
#include <mempool.h>              // for mempool_cfg, mempool_create, mempool_obj_iter
#include <cnet.h>                 // for cnet_add_instance, cnet_new_if_index, per_th...
#include "cnet_reg.h"
#include <cne_inet.h>        // for in_caddr_create, _in_addr, in_caddr
#include <cnet_drv.h>        // for drv_entry
#include <cnet_ip_common.h>
#include <cnet_netif.h>
#include <cnet_eth.h>           // for cnet_eth_init
#include <cnet_route.h>         // for
#include <cnet_route4.h>        // for
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>         // for AF_INET, CH_UNSPEC
#include <endian.h>            // for be32toh
#include <stdatomic.h>         // for atomic_fetch_add
#include <string.h>            // for NULL, strcmp, strerror
#include <bsd/string.h>        // for
#include <cnet_arp.h>

#include "cne_log.h"           // for CNE_ERR_RET
#include "pktdev_api.h"        // for pktdev_start, pktdev_stats_get, pktdev_stats...

int
cnet_netif_set_mtu(struct netif *netif, uint16_t mtu)
{
    cnet_assert((netif == NULL) || (netif->drv == NULL));

    netif->mtu = mtu;

    return 0;
}

int
cnet_netif_set_flags(struct netif *netif, uint32_t flags)
{
    uint32_t oflags;
    int ret;
    uint16_t port;

    cnet_assert((netif != NULL) && (netif->drv != NULL));

    port = netif->lpid;

    if ((oflags = netif->ifflags) != flags) {
        netif->ifflags = flags;

        if (is_clr(oflags, _IFF_UP) && is_set(flags, _IFF_UP)) {
            if ((ret = pktdev_start(port)) < 0)
                CNE_ERR_RET("pktdev_dev_start: port=%d, %s", port, strerror(-ret));
        } else if (is_set(oflags, _IFF_UP) && is_clr(flags, _IFF_UP))
            pktdev_stop(netif->lpid);
    }
    return 0;
}

static struct inet4_addr *
ipv4_ipaddr_alloc(struct netif *netif)
{
    for (int i = 0; i < NUM_IP_ADDRS; i++) {
        struct inet4_addr *net = &netif->ip4_addrs[i];

        if (net->valid == 0) {
            net->valid = 1;
            return net;
        }
    }

    return NULL;
}

static int
ipv4_ipaddr_free(struct netif *netif, struct inet4_addr *net)
{
    if (netif && net && net->valid) {
        memset(net, 0, sizeof(struct inet4_addr));
        return 0;
    }
    return -1;
}

struct inet4_addr *
cnet_ipv4_ipaddr_find(struct netif *netif, struct in_addr *ip)
{
    for (int i = 0; i < NUM_IP_ADDRS; i++) {
        struct inet4_addr *net = &netif->ip4_addrs[i];

        if (net->valid && (net->ip.s_addr == ip->s_addr))
            return net;
    }
    return NULL;
}

int
cnet_ipv4_ipaddr_delete(struct netif *netif, struct in_addr *ip)
{
    struct inet4_addr *net;

    if (ip) {
        net = cnet_ipv4_ipaddr_find(netif, ip);
        if (net)
            return ipv4_ipaddr_free(netif, net);
    }
    return -1;
}

int
cnet_ipv4_ipaddr_add(struct netif *netif, struct inet4_addr *ip)
{
    struct inet4_addr *net;

    if (netif && ip) {
        net = cnet_ipv4_ipaddr_find(netif, &ip->ip);
        if (!net) {
            net = ipv4_ipaddr_alloc(netif);
            if (net) { /* Add the IP address information */
                net->ip.s_addr        = ip->ip.s_addr;
                net->broadcast.s_addr = ip->broadcast.s_addr;
                net->netmask.s_addr   = ip->netmask.s_addr;
                return 0;
            }
        } else { /* Update the ip address information */
            net->ip.s_addr        = ip->ip.s_addr;
            net->broadcast.s_addr = ip->broadcast.s_addr;
            net->netmask.s_addr   = ip->netmask.s_addr;
        }
    }
    return -1;
}

struct netif *
cnet_netif_from_name(const char *ifname, int typ)
{
    struct netif *netif;

    vec_foreach_ptr (netif, this_cnet->netifs) {
        if ((typ == NETIF_IFNAME_TYPE) && !strcmp(ifname, netif->ifname))
            return netif;
        if ((typ == NETIF_NETDEV_NAME_TYPE) && !strcmp(ifname, netif->netdev_name))
            return netif;
    }

    return NULL;
}

int
cnet_netif_attach_ports(struct cnet *cnet)
{
    struct drv_entry *drv;
    struct netif *netif = NULL;

    for (uint16_t lpid = 0; lpid < CNE_MAX_ETHPORTS; lpid++) {
        if ((netif = vec_at_index(this_cnet->netifs, lpid)) == NULL)
            continue;

        /* grab the driver that matches the port id */
        drv = vec_at_index(cnet->drvs, lpid);
        if (!drv)
            CNE_ERR_RET("Unable to find driver for %d - %s\n", lpid, netif->ifname);

        netif->drv = drv;
        drv->netif = netif;

        pktdev_stats_reset(lpid);
    }

    return 0;
}

int
cnet_netif_register(uint16_t lpid, char *ifname, char *netdev)
{
    struct cnet *cnet   = this_cnet;
    struct netif *netif = NULL;

    if ((lpid >= CNE_MAX_ETHPORTS) || !ifname || !netdev)
        CNE_ERR_GOTO(leave, "Arguments are invalid\n");

    if ((netif = cnet_netif_alloc(lpid)) == NULL)
        CNE_ERR_GOTO(leave, "Unable to allocate netif structure\n");

    strlcpy(netif->ifname, ifname, sizeof(netif->ifname));

    /* when netdev is NULL we have a virtual interface */
    if (netdev)
        strlcpy(netif->netdev_name, netdev, sizeof(netif->netdev_name));

    /* The netif_idx is the index into the vector list */
    netif->netif_idx = vec_add(cnet->netifs, netif);

    return 0;
leave:
    cnet_netif_free(netif);
    return -1;
}

int
cnet_netif_foreach(int (*func)(struct netif *netif, void *arg), void *arg)
{
    struct netif *netif;

    if (!func)
        return -1;

    vec_foreach_ptr (netif, this_cnet->netifs) {
        if (netif && func(netif, arg) < 0)
            return -1;
    }

    return 0;
}

struct netif *
cnet_netif_find_by_name(char *ifname)
{
    struct netif *netif;

    vec_foreach_ptr (netif, this_cnet->netifs) {
        if (netif && !strncmp(netif->ifname, ifname, sizeof(netif->ifname)))
            return netif;
    }
    return NULL;
}

struct netif *
cnet_netif_find_by_ifindex(int ifindex)
{
    struct netif *netif;

    vec_foreach_ptr (netif, this_cnet->netifs) {
        if (netif && (ifindex == netif->ifindex))
            return netif;
    }
    return NULL;
}

struct netif *
cnet_netif_find_by_netdev(char *netdev_name)
{
    struct netif *netif;

    vec_foreach_ptr (netif, this_cnet->netifs) {
        if (netif && !strncmp(netif->netdev_name, netdev_name, sizeof(netif->ifname)))
            return netif;
    }
    return NULL;
}

struct netif *
cnet_netif_find_by_lport(int lport)
{
    struct netif *netif;

    vec_foreach_ptr (netif, this_cnet->netifs) {
        if (netif && netif->lpid == lport)
            return netif;
    }
    return NULL;
}

int
cnet_is_ifname_valid(char *ifname)
{
    return cnet_netif_find_by_name(ifname) ? 1 : 0;
}

int
cnet_is_netdev_valid(char *netdev_name)
{
    return cnet_netif_find_by_netdev(netdev_name) ? 1 : 0;
}

int
cnet_is_ifindex_valid(int ifindex)
{
    return cnet_netif_find_by_ifindex(ifindex) ? 1 : 0;
}
