/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
 */

#include <stdlib.h>               // for NULL, strtoul
#include <string.h>               // for strcmp, strrchr
#include <sys/socket.h>           // for AF_INET
#include <arpa/inet.h>            // for inet_pton
#include <net/cne_ether.h>        // for ether_format_addr
#include <cnet.h>                 // for cnet_add_instance
#include <cnet_reg.h>
#include <cnet_stk.h>          // for stk_entry
#include <cne_inet.h>          // for _in_addr, inet_ntop4
#include <cnet_drv.h>          // for drv_entry
#include <cnet_netif.h>        // for net_addr, netif, net_addr::(anonymous), _IF...
#include <cnet_ifshow.h>
#include <endian.h>          // for htobe32, be32toh
#include <inttypes.h>        // for PRIu64

#include "cne_common.h"         // for __cne_unused
#include "cne_lport.h"          // for lport_stats
#include "cnet_const.h"         // for CNET_UTILS_PRIO, is_clr
#include "mempool.h"            // for mempool_obj_iter, mempool_t
#include "pktdev_core.h"        // for cne_pktdev, pktdev_data

typedef struct flag_bits {
    const char *flag;
    uint32_t bits;
    uint32_t clear; /* And out the bits if set */
} flag_bits_t;

static void
netif_show(struct netif *netif, char *ifname)
{
    struct lport_stats *ps, stats = {0};
    int32_t j;
    struct in_addr addr;
    char ip1[IP4_ADDR_STRLEN] = {0};
    char ip2[IP4_ADDR_STRLEN] = {0};
    char ip3[IP4_ADDR_STRLEN] = {0};

#if CNET_ENABLE_IP6
    struct in6_addr addr6;
    char ip61[IP6_ADDR_STRLEN] = {0};
    char ip62[IP6_ADDR_STRLEN] = {0};
    char ip63[IP6_ADDR_STRLEN] = {0};
#endif

    if (netif->drv == NULL)
        return;

    /* When a interface is given only display that interface */
    if (ifname && strncmp(ifname, netif->ifname, sizeof(netif->ifname)))
        return;

    if (pktdev_stats_get(netif->lpid, &stats) < 0)
        return;

    cne_printf("  [orange]%-6s[] ", netif->ifname);
    cnet_print_flags(netif->ifflags);
    cne_printf(" [magenta]mtu [green]%d - [magenta]index [orange]%d[]\n", netif->mtu,
               netif->netif_idx);

    for (j = 0; j < NUM_IP_ADDRS; j++) {
        if (!netif->ip4_addrs[j].valid)
            continue;

        addr.s_addr = be32toh(netif->ip4_addrs[j].ip.s_addr);
        cne_printf("%9s[magenta]inet.%d[]: [orange]%-15s[]", "", j,
                   inet_ntop4(ip1, sizeof(ip1), &addr, NULL) ?: "Invalid IP");

        addr.s_addr = be32toh(netif->ip4_addrs[j].netmask.s_addr);
        cne_printf(" [magenta]netmask[]: [goldenrod]%-15s[]",
                   inet_ntop4(ip2, sizeof(ip2), &addr, NULL) ?: "Invalid IP");

        if (netif->ip4_addrs[j].broadcast.s_addr) {
            addr.s_addr = be32toh(netif->ip4_addrs[j].broadcast.s_addr);
            cne_printf(" [magenta]broadcast[]: [green]%-15s[]\n",
                       inet_ntop4(ip3, sizeof(ip3), &addr, NULL));
        } else
            cne_printf("\n");
    }

#if CNET_ENABLE_IP6
    for (j = 0; j < NUM_IP_ADDRS; j++) {
        if (!netif->ip6_addrs[j].valid)
            continue;

        inet6_addr_ntoh(&addr6, &netif->ip6_addrs[j].ip);
        cne_printf("%9s[magenta]inet.%d[]: [orange]%-15s[]", "", j,
                   inet_ntop6(ip61, sizeof(ip61), &addr6, NULL) ?: "Invalid IP");

        inet6_addr_ntoh(&addr6, &netif->ip6_addrs[j].netmask);
        cne_printf(" [magenta]netmask[]: [goldenrod]%-15s[]",
                   inet_ntop6(ip62, sizeof(ip62), &addr6, NULL) ?: "Invalid IP");

        if (netif->ip4_addrs[j].broadcast.s_addr) {
            inet6_addr_ntoh(&addr6, &netif->ip6_addrs[j].broadcast);
            cne_printf(" [magenta]broadcast[]: [green]%-15s[]\n",
                       inet_ntop6(ip63, sizeof(ip63), &addr6, NULL));
        } else
            cne_printf("\n");
    }
#endif

    ps = &stats;

    cne_printf("%9s[magenta]RX []:%'16" PRIu64 " [magenta]TX []:%'16" PRIu64 "[] ", "",
               ps->ipackets, ps->opackets);

    if ((netif->ifflags & _IFF_LOOPBACK) == 0) {
        char buf[64];

        ether_format_addr(buf, sizeof(buf), &netif->mac);
        cne_printf("[magenta]MAC[]: [skyblue]%s[]", buf);
    }
    cne_printf("\n");

    cne_printf("%9s[magenta]RXE[]:[red]%'16" PRIu64 "[] [magenta]TXE[]:[red]%'16" PRIu64
               "[] [magenta]MISS[]:[red]%'16" PRIu64 "[] \n",
               "", ps->ierrors, ps->oerrors, ps->imissed);
}

int
cnet_ifshow(char *ifname)
{
    struct cnet *cnet = this_cnet;
    struct netif *netif;

    vec_foreach_ptr (netif, cnet->netifs)
        netif_show(netif, ifname);

    return 0;
}
