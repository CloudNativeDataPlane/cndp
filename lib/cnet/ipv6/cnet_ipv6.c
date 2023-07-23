/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <net/cne_ether.h>        // for CNE_ETHER_TYPE_IPV4, cne_ether_hdr
#include <hexdump.h>              // for cne_hexdump
#include <cnet.h>                 // for cnet_add_instance
#include <cnet_stk.h>             // for stk_entry, per_thread_stk, this_stk
#include <cne_inet.h>             // for in_caddr_create, inet_ntop4, in_c...
#include <cnet_drv.h>             // for drv_entry
#include <cnet_netif.h>           // for netif, cnet_netif_from_index...

#include <cnet_route.h>         // for _RTF_HOST
#include <cnet_route6.h>        // for

#include <cnet_arp.h>              // for
#include <cnet_ip_common.h>        // for ip_info
#include <endian.h>                // for be16toh, htobe16, be32toh
#include <netinet/in.h>            // for INADDR_BROADCAST, IN_MULTICAST
#include <stdint.h>                // for uint8_t, uint32_t, int32_t, uint16_t
#include <stdio.h>                 // for printf, NULL, fprintf, fflush
#include <stdlib.h>                // for calloc, free

#include "cne_branch_prediction.h"        // for unlikely
#include "cne_common.h"                   // for __cne_unused
#include "net/cne_udp.h"                  // for cne_udp_hdr
#include "net/cne_tcp.h"                  // for cne_tcp_hdr
#include "cne_log.h"                      // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_W...
#include "cne_vec.h"
#include "cnet_const.h"        // for iofunc_t, BEST_MATCH, False, IPV4_IO
#include "cnet_reg.h"
#include "cnet_ipv6.h"            // for ipv6_entry, ipv6_stats, DEFAULT_I...
#include "cnet_protosw.h"         // for protosw_entry, cnet_ipproto_get
#include "pktmbuf.h"              // for pktmbuf_t, pktmbuf_free
#include <cne_fib6.h>             // for IPV6_ADDR_LEN
#include <ip6_flowlabel.h>        // for srhash_init0()

static void
__ipv6_stats_dump(stk_t *stk)
{
    cne_printf("[magenta]Network Stack statistics[]: [orange]%s[]\n", stk->name);

#define _(stat) cne_printf("    [magenta]%-24s[]= [orange]%'ld[]\n", #stat, stk->ipv6->stats.stat)
    _(ip6_ver_error);
    _(ip6_hl_error);
    _(vec6_pool_empty);
    _(ip6_invalid_src_addr);
    _(route6_lookup_failed);
    _(ip6_forward_failed);
    _(ip6_reassemble_failed);
    _(ip6_proto_invalid);
    _(ip6_mbuf_too_small);
    _(ip6_option_invalid);
    _(ip6_mforward_pkts);
    _(ip6_mforward_failed);
    _(ip6_mlookup_failed);
    _(ip6_forwarding_disabled);
#undef _
}

int
cnet_ipv6_stats_dump(stk_t *stk)
{
    if (stk)
        __ipv6_stats_dump(stk);
    else {
        vec_foreach_ptr (stk, this_cnet->stks)
            __ipv6_stats_dump(stk);
    }
    return 0;
}

void
cnet_ipv6_dump(const char *msg, struct cne_ipv6_hdr *ip6)
{
    struct in6_addr daddr, saddr;
    char ip6_src[IP6_ADDR_STRLEN] = {0};
    char ip6_dst[IP6_ADDR_STRLEN] = {0};

    cne_printf("%s [cyan]IPv6 Header[] @ %p\n", (msg == NULL) ? "" : msg, ip6);

    memcpy(daddr.s6_addr, ip6->dst_addr, IPV6_ADDR_LEN);
    memcpy(saddr.s6_addr, ip6->src_addr, IPV6_ADDR_LEN);
    cne_printf(
        "   [cyan]Src [orange]%s \n [cyan]Dst [orange]%s \n"
        "[cyan]Version [orange]%d [cyan]Traffic Class [orange]%d  [cyan]Flow Label [orange]%d\n",
        inet_ntop(AF_INET6, &saddr, ip6_src, sizeof(ip6_src)),
        inet_ntop(AF_INET6, &daddr, ip6_dst, sizeof(ip6_dst)), ip6_get_version(ip6),
        ip6_get_tclass(ip6), ip6_get_flowlabel(ip6));
    cne_printf("   [cyan]Payload Length [orange]%d [cyan]Next Header [orange]%d [cyan]Hop Limit "
               "[orange]%d ",
               be16toh(ip6->payload_len), ip6->proto, ip6->hop_limits);
}

static int
ipv6_create(void *_stk)
{
    stk_t *stk = _stk;

    do_srhash_init(0);

    stk->ipv6 = calloc(1, sizeof(struct ipv6_entry));
    if (stk->ipv6 == NULL)
        return -1;

    stk->ipv6->ip6_forwarding = DEFAULT_FORWARDING_STATE;
    stk->ipv6->reassem_ttl    = 0;

    return 0;
}

static int
ipv6_destroy(void *_stk)
{
    stk_t *stk = _stk;

    free(stk->ipv6);
    stk->ipv6 = NULL;

    return 0;
}

CNE_INIT_PRIO(cnet_ipv6_constructor, STACK)
{
    cnet_add_instance("ipv6", CNET_IPV6_PRIO, ipv6_create, ipv6_destroy);
}
