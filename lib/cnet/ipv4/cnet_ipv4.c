/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <net/cne_ether.h>        // for CNE_ETHER_TYPE_IPV4, cne_ether_hdr
#include <hexdump.h>              // for cne_hexdump
#include <cnet.h>                 // for cnet_add_instance
#include <cnet_stk.h>             // for stk_entry, per_thread_stk, this_stk
#include <cne_inet.h>             // for in_caddr_create, inet_ntop4, in_c...
#include <cnet_drv.h>             // for drv_entry
#include <cnet_netif.h>           // for netif, cnet_netif_from_index...
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>             // for
#include <cnet_route.h>            // for _RTF_HOST
#include <cnet_route4.h>           // for
#include <cnet_arp.h>              // for
#include <cnet_ip_common.h>        // for ip_info
#include <endian.h>                // for be16toh, htobe16, be32toh
#include <netinet/in.h>            // for INADDR_BROADCAST, IN_MULTICAST
#include <stdint.h>                // for uint8_t, uint32_t, int32_t, uint16_t
#include <stdio.h>                 // for printf, NULL, fprintf, fflush
#include <stdlib.h>                // for calloc, free

#include "cne_branch_prediction.h"        // for unlikely
#include "cne_common.h"                   // for __cne_unused
#include "net/cne_ip.h"                   // for cne_ipv4_hdr, cne_ipv4_cksum
#include "net/cne_udp.h"                  // for cne_udp_hdr
#include "net/cne_tcp.h"                  // for cne_tcp_hdr
#include "cne_log.h"                      // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_W...
#include "cne_vec.h"
#include "cnet_const.h"        // for iofunc_t, BEST_MATCH, False, IPV4_IO
#include "cnet_reg.h"
#include "cnet_ipv4.h"           // for ipv4_entry, ipv4_stats, DEFAULT_I...
#include "cnet_protosw.h"        // for protosw_entry, cnet_ipproto_get
#include "pktmbuf.h"             // for pktmbuf_t, pktmbuf_free

static void
__ipv4_stats_dump(stk_t *stk)
{
    cne_printf("[magenta]Network Stack statistics[]: [orange]%s[]\n", stk->name);

#define _(stat) cne_printf("    [magenta]%-24s[]= [orange]%'ld[]\n", #stat, stk->ipv4->stats.stat)
    _(ip_ver_error);
    _(ip_hl_error);
    _(vec_pool_empty);
    _(ip_invalid_src_addr);
    _(ip_checksum_error);
    _(route_lookup_failed);
    _(ip_forward_failed);
    _(ip_reassemble_failed);
    _(ip_proto_invalid);
    _(ip_mbuf_too_small);
    _(ip_option_invalid);
    _(ip_mforward_pkts);
    _(ip_mforward_failed);
    _(ip_mlookup_failed);
    _(ip_forwarding_disabled);
#undef _
}

int
cnet_ipv4_stats_dump(stk_t *stk)
{
    if (stk)
        __ipv4_stats_dump(stk);
    else {
        vec_foreach_ptr (stk, this_cnet->stks)
            __ipv4_stats_dump(stk);
    }
    return 0;
}

void
cnet_ipv4_dump(const char *msg, struct cne_ipv4_hdr *ip)
{
    struct in_addr daddr, saddr;
    char ip1[IP4_ADDR_STRLEN] = {0};
    char ip2[IP4_ADDR_STRLEN] = {0};

    cne_printf("%s [cyan]IPv4 Header[] @ %p\n", (msg == NULL) ? "" : msg, ip);
    daddr.s_addr = ip->dst_addr;
    saddr.s_addr = ip->src_addr;
    cne_printf("   [cyan]Src [orange]%s [cyan]Dst [orange]%s [cyan]cksum [orange]%04x "
               "[cyan]version [orange]%d [cyan]hlen [orange]%d  [cyan]ver [orange]%02x[]\n",
               inet_ntop4(ip1, sizeof(ip1), &saddr, NULL),
               inet_ntop4(ip2, sizeof(ip2), &daddr, NULL), be16toh(ip->hdr_checksum),
               ip->version_ihl >> 4, (ip->version_ihl & 0x0f) << 2, ip->version_ihl);
    cne_printf("   [cyan]offset [orange]%d [cyan]next_proto [orange]%d [cyan]id [orange]%d "
               "[cyan]ttl [orange]%d [cyan]tlen [orange]%d [cyan]tos [orange]%d[]\n",
               ip->fragment_offset, ip->next_proto_id, be16toh(ip->packet_id), ip->time_to_live,
               be16toh(ip->total_length), ip->type_of_service);
}

static int
ipv4_create(void *_stk)
{
    stk_t *stk = _stk;

    stk->ipv4 = calloc(1, sizeof(struct ipv4_entry));
    if (stk->ipv4 == NULL)
        return -1;

    stk->ipv4->ip_forwarding = DEFAULT_FORWARDING_STATE;
    stk->ipv4->reassem_ttl   = 0;

    return 0;
}

static int
ipv4_destroy(void *_stk)
{
    stk_t *stk = _stk;

    free(stk->ipv4);
    stk->ipv4 = NULL;

    return 0;
}

CNE_INIT_PRIO(cnet_ipv4_constructor, STACK)
{
    cnet_add_instance("ipv4", CNET_IPV4_PRIO, ipv4_create, ipv4_destroy);
}
