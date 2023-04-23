/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <cnet.h>        // for cnet_add_instance
#include <cnet_reg.h>
#include <cnet_stk.h>             // for stk_entry, per_thread_stk, this_stk
#include <net/cne_inet6.h>        // for _in_addr, in_caddr_copy, inet_ntop6, in_caddr
#include <cnet_ipv6.h>            // for __netbytes
#include <cnet_netif.h>           // for netif
#include <endian.h>               // for be32toh
#include <stdio.h>                // for printf, NULL
#include <cne_fib6.h>             // for
#include <ip6_node_api.h>         // for cne_node_ip6_add_input()

#include "net/cne_inet6.h"
#include "cnet_fib_info.h"
#include "cnet_route.h"
#include "cnet_route6.h"
#include "ip6_input_priv.h"
#include "cne_vec.h"        // for vec_at_index, vec_len
#include "mempool.h"        // for mempool_destroy, mempool_cfg, mempool_create

#define RT6_DEFAULT_NUM_RULES 1024 /* Default number of max rules */
#define RT6_MAX_RULES \
    ((1UL << RT6_NEXT_INDEX_SHIFT) - 1) /* MAX routes (16M) leaving bit 24-31 a next node index */
#define RT6_DEFAULT_NUM_TBL8S (1 << 8)  /* Default number of tbl8 entries */

int
cnet_route6_insert(int netdev_idx, struct in6_addr *dst, struct in6_addr *netmask,
                   struct in6_addr *gate, uint8_t metric, uint16_t timo)
{
    struct rt6_entry *rt;
    int rc = -1;

    rt = cnet_route6_alloc();
    if (rt) {
        int idx;
        char ip[IP6_ADDR_STRLEN] = {0};
        uint8_t depth;
        fib_info_t *fi = this_cnet->rt6_finfo;

        inet6_addr_copy(&(rt->nexthop), dst);
        inet6_addr_copy(&(rt->netmask), netmask);
        inet6_addr_copy(&(rt->gateway), gate);
        rt->netif_idx = netdev_idx;
        rt->metric    = metric;
        rt->timo      = timo;

        idx = fib_info_alloc(fi, rt); /* Works for ip6 route as well */
        if (idx < 0)
            CNE_WARN("FIB allocate failed for %s\n",
                     inet_ntop6(ip, sizeof(ip), &rt->nexthop, &rt->netmask) ?: "Invalid IP");

        depth = __mask6_size(&rt->netmask);
        if ((rc = cne_node_ip6_add_input(fi->fib6, rt->nexthop.s6_addr, depth, (uint32_t)idx))) {
            (void)fib_info_free(fi, idx);
            CNE_ERR_RET("Add %s Failed: %s\n",
                        inet_ntop6(ip, sizeof(ip), &rt->nexthop, &rt->netmask) ?: "Invalid IP",
                        strerror(-rc));
        }
    }

    return rc;
}

int
cnet_route6_delete(struct in6_addr *ipaddr)
{
    fib_info_t *fi;
    uint64_t nexthop;

    fi = this_cnet->rt6_finfo;

    if (!fi || !ipaddr)
        return -1;

    if (likely(fib6_info_lookup_index(fi, &ipaddr->s6_addr, &nexthop, 1) > 0)) {
        struct rt6_entry *rt;

        if (fib_info_get(fi, &nexthop, (void **)&rt, 1) < 0)
            CNE_ERR_RET("Unable to delete FIB entry pointer\n");

        if (cne_fib6_delete(fi->fib6, rt->nexthop.s6_addr, __mask6_size(&rt->netmask)) < 0)
            CNE_ERR_RET("Unable to delete FIB6 entry\n");

        if (fib_info_free(fi, (uint32_t)nexthop) != rt)
            CNE_WARN("Freed entry does not match\n");
        cnet_route6_free(rt);
    }

    return 0;
}

int
cnet_route6_get_bulk(uint64_t *nh, struct rt6_entry **rt, int n)
{
    if (nh && rt && n > 0) {
        fib_info_t *fi = this_cnet->rt6_finfo;

        for (int i = 0; i < n; i++)
            rt[i] = fib_info_object_get(fi, (uint32_t)nh[i]);
    }
    return 0;
}

struct rt6_entry *
cnet_route6_get(uint64_t nh)
{
    struct rt6_entry *rt = NULL;

    return (cnet_route6_get_bulk(&nh, &rt, 1) < 0) ? NULL : rt;
}

int
cnet_route6_alloc_bulk(struct rt6_entry **rt, int n)
{
    if (mempool_get_bulk(this_cnet->rt6_obj, (void **)rt, n) < 0)
        return -1;

    return 0;
}

struct rt6_entry *
cnet_route6_alloc(void)
{
    struct rt6_entry *rt;

    return cnet_route6_alloc_bulk(&rt, 1) ? NULL : rt;
}

void
cnet_route6_free_bulk(struct rt6_entry **entry, int n)
{
    mempool_put_bulk(this_cnet->rt6_obj, (void **)entry, n);
}

void
cnet_route6_free(struct rt6_entry *entry)
{
    cnet_route6_free_bulk(&entry, 1);
}

void
cne_route6_timer(void)
{
    CNE_DEBUG("route6 timer not supported yet\n");
}

int
cne_route6_notify(void)
{
    CNE_DEBUG("route6 notify not supported yet\n");
    return 0;
}

int
cnet_route6_create(struct cnet *cnet, uint32_t num_rules, uint32_t num_tbl8s)
{
    fib_info_t *fi = NULL;
    struct cne_fib6 *fib;
    struct cne_fib6_conf cfg;

    struct mempool_cfg mcfg = {0};

    if (num_rules == 0 || (num_rules > RT6_MAX_RULES))
        num_rules = RT6_DEFAULT_NUM_RULES;
    if (num_tbl8s == 0)
        num_tbl8s = RT6_DEFAULT_NUM_TBL8S;

    num_rules        = cne_align32pow2(num_rules);
    cnet->num_routes = num_rules;

    cfg.type = CNE_FIB6_TRIE;
    cfg.default_nh =
        (uint64_t)((CNE_NODE_IP6_INPUT_NEXT_PKT_DROP << RT6_NEXT_INDEX_SHIFT) | (num_rules + 1));
    cfg.max_routes    = num_rules;
    cfg.trie.nh_sz    = CNE_FIB6_TRIE_4B;
    cfg.trie.num_tbl8 = num_tbl8s;

    fib = cne_fib6_create("rt6-fib", &cfg);
    if (!fib)
        CNE_ERR_GOTO(err, "Unable to create FIB6\n");

    fi = fib6_info_create(fib, num_rules, RT6_NEXT_INDEX_SHIFT);
    if (!fi) {
        cne_fib6_free(fib);
        CNE_ERR_GOTO(err, "Unable to allocate fib6_info structure\n");
    }

    cnet->rt6_finfo = fi;

    mcfg.objcnt   = num_rules;
    mcfg.objsz    = sizeof(struct rt6_entry);
    mcfg.cache_sz = 16;
    cnet->rt6_obj = mempool_create(&mcfg);
    if (cnet->rt6_obj == NULL)
        CNE_ERR_GOTO(err, "Unable to allocate rt6_obj\n");

    return 0;
err:
    cnet_route6_destroy(cnet);
    return -1;
}

int
cnet_route6_destroy(struct cnet *cnet)
{
    if (cnet) {
        fib_info_destroy(cnet->rt6_finfo);
        mempool_destroy(cnet->rt6_obj);
    }

    return 0;
}

static int
route6_dump(struct rt6_entry *rt, void *arg __cne_unused)
{
    struct netif *netif;
    struct in6_addr nh, mask, gate;
    char ip1[IP6_ADDR_STRLEN] = {0};
    char ip2[IP6_ADDR_STRLEN] = {0};
    char ip3[IP6_ADDR_STRLEN] = {0};

    inet6_addr_copy(&nh, &(rt->nexthop));
    inet6_addr_copy(&mask, &(rt->netmask));
    inet6_addr_copy(&gate, &(rt->gateway));

    cne_printf("  [yellow]%-17s ", inet_ntop6(ip1, sizeof(ip1), &nh, NULL) ?: "Invalid IP");
    cne_printf("[orange]%-17s [cyan]%3d  ",
               inet_ntop6(ip2, sizeof(ip2), &mask, NULL) ?: "Invalid IP", rt->netif_idx);

    netif = vec_at_index(this_cnet->netifs, rt->netif_idx);
    cne_printf("[orange]%-17s [cyan]%6d %7d   [magenta]%s[]\n",
               inet_ntop6(ip3, sizeof(ip3), &gate, NULL) ?: "Invalid IP", rt->metric, rt->timo,
               netif->ifname);

    return 0;
}

int
cnet_route6_show(void)
{
    cne_printf("[magenta]IPv6 Route Table for CNET on lcore [orange]%d[]\n", cne_lcore_id());
    cne_printf("  [magenta]%-17s %-17s  IF  %-17s Metric Timeout   Netdev[]\n", "Nexthop", "Mask",
               "Gateway");
    return fib_info_foreach(this_cnet->rt6_finfo, (fib_func_t)route6_dump, NULL);
}
