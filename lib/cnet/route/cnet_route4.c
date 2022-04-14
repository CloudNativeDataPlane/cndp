/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <cnet.h>        // for cnet_add_instance
#include <cnet_reg.h>
#include <cnet_stk.h>            // for stk_entry, per_thread_stk, this_stk
#include <cnet_inet.h>           // for _in_addr, in_caddr_copy, inet_ntop4, in_caddr
#include <cnet_ipv4.h>           // for __netbytes
#include <cnet_netif.h>          // for netif
#include <endian.h>              // for be32toh
#include <stdio.h>               // for printf, NULL
#include <cne_fib.h>             // for
#include <ip4_node_api.h>        // for

#include "cnet_fib_info.h"
#include "cnet_route.h"
#include "cnet_route4.h"
#include "ip4_input_priv.h"
#include "cne_vec.h"        // for vec_ptr_at_index, vec_len
#include "mempool.h"        // for mempool_destroy, mempool_cfg, mempool_create

#define RT4_DEFAULT_NUM_RULES 1024 /* Default number of max rules */
#define RT4_MAX_RULES \
    ((1UL << RT4_NEXT_INDEX_SHIFT) - 1) /* MAX routes (16M) leaving bit 24-31 a next node index */
#define RT4_DEFAULT_NUM_TBL8S (1 << 8)  /* Default number of tbl8 entries */

int
cnet_route4_insert(int netdev_idx, struct in_addr *dst, struct in_addr *netmask,
                   struct in_addr *gate, uint8_t metric, uint16_t timo)
{
    struct rt4_entry *rt;
    int rc = -1;

    rt = cnet_route4_alloc();
    if (rt) {
        int idx;
        uint8_t depth;
        fib_info_t *fi = this_cnet->rt4_finfo;

        rt->nexthop.s_addr = dst->s_addr;
        rt->netmask.s_addr = netmask->s_addr;
        rt->gateway.s_addr = (gate) ? gate->s_addr : 0;
        rt->netif_idx      = netdev_idx;
        rt->metric         = metric;
        rt->timo           = timo;

        idx = fib_info_alloc(fi, rt);
        if (idx < 0)
            CNE_WARN("FIB allocate failed for %s\n", inet_ntop4(&rt->nexthop, &rt->netmask));

        depth = __prefixbits(rt->netmask.s_addr);
        if ((rc = cne_node_ip4_add_input(fi->fib, rt->nexthop.s_addr, depth, (uint32_t)idx))) {
            (void)fib_info_free(fi, idx);
            CNE_ERR_RET("Add %s Failed: %s\n", inet_ntop4(&rt->nexthop, &rt->netmask),
                        strerror(-rc));
        }
    }

    return rc;
}

int
cnet_route4_delete(struct in_addr *ipaddr)
{
    fib_info_t *fi;
    uint64_t nexthop;

    fi = this_cnet->rt4_finfo;

    if (!fi || !ipaddr)
        return -1;

    if (likely(fib_info_lookup_index(fi, &ipaddr->s_addr, &nexthop, 1) > 0)) {
        struct rt4_entry *rt;

        if (fib_info_get(fi, &nexthop, (void **)&rt, 1) < 0)
            CNE_ERR_RET("Unable to delete FIB entry pointer\n");

        if (cne_fib_delete(fi->fib, rt->nexthop.s_addr, __prefixbits(rt->netmask.s_addr)) < 0)
            CNE_ERR_RET("Unable to delete FIB entry\n");

        if (fib_info_free(fi, (uint32_t)nexthop) != rt)
            CNE_WARN("Freed entry does not match\n");
        cnet_route4_free(rt);
    }

    return 0;
}

int
cnet_route4_get_bulk(uint64_t *nh, struct rt4_entry **rt, int n)
{
    if (nh && rt && n > 0) {
        fib_info_t *fi = this_cnet->rt4_finfo;

        for (int i = 0; i < n; i++)
            rt[i] = fib_info_object_get(fi, (uint32_t)nh[i]);
    }
    return 0;
}

struct rt4_entry *
cnet_route4_get(uint64_t nh)
{
    struct rt4_entry *rt = NULL;

    return (cnet_route4_get_bulk(&nh, &rt, 1) < 0) ? NULL : rt;
}

int
cnet_route4_alloc_bulk(struct rt4_entry **rt, int n)
{
    if (mempool_get_bulk(this_cnet->rt4_obj, (void **)rt, n) < 0)
        return -1;

    return 0;
}

struct rt4_entry *
cnet_route4_alloc(void)
{
    struct rt4_entry *rt;

    return cnet_route4_alloc_bulk(&rt, 1) ? NULL : rt;
}

void
cnet_route4_free_bulk(struct rt4_entry **entry, int n)
{
    mempool_put_bulk(this_cnet->rt4_obj, (void **)entry, n);
}

void
cnet_route4_free(struct rt4_entry *entry)
{
    cnet_route4_free_bulk(&entry, 1);
}

void
cne_route4_timer(void)
{
    /* TODO: add timer support */
}

int
cne_route4_notify(void)
{
    /* TODO: add notify support */
    return 0;
}

int
cnet_route4_create(struct cnet *cnet, uint32_t num_rules, uint32_t num_tbl8s)
{
    fib_info_t *fi = NULL;
    struct cne_fib *fib;
    struct cne_fib_conf cfg;

    struct mempool_cfg mcfg = {0};

    if (num_rules == 0 || (num_rules > RT4_MAX_RULES))
        num_rules = RT4_DEFAULT_NUM_RULES;
    if (num_tbl8s == 0)
        num_tbl8s = RT4_DEFAULT_NUM_TBL8S;

    num_rules        = cne_align32pow2(num_rules);
    cnet->num_routes = num_rules;

    cfg.type = CNE_FIB_DIR24_8;
    cfg.default_nh =
        (uint64_t)((CNE_NODE_IP4_INPUT_NEXT_PKT_DROP << RT4_NEXT_INDEX_SHIFT) | (num_rules + 1));
    cfg.max_routes       = num_rules;
    cfg.dir24_8.nh_sz    = CNE_FIB_DIR24_8_4B;
    cfg.dir24_8.num_tbl8 = num_tbl8s;

    fib = cne_fib_create("rt4-fib", &cfg);
    if (!fib)
        CNE_ERR_GOTO(err, "Unable to create FIB\n");

    fi = fib_info_create(fib, num_rules, RT4_NEXT_INDEX_SHIFT);
    if (!fi) {
        cne_fib_free(fib);
        CNE_ERR_GOTO(err, "Unable to allocate fib_info structure\n");
    }

    cnet->rt4_finfo = fi;

    mcfg.objcnt   = num_rules;
    mcfg.objsz    = sizeof(struct rt4_entry);
    mcfg.cache_sz = 16;
    cnet->rt4_obj = mempool_create(&mcfg);
    if (cnet->rt4_obj == NULL)
        CNE_ERR_GOTO(err, "Unable to allocate rt4_obj\n");

    return 0;
err:
    cnet_route4_destroy(cnet);
    return -1;
}

int
cnet_route4_destroy(struct cnet *cnet)
{
    if (cnet) {
        fib_info_destroy(cnet->rt4_finfo);
        mempool_destroy(cnet->rt4_obj);
    }

    return 0;
}

static int
route4_dump(struct rt4_entry *rt, void *arg __cne_unused)
{
    struct netif *netif;
    struct in_addr nh, mask, gate;

    nh.s_addr   = htobe32(rt->nexthop.s_addr);
    mask.s_addr = htobe32(rt->netmask.s_addr);
    gate.s_addr = htobe32(rt->gateway.s_addr);

    cne_printf("  [yellow]%-17s ", inet_ntop4(&nh, NULL));
    cne_printf("[orange]%-17s [cyan]%3d  ", inet_ntop4(&mask, NULL), rt->netif_idx);

    netif = vec_ptr_at_index(this_cnet->netifs, rt->netif_idx);
    cne_printf("[orange]%-17s [cyan]%6d %7d   [magenta]%s[]\n", inet_ntop4(&gate, NULL), rt->metric,
               rt->timo, netif->ifname);

    return 0;
}

int
cnet_route4_show(void)
{
    cne_printf("[magenta]Route Table for CNET on lcore [orange]%d[]\n", cne_lcore_id());
    cne_printf("  [magenta]%-17s %-17s  IF  %-17s Metric Timeout   Netdev[]\n", "Nexthop", "Mask",
               "Gateway");
    return fib_info_foreach(this_cnet->rt4_finfo, (fib_func_t)route4_dump, NULL);
}
