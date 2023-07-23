/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <cne_hash.h>        // for cne_hash_add_key_data, cne_hash_d...
#include <endian.h>          // for htobe16
#include <mempool.h>         // for mempool_destroy, mempool_get, mem...
#ifdef CNE_MACHINE_CPUFLAG_SSE4_2
#include <cne_hash_crc.h>        // for cne_hash_crc

#define DEFAULT_HASH_FUNC cne_hash_crc
#else
#include <cne_jhash.h>

#define DEFAULT_HASH_FUNC cne_jhash
#endif

#include <cnet.h>        // for cnet_add_instance
#include <cnet_nd6.h>
#include <cnet_netif.h>        // for netif, net_addr, cnet_netif_match...
#include <nd6.h>

#include "cne_branch_prediction.h"        // for unlikely
#include "cne_build_config.h"             // for CNE_MACHINE_CPUFLAG_SSE4_2
#include "cne_log.h"                      // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_W...
#include "cne_vec.h"                      // for vec_len
#include <cne_fib.h>
#include "private_fib6.h"
#include <cnet_fib_info.h>
#include <ip6_input_priv.h>
#include <net/cne_ether.h>        // for ether_addr_copy, ether_format_addr

struct nd6_cache_entry *
cnet_nd6_alloc(void)
{
    struct cnet *cnet             = this_cnet;
    struct nd6_cache_entry *entry = NULL;

    if (mempool_get(cnet->nd6_obj, (void **)&entry) < 0)
        return NULL;

    return entry;
}

/** Free an NDP entry to the objpool */
void
cnet_nd6_free(struct nd6_cache_entry *entry)
{
    struct cnet *cnet = this_cnet;

    if (entry)
        mempool_put(cnet->nd6_obj, entry);
}

struct nd6_cache_entry *
cnet_nd6_add(int netif_idx, struct in6_addr *addr, struct ether_addr *mac, ND_STATE state)
{
    struct nd6_cache_entry *entry = NULL;
    fib_info_t *fi                = this_cnet->nd6_finfo;
    struct in6_addr mask;
    int ret;
    uint64_t idx;

    __size_to_mask6(128, &mask);        // CNE_FIB6_MAXDEPTH ?

    ret = fib6_info_lookup(fi, &addr->s6_addr, (void **)&entry, 1);
    if (unlikely(ret > 0 && ret <= ND6_FIB_MAX_ENTRIES)) {
        /* Found the entry just update the MAC address and return */
        if (mac)
            ether_addr_copy(mac, &entry->ll_addr);

        entry->reach_state = state;
        return entry;
    }

    if (netif_idx < 0)
        return NULL;

    entry = cnet_nd6_alloc();
    if (entry) {
        char ipaddr[IP6_ADDR_STRLEN] = {0};

        entry->netif_idx = netif_idx; /* Netif index value of sending/source
                                         interface from this host/router */

        inet6_addr_copy(&entry->nbr_addr6, addr);

        /* We may not have ll addr in the beginning */
        if (mac)
            ether_addr_copy(mac, &entry->ll_addr);

        entry->reach_state                 = state;
        entry->ar_packets_queue            = NULL;
        entry->num_unans_probes            = 0;
        entry->next_unreachd_event.tv_sec  = 0;
        entry->next_unreachd_event.tv_usec = 0;

        ret = fib_info_alloc(fi, entry);
        if (ret < 0)
            CNE_WARN("FIB allocate failed for %s\n",
                     inet_ntop6(ipaddr, sizeof(ipaddr), &entry->nbr_addr6, &mask) ?: "Invalid IP6");

        idx = ret;
        if (cne_fib6_add(fi->fib6, addr->s6_addr, CNE_FIB6_MAXDEPTH, idx)) {
            fib_info_free(fi, idx);
            CNE_ERR("ND6 add failed for %s\n",
                    inet_ntop6(ipaddr, sizeof(ipaddr), &entry->nbr_addr6, &mask) ?: "Invalid IP6");
            cnet_nd6_free(entry);
            return NULL;
        }
    }
    return entry;
}

struct nd6_cache_entry *
cnet_nd6_update(struct in6_addr *addr, struct ether_addr *mac, ND_STATE state, bool *routerFlag)
{
    struct nd6_cache_entry *entry = NULL;
    fib_info_t *fi                = this_cnet->nd6_finfo;
    struct in6_addr mask;
    int ret;

    __size_to_mask6(128, &mask);        // CNE_FIB6_MAXDEPTH ?

    ret = fib6_info_lookup(fi, &addr->s6_addr, (void **)&entry, 1);
    if (unlikely(ret > 0 && ret <= ND6_FIB_MAX_ENTRIES)) {
        /* Found the entry just update the MAC address/other info and return */
        if (mac)
            ether_addr_copy(mac, &entry->ll_addr);

        entry->reach_state = state;
        if (routerFlag)
            entry->is_router = *routerFlag;
        return entry;
    }

    return entry;
}

struct nd6_cache_entry *
cnet_nd6_entry_lookup(struct in6_addr *addr)
{
    fib_info_t *fi = this_cnet->nd6_finfo;
    uint64_t idx;

    if (addr && fib6_info_lookup_index(fi, &addr->s6_addr, &idx, 1) > 0) {
        struct nd6_cache_entry *entry = fib_info_object_get(fi, idx);

        return entry;
    }

    return NULL;
}

int
cnet_nd6_delete(struct in6_addr *addr)
{
    fib_info_t *fi = this_cnet->nd6_finfo;
    uint64_t idx;

    if (addr && fib6_info_lookup_index(fi, &addr->s6_addr, &idx, 1) > 0) {
        struct nd6_cache_entry *entry = fib_info_object_get(fi, idx);

        if (entry) {
            if (cne_fib6_delete(fi->fib6, entry->nbr_addr6.s6_addr, 128) < 0)
                CNE_ERR_RET("Unable to delete ARP entry\n");

            if (fib_info_free(fi, (uint32_t)idx) != entry)
                CNE_WARN("Freed entry does not match\n");

            cnet_nd6_free(entry);
            return 0;
        }
    }

    return -1;
}

static int
_nd6_show(struct nd6_cache_entry *entry, void *arg __cne_unused)
{
    struct netif *netif;
    char buf[64];
    struct in6_addr addr;
    char ip[IP6_ADDR_STRLEN] = {0};

    inet6_addr_ntoh(&addr, &entry->nbr_addr6);
    cne_printf("  [orange]%-15s[] ", inet_ntop6(ip, sizeof(ip), &addr, NULL) ?: "Invalid IP");
    ether_format_addr(buf, sizeof(buf), &entry->ll_addr);
    cne_printf("[yellow]%-17s[] ", buf);

    if (entry->netif_idx < 0xFF) {
        netif = vec_at_index(this_cnet->netifs, entry->netif_idx);
        cne_printf("[magenta]%-10s [green]%3d [orange]%-16s[]\n", nd6_get_state(entry),
                   entry->netif_idx, netif->ifname);
    } else
        cne_printf("[magenta]%-10s [green]%3d [orange]%-16s[]\n", nd6_get_state(entry),
                   entry->netif_idx, "Unk");

    return 0;
}

int
cnet_nd6_show(void)
{
    cne_printf("[magenta]NDP Table for CNET on lcore [orange]%d[]\n", cne_lcore_id());
    cne_printf("  [magenta]%-15s %-17s %-4s %3s %-16s[]\n", "Neighbor's IP6 Address", "MAC Address",
               "Reachability State", " IF", "Name");

    return fib_info_foreach(this_cnet->nd6_finfo, (fib_func_t)_nd6_show, NULL);
}

int
cnet_nd6_create(struct cnet *cnet, uint32_t num_entries, uint32_t num_tbl8s)
{
    struct mempool_cfg cfg   = {0};
    struct cne_fib_conf fcfg = {0};
    fib_info_t *fi           = NULL;
    struct cne_fib6 *fib     = NULL;

    if (!cnet)
        return -1;

    if (num_entries == 0 || (num_entries > ND6_FIB_MAX_ENTRIES))
        num_entries = ND6_FIB_DEFAULT_ENTRIES;
    if (num_tbl8s == 0)
        num_tbl8s = ND6_FIB_DEFAULT_NUM_TBL8S;
    num_entries    = cne_align32pow2(num_entries);
    cnet->num_arps = num_entries;

    fcfg.type = CNE_FIB_DIR24_8;
    fcfg.default_nh =
        (uint64_t)((CNE_NODE_IP6_INPUT_NEXT_PKT_DROP << ND6_NEXT_INDEX_SHIFT) | (num_entries + 1));
    fcfg.max_routes    = num_entries;
    fcfg.trie.nh_sz    = CNE_FIB_TRIE_4B;
    fcfg.trie.num_tbl8 = num_tbl8s;

    fib = cne_fib6_create("nd6-fib", &fcfg);
    if (fib == NULL)
        CNE_ERR_GOTO(err, "Unable to create FIB6\n");

    fi = fib6_info_create(fib, num_entries, ND6_NEXT_INDEX_SHIFT);
    if (!fi) {
        cne_fib6_free(fib);
        CNE_ERR_GOTO(err, "Unable to allocate ND6-FIB\n");
    }

    cnet->nd6_finfo = fi;

    cfg.objcnt    = num_entries;
    cfg.objsz     = sizeof(struct nd6_cache_entry);
    cfg.cache_sz  = 0;
    cnet->nd6_obj = mempool_create(&cfg);
    if (cnet->nd6_obj == NULL)
        CNE_ERR_GOTO(err, "ND6 object allocation failed\n");

    return 0;
err:
    cnet_nd6_destroy(cnet);
    return -1;
}

int
cnet_nd6_destroy(struct cnet *cnet)
{
    if (cnet) {
        fib_info_destroy(cnet->nd6_finfo);
        if (cnet->nd6_obj)
            mempool_destroy(cnet->nd6_obj);

        cnet->nd6_finfo = NULL;
        cnet->nd6_obj   = NULL;
    }

    return 0;
}
