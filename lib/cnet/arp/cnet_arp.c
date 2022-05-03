/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2022 Intel Corporation
 */

#include <mempool.h>         // for mempool_destroy, mempool_get, mem...
#include <cne_hash.h>        // for cne_hash_add_key_data, cne_hash_d...
#include <endian.h>          // for htobe16
#ifdef CNE_MACHINE_CPUFLAG_SSE4_2
#include <cne_hash_crc.h>        // for cne_hash_crc

#define DEFAULT_HASH_FUNC cne_hash_crc
#else
#include <cne_jhash.h>

#define DEFAULT_HASH_FUNC cne_jhash
#endif

#include <cnet.h>              // for cnet_add_instance
#include <cnet_stk.h>          // for stk_entry, per_thread_stk, this_stk
#include <cne_inet.h>          // for inet_ntop4, inet_addr_copy
#include <cnet_drv.h>          // for drv_entry
#include <cnet_netif.h>        // for netif, net_addr, cnet_netif_match...
#include <cnet_eth.h>          // for IPV4_ADDR_SIZE
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>             // for AF_INET
#include <cnet_route.h>            // for
#include <cnet_ip_common.h>        // for ETH_HW_TYPE
#include <cnet_arp.h>

#include <net/cne_ether.h>                // for ether_addr_copy, ether_format_addr
#include <net/cne_arp.h>                  // for cne_arp_hdr, cne_arp_ipv4, CNE_AR...
#include "cne_branch_prediction.h"        // for unlikely
#include "cne_build_config.h"             // for CNE_MACHINE_CPUFLAG_SSE4_2
#include "cne_log.h"                      // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_W...
#include "cne_mmap.h"                     // for MMAP_HUGEPAGE_DEFAULT
#include "cne_vec.h"                      // for vec_len
#include "cnet_const.h"                   // for iofunc_t, ARP_IO
#include "cnet_reg.h"
#include "cnet_ipv4.h"        // for ipv4_entry
#include <cne_fib.h>
#include <cnet_fib_info.h>
#include <ip4_input_priv.h>

struct arp_entry *
cnet_arp_alloc(void)
{
    struct cnet *cnet       = this_cnet;
    struct arp_entry *entry = NULL;

    if (mempool_get(cnet->arp_obj, (void **)&entry) < 0)
        return NULL;

    return entry;
}

/** Free a ARP entry to the objpool */
void
cnet_arp_free(struct arp_entry *entry)
{
    struct cnet *cnet = this_cnet;

    if (entry)
        mempool_put(cnet->arp_obj, entry);
}

struct arp_entry *
cnet_arp_add(int netif_idx, struct in_addr *addr, struct ether_addr *mac, int perm)
{
    struct arp_entry *entry = NULL;
    fib_info_t *fi          = this_cnet->arp_finfo;
    struct in_addr mask;
    int ret;
    uint64_t idx;

    mask.s_addr = 0xFFFFFFFF;

    ret = fib_info_lookup(fi, &addr->s_addr, (void **)&entry, 1);
    if (unlikely(ret > 0 && ret <= ARP_FIB_MAX_ENTRIES)) {
        /* Found the entry just update the MAC address and return */
        ether_addr_copy(mac, &entry->ha);
        return entry;
    }

    entry = cnet_arp_alloc();
    if (entry) {
        char ipaddr[IP4_ADDR_STRLEN] = {0};

        inet_addr_copy(&entry->pa, addr);

        entry->netif_idx = netif_idx;
        entry->flags     = (perm) ? ARP_STATIC_FLAG : 0;
        ether_addr_copy(mac, &entry->ha);

        ret = fib_info_alloc(fi, entry);
        if (ret < 0)
            CNE_WARN("FIB allocate failed for %s\n",
                     inet_ntop4(ipaddr, sizeof(ipaddr), &entry->pa, &mask) ?: "Invalid IP");

        idx = ret;
        if (cne_fib_add(fi->fib, addr->s_addr, 32, idx)) {
            fib_info_free(fi, idx);
            CNE_ERR("ARP add failed for %s\n",
                    inet_ntop4(ipaddr, sizeof(ipaddr), &entry->pa, &mask) ?: "Invalid IP");
            cnet_arp_free(entry);
            return NULL;
        }
    }
    return entry;
}

int
cnet_arp_delete(struct in_addr *addr)
{
    fib_info_t *fi = this_cnet->arp_finfo;
    uint64_t idx;

    if (addr && fib_info_lookup_index(fi, &addr->s_addr, &idx, 1) > 0) {
        struct arp_entry *entry = fib_info_object_get(fi, idx);

        if (entry) {
            if (cne_fib_delete(fi->fib, entry->pa.s_addr, 32) < 0)
                CNE_ERR_RET("Unable to delete ARP entry\n");

            if (fib_info_free(fi, (uint32_t)idx) != entry)
                CNE_WARN("Freed entry does not match\n");

            cnet_arp_free(entry);
            return 0;
        }
    }

    return -1;
}

static int
_arp_show(struct arp_entry *entry, void *arg __cne_unused)
{
    struct netif *netif;
    char buf[64];
    struct in_addr addr;
    char ip[IP4_ADDR_STRLEN] = {0};

    addr.s_addr = be32toh(entry->pa.s_addr);
    cne_printf("  [orange]%-15s[] ", inet_ntop4(ip, sizeof(ip), &addr, NULL) ?: "Invalid IP");
    ether_format_addr(buf, sizeof(buf), &entry->ha);
    cne_printf("[yellow]%-17s[] ", buf);

    if (entry->netif_idx < 0xFF) {
        netif = vec_at_index(this_cnet->netifs, entry->netif_idx);
        cne_printf("[magenta]%04x [green]%3d [orange]%-16s [red]%s[]\n", entry->flags,
                   entry->netif_idx, netif->ifname,
                   (entry->flags & ARP_STATIC_FLAG) ? "Static" : "");
    } else
        cne_printf("[magenta]%04x [green]%3d [orange]%-16s [green]%s[]\n", entry->flags,
                   entry->netif_idx, "Unk", (entry->flags & ARP_STATIC_FLAG) ? "Static" : "");

    return 0;
}

int
cnet_arp_show(void)
{
    cne_printf("[magenta]ARP Table for CNET on lcore [orange]%d[]\n", cne_lcore_id());
    cne_printf("  [magenta]%-15s %-17s %-4s %3s %-16s[]\n", "IP Address", "MAC Address", "Flgs",
               " IF", "Name");

    return fib_info_foreach(this_cnet->arp_finfo, (fib_func_t)_arp_show, NULL);
}

int
cnet_arp_create(struct cnet *cnet, uint32_t num_entries, uint32_t num_tbl8s)
{
    struct mempool_cfg cfg   = {0};
    struct cne_fib_conf fcfg = {0};
    fib_info_t *fi           = NULL;
    struct cne_fib *fib      = NULL;

    if (!cnet)
        return -1;

    if (num_entries == 0 || (num_entries > ARP_FIB_MAX_ENTRIES))
        num_entries = ARP_FIB_DEFAULT_ENTRIES;
    if (num_tbl8s == 0)
        num_tbl8s = ARP_FIB_DEFAULT_NUM_TBL8S;
    num_entries    = cne_align32pow2(num_entries);
    cnet->num_arps = num_entries;

    fcfg.type = CNE_FIB_DIR24_8;
    fcfg.default_nh =
        (uint64_t)((CNE_NODE_IP4_INPUT_NEXT_PKT_DROP << ARP_NEXT_INDEX_SHIFT) | (num_entries + 1));
    fcfg.max_routes       = num_entries;
    fcfg.dir24_8.nh_sz    = CNE_FIB_DIR24_8_4B;
    fcfg.dir24_8.num_tbl8 = num_tbl8s;

    fib = cne_fib_create("arp-fib", &fcfg);
    if (fib == NULL)
        CNE_ERR_GOTO(err, "Unable to create FIB\n");

    fi = fib_info_create(fib, num_entries, ARP_NEXT_INDEX_SHIFT);
    if (!fi) {
        cne_fib_free(fib);
        CNE_ERR_GOTO(err, "Unable to allocate ARP-FIB\n");
    }

    cnet->arp_finfo = fi;

    cfg.objcnt    = num_entries;
    cfg.objsz     = sizeof(struct arp_entry);
    cfg.cache_sz  = 0;
    cnet->arp_obj = mempool_create(&cfg);
    if (cnet->arp_obj == NULL)
        CNE_ERR_GOTO(err, "ARP object allocation failed\n");

    return 0;
err:
    cnet_arp_destroy(cnet);
    return -1;
}

int
cnet_arp_destroy(struct cnet *cnet)
{
    if (cnet) {
        fib_info_destroy(cnet->arp_finfo);
        if (cnet->arp_obj)
            mempool_destroy(cnet->arp_obj);

        cnet->arp_finfo = NULL;
        cnet->arp_obj   = NULL;
    }

    return 0;
}
