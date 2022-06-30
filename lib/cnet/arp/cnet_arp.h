/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_ARP_H
#define __CNET_ARP_H

/**
 * @file
 * CNET ARP routines.
 */

#include <cnet/cnet.h>
#include <net/cne_arp.h>
#include <net/cne_ip.h>
#include <net/ethernet.h>        // for ether_addr
#include <stdint.h>              // for uint8_t, uint16_t

#include "cne_inet.h"        // for _in_addr
#include "pktmbuf.h"         // for pktmbuf_t

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ARP_NEXT_INDEX_SHIFT      = 24,
    ARP_FIB_MAX_ENTRIES       = (1UL << ARP_NEXT_INDEX_SHIFT),
    ARP_FIB_DEFAULT_ENTRIES   = 1024,
    ARP_FIB_DEFAULT_NUM_TBL8S = (1 << 8),
};

/* arp_entry.flags */
enum {
    ARP_STATIC_FLAG     = 0x01, /**< This entry does not timeout */
    ARP_SEND_GRATUITOUS = 0x02  /**< Send a gratuitous ARP packet */
};

/* ARP table format */
struct arp_entry {
    uint16_t flags;       /**< ARP flags */
    uint16_t netif_idx;   /**< Netif index value */
    struct in_addr pa;    /**< protocol address */
    struct ether_addr ha; /**< hardware address */
};

/**
 * Allocate an ARP entry
 *
 * @return
 *   NULL on error, otherwise pointer to ARP entry.
 */
CNDP_API struct arp_entry *cnet_arp_alloc(void);

/**
 * Free an ARP entry
 *
 * @param entry
 *   The ARP entry to free.
 */
CNDP_API void cnet_arp_free(struct arp_entry *entry);

/**
 * Create the ARP table and structure to hold ARP information.
 *
 * @param _cnet
 *   The pointer to the current CNET structure.
 * @param num_entries
 *   The number of entries to allocate in ARP table, if zero use ARP_FIB_DEFAULT_ENTRIES.
 * @param num_tbl8s
 *   The number of table entries to allocate in ARP table, if zero use ARP_FIB_DEFAULT_NUM_TBLS8.
 * @return
 *   0 on success or -1 on error.
 */
CNDP_API int cnet_arp_create(struct cnet *_cnet, uint32_t num_entries, uint32_t num_tbl8s);

/**
 * Destroy the ARP table and structure to hold ARP information.
 *
 * @param cnet
 *   The pointer to the current CNET structure.
 * @return
 *   0 on success or -1 on error.
 */
CNDP_API int cnet_arp_destroy(struct cnet *cnet);

/**
 * Add an ARP entry to the ARP table. If perm is set then create a static entry.
 *
 * @param netif_idx
 *   The netif structure index to assign the ARP entry.
 * @param addr
 *   The IP address to add to the ARP table
 * @param mac
 *   The MAC address to add to the ARP table
 * @param perm
 *   If non-zero then add the entry to the ARP table as a static entry.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API struct arp_entry *cnet_arp_add(int netif_idx, struct in_addr *addr, struct ether_addr *mac,
                                        int perm);

/**
 * Delete an ARP entry
 *
 * @param addr
 *   The IP address to delete
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cnet_arp_delete(struct in_addr *addr);

/**
 * Show the stack entry ARP table, each stack has an ARP table
 *
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cnet_arp_show(void);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_ARP_H */
