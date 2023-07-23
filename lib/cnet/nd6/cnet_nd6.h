/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __CNET_ND6_H
#define __CNET_ND6_H

/**
 * @file
 * CNET ND6 routines.
 */

#include <cnet/cnet.h>
#include <net/ethernet.h>        // for ether_addr
#include <stdint.h>              // for uint8_t, uint16_t

#include "nd6.h"
#include <cne_inet6.h>        // for inet_ntop6, inet_addr_copy
#include "pktmbuf.h"          // for pktmbuf_t

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ND6_NEXT_INDEX_SHIFT      = 24,
    ND6_FIB_MAX_ENTRIES       = (1UL << ND6_NEXT_INDEX_SHIFT),
    ND6_FIB_DEFAULT_ENTRIES   = 1024,
    ND6_FIB_DEFAULT_NUM_TBL8S = (1 << 8),
};

/* nd6_cache_entry.flags */
enum {
    ND6_STATIC_FLAG     = 0x01, /**< This entry does not timeout */
    ND6_SEND_GRATUITOUS = 0x02  /**< Send a gratuitous ND6 packet */
};

/**
 * Allocate an ND6 entry
 *
 * @return
 *   NULL on error, otherwise pointer to ND6 entry.
 */
CNDP_API struct nd6_cache_entry *cnet_nd6_alloc(void);

/**
 * Free an ND6 entry
 *
 * @param entry
 *   The ND6 entry to free.
 */
CNDP_API void cnet_nd6_free(struct nd6_cache_entry *entry);

/**
 * Create the ND6 table and structure to hold ND6 information.
 *
 * @param _cnet
 *   The pointer to the current CNET structure.
 * @param num_entries
 *   The number of entries to allocate in ND6 table, if zero use
 * ND6_FIB_DEFAULT_ENTRIES.
 * @param num_tbl8s
 *   The number of table entries to allocate in ND6 table, if zero use
 * ND6_FIB_DEFAULT_NUM_TBLS8.
 * @return
 *   0 on success or -1 on error.
 */
CNDP_API int cnet_nd6_create(struct cnet *_cnet, uint32_t num_entries, uint32_t num_tbl8s);

/**
 * Destroy the ND6 table and structure to hold ND6 information.
 *
 * @param cnet
 *   The pointer to the current CNET structure.
 * @return
 *   0 on success or -1 on error.
 */
CNDP_API int cnet_nd6_destroy(struct cnet *cnet);

/**
 * Add an ND6 entry to the ND6 table. If perm is set then create a static entry.
 *
 * @param netif_idx
 *   The netif structure index to assign the ND6 entry.
 * @param addr
 *   The IP address to add to the ND6 table
 * @param mac
 *   The MAC address to add to the ND6 table
 * @param perm
 *   If non-zero then add the entry to the ND6 table as a static entry.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API struct nd6_cache_entry *cnet_nd6_add(int netif_idx, struct in6_addr *addr,
                                              struct ether_addr *mac, ND_STATE state);

CNDP_API struct nd6_cache_entry *cnet_nd6_update(struct in6_addr *addr, struct ether_addr *mac,
                                                 ND_STATE state, bool *routerFlag);

CNDP_API struct nd6_cache_entry *cnet_nd6_entry_lookup(struct in6_addr *addr);

/**
 * Delete an ND6 entry
 *
 * @param addr
 *   The IP address to delete
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cnet_nd6_delete(struct in6_addr *addr);

/**
 * Show the stack entry ND6 table, each stack has an ND6 table
 *
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cnet_nd6_show(void);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_ND6_H */
