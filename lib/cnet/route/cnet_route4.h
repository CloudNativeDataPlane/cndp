/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2025 Intel Corporation
 */

#ifndef __CNET_ROUTE4_H
#define __CNET_ROUTE4_H

/**
 * @file
 * CNET Route routines and constants for IPv4.
 */

#include <net/ethernet.h>        // for ether_addr
#include <stdint.h>              // for uint16_t, uint8_t, uint32_t
#include <sys/queue.h>           // for TAILQ_ENTRY

#include "cne_common.h"        // for __cne_cache_aligned
#include "cnet_const.h"        // for match_t, rt_attach_t, vfunc_t
#include "cne_inet.h"          // for in_caddr
#include "cnet_stk.h"          // for this_stk
#include "cnet_route.h"

struct netif;
#ifdef __cplusplus
extern "C" {
#endif

#define RT4_NEXT_INDEX_SHIFT 24UL /* use the upper 8 bits for next index value */

/* Routing Table entry for Internet protocol addresses */
struct rt4_entry {
    struct in_addr nexthop; /**< Next hop address */
    struct in_addr netmask; /**< Netmask value */
    struct in_addr gateway; /**< Gateway address */
    struct in_addr subnet;  /**< Pre-masked address */
    uint32_t flags;         /**< Routing flags */
    uint16_t netif_idx;     /**< Netif index value */
    uint16_t timo;          /**< Timeout value */
    uint16_t metric;        /**< Metric value */
} __cne_cache_aligned;

/**
 * @brief Create a IPv4 route instance.
 *
 * @param cnet
 *   The cnet pointer to use for creating the routing structure.
 * @param num_rules
 *   The total number of rules or routes to support. If zero use default RT4_DEFAULT_NUM_RULES
 * @param num_tbl8s
 *   Number of TBL8 entries in the FIB table to use. If zero use default RT4_DEFAULT_NUM_TBL8S
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route4_create(struct cnet *cnet, uint32_t num_rules, uint32_t num_tbl8s);

/**
 * @brief Destroy the IPv4 routing instance
 *
 * @param cnet
 *   The cnet pointer to use for creating the routing structure.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route4_destroy(struct cnet *cnet);

/**
 * @brief Allocate a IPv4 route entry.
 *
 * @return
 *   NULL on error or pointer to struct rt4_entry.
 */
CNDP_API struct rt4_entry *cnet_route4_alloc(void);

/**
 * @brief Allocate a number of IPv4 route entries.
 *
 * @param rt
 *   The pointer array to use for creating the number of entries.
 * @param n
 *   The number of entries to allocate.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route4_alloc_bulk(struct rt4_entry **rt, int n);

/**
 * @brief Free a IPv4 route entry.
 *
 * @param entry
 *   The route entry to free.
 * @return
 *   N/A
 */
CNDP_API void cnet_route4_free(struct rt4_entry *entry);

/**
 * @brief Free a bulk of IPv4 route entries.
 *
 * @param entry
 *   The array of pointer to free route entries
 * @param n
 *   The number or route entries to free.
 * @return
 *   N/A
 */
CNDP_API void cnet_route4_free_bulk(struct rt4_entry **entry, int n);

/**
 * @brief Enable a IPv4 route entry timer to age entries.
 *
 * @return
 *   N/A
 */
CNDP_API void cne_route4_timer(void);

/**
 * @brief Routine to call when a route notification is received.
 *
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cne_route4_notify(void);

/**
 * @brief Insert IPv4 route into the routing table.
 *
 * @param netif_idx
 *   The netif index to insert into the routing table.
 * @param dst
 *   The destination IPv4 address to insert into the routing table.
 * @param netmask
 *   The destination IPv4 netmask.
 * @param gate
 *   The destination IPv4 gateway address.
 * @param metric
 *   The destination IPv4 metric.
 * @param timo
 *   The destination IPv4 route timeout.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route4_insert(int netif_idx, struct in_addr *dst, struct in_addr *netmask,
                                struct in_addr *gate, uint8_t metric, uint16_t timo);

/**
 * @brief Delete a IPv4 route entry
 *
 * @param ipaddr
 *   The IPv4 destination address to delete.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route4_delete(struct in_addr *ipaddr);

/**
 * @brief Get a bulk of route entries using the nexthop index values.
 *
 * @param nh
 *   The array of nexthop index values to find the route entries
 * @param rt
 *   The array to return the route entry pointers.
 * @param n
 *   The number of nexthop and route entries to return.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route4_get_bulk(uint64_t *nh, struct rt4_entry **rt, int n);

/**
 * @brief Return a single route entry given the nexthop index value
 *
 * @param nh
 *   The nexthop index value to be used to return the route entry.
 * @return
 *   NULL on error or pointer to found route entry
 */
CNDP_API struct rt4_entry *cnet_route4_get(uint64_t nh);

/**
 * @brief Display the IPvr route entries.
 *
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route4_show(void);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_ROUTE4_H */
