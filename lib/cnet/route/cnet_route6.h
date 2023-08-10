/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __CNET_ROUTE6_H
#define __CNET_ROUTE6_H

/**
 * @file
 * CNET Route routines and constants for IPv6.
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

#define RT6_NEXT_INDEX_SHIFT 24UL /* use the upper 8 bits for next index value */

/* Routing Table entry for Internet protocol addresses */
struct rt6_entry {
    struct in6_addr nexthop; /**< Next hop address */
    struct in6_addr netmask; /**< Netmask value */
    struct in6_addr gateway; /**< Gateway address */
    struct in6_addr subnet;  /**< Pre-masked address */
    uint32_t flags;          /**< Routing flags */
    uint16_t netif_idx;      /**< Netif index value */
    uint16_t timo;           /**< Timeout value */
    uint16_t metric;         /**< Metric value */
} __cne_cache_aligned;

/**
 * @brief Create a IPv6 route instance.
 *
 * @param cnet
 *   The cnet pointer to use for creating the routing structure.
 * @param num_rules
 *   The total number of rules or routes to support. If zero use default RT6_DEFAULT_NUM_RULES
 * @param num_tbl8s
 *   Number of TBL8 entries in the FIB table to use. If zero use default RT6_DEFAULT_NUM_TBL8S
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route6_create(struct cnet *cnet, uint32_t num_rules, uint32_t num_tbl8s);

/**
 * @brief Destroy the IPv6 routing instance
 *
 * @param cnet
 *   The cnet pointer to use for creating the routing structure.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route6_destroy(struct cnet *cnet);

/**
 * @brief Allocate a IPv6 route entry.
 *
 * @return
 *   NULL on error or pointer to struct rt6_entry.
 */
CNDP_API struct rt6_entry *cnet_route6_alloc(void);

/**
 * @brief Allocate a number of IPv6 route entries.
 *
 * @param rt
 *   The pointer array to use for creating the number of entries.
 * @param n
 *   The number of entries to allocate.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route6_alloc_bulk(struct rt6_entry **rt, int n);

/**
 * @brief Free a IPv6 route entry.
 *
 * @param entry
 *   The route entry to free.
 * @return
 *   N/A
 */
CNDP_API void cnet_route6_free(struct rt6_entry *entry);

/**
 * @brief Free a bulk of IPv6 route entries.
 *
 * @param entry
 *   The array of pointer to free route entries
 * @param n
 *   The number or route entries to free.
 * @return
 *   N/A
 */
CNDP_API void cnet_route6_free_bulk(struct rt6_entry **entry, int n);

/**
 * @brief Enable a IPv6 route entry timer to age entries.
 *
 * @return
 *   N/A
 */
CNDP_API void cne_route6_timer(void);

/**
 * @brief Routine to call when a route notification is received.
 *
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cne_route6_notify(void);

/**
 * @brief Insert IPv6 route into the routing table.
 *
 * @param netif_idx
 *   The netif index to insert into the routing table.
 * @param dst
 *   The destination IPv6 address to insert into the routing table.
 * @param netmask
 *   The destination IPv6 netmask.
 * @param gate
 *   The destination IPv6 gateway address.
 * @param metric
 *   The destination IPv6 metric.
 * @param timo
 *   The destination IPv6 route timeout.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route6_insert(int netif_idx, struct in6_addr *dst, struct in6_addr *netmask,
                                struct in6_addr *gate, uint8_t metric, uint16_t timo);

/**
 * @brief Delete a IPv6 route entry
 *
 * @param ipaddr
 *   The IPv6 destination address to delete.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route6_delete(struct in6_addr *ipaddr);

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
CNDP_API int cnet_route6_get_bulk(uint64_t *nh, struct rt6_entry **rt, int n);

/**
 * @brief Return a single route entry given the nexthop index value
 *
 * @param nh
 *   The nexthop index value to be used to return the route entry.
 * @return
 *   NULL on error or pointer to found route entry
 */
CNDP_API struct rt6_entry *cnet_route6_get(uint64_t nh);

/**
 * @brief Display the IPv6 route entries.
 *
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_route6_show(void);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_ROUTE6_H */
