/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __INCLUDE_ND6_H__
#define __INCLUDE_ND6_H__

#include <cne_common.h>
#include <netinet/in.h>        // for in6_addr
#include <sys/time.h>
#include <pktmbuf.h>
#include <pktdev_api.h>
#include "icmp6.h"
#include "cne_graph_worker.h"        // for cne_node, cne_node_enqueue_x1
#include "cnet_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ND_CACHE_TBL_SZ 100

/* From NDP RFC 4861:Node constants */
#define MAX_MULTICAST_SOLICIT      3
#define MAX_UNICAST_SOLICIT        3
#define MAX_ANYCAST_DELAY_TIME     1        // 1 second
#define MAX_NEIGHBOR_ADVERTISEMENT 3
#define REACHABLE_TIME             30000        // 30k milliseconds
#define RETRANS_TIMER              1000         // 1k milliseconds
#define DELAY_FIRST_PROBE_TIME     5            // 5 seconds
#define MIN_RANDOM_FACTOR          0.5
#define MAX_RANDOM_FACTOR          1.5

#define ND6_NS_MIN_PKT_LEN 24
#define ND6_NA_MIN_PKT_LEN 24

typedef enum { ND_INCOMPLETE, ND_REACHABLE, ND_STALE, ND_DELAY, ND_PROBE } ND_STATE;

/* Neighbor Cache : A set of entries about individual neighbors to
 * which traffic has been sent recently (Ref: RFC 4861).
 */
struct nd6_cache_entry {
    union {
        struct in_addr nbr_addr;   /**< Neighbor’s on-link unicast IPv4 address */
        struct in6_addr nbr_addr6; /**< Neighbor’s on-link unicast IPv6 address */
    };
    uint16_t netif_idx;                 /**< Netif index value of sending/source interface from
                                           this host/router */
    struct ether_addr ll_addr;          /**< link-layer address */
    bool is_router;                     /**< whether the neighbor is a router or a host */
    pktmbuf_t *ar_packets_queue;        /**< queued packets waiting for address
                                           resolution to complete   */
    ND_STATE reach_state;               /**< Reachability state */
    int num_unans_probes;               /**< Number of unanswered probes */
    struct timeval next_unreachd_event; /**< The time the next Neighbor Unreachability
                                   Detection event is scheduled to take place */
};

/* Destination Cache: A set of entries about destinations to which
 * traffic has been sent recently (Ref: RFC 4861).
 * This cache is updated with information learned from Redirect messages.
 */

struct dest_cache {
    union {
        struct in_addr dst_addr;   /**< Destination’s on-link / off-link unicast IPv4 address */
        struct in6_addr dst_addr6; /**< Destination’s on-link / off-link unicast IPv6 address */
    };
    /* PMTU */
    /* round-trip timer */

    struct nd6_cache_entry *nxtHopNbr; /**< Next Hop Neighbor */
};

struct nd_prefix_list {

    u_int32_t invalid_time; /** <invalidation timer value */
};

/* Default Router List:
 */

struct nd_default_router_list {

    struct nd6_cache_entry *router;
    u_int32_t invalid_time; /** <invalidation timer value */
};

/**
 * Send NDP Neighbor Solution Message via ICMP6
 *
 * @param graph
 *   The pointer to CNET graph structure.
 * @param node
 *   The pointer to CNET node.
 * @param src_addr
 *   The pointer to src IPv6 address.
 * @param target
 *   The pointer to target IPv6 address.
 * @param verify_reach
 *   Whether verify the reachability of a neighbor.
 */
CNDP_API void nd6_send_ns(struct cne_graph *graph, struct cne_node *node, struct in6_addr *src_addr,
                          struct in6_addr *target, bool verify_reach);

/**
 * Receive incoming NDP Requests via ICMP6
 *
 * @param graph
 *   The pointer to CNET graph structure.
 * @param node
 *   The pointer to CNET node.
 * @param iip
 *   The pointer to ICMP6 & IPv6 header.
 * @return
 *   The next node
 */
CNDP_API uint16_t nd6_recv_requests(struct cne_graph *graph, struct cne_node *node, icmp6ip_t *iip);

/**
 * Get NDP state in string
 *
 * @param entry
 *   The pointer to nd6 cache entry
 * @return
 *   NDP state in string
 */
CNDP_API const char *nd6_get_state(struct nd6_cache_entry *entry);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_ND6_H__ */
