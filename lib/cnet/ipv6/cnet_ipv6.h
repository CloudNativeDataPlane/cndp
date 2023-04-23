/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __CNET_IPv6_H
#define __CNET_IPv6_H

/**
 * @file
 * CNET IPv6 routines.
 */

#include <net/cne_ip.h>        // for cne_ipv6_hdr
#include <net/cne_inet6.h>
#include <cne_inet.h>          // for _in_addr
#include <endian.h>            // for htobe16
#include <netinet/in.h>        // for IN_CLASSA, IN_CLASSB, IN_CLASSC, IN_CLASSD
#include <stdint.h>            // for uint16_t, uint8_t, uint64_t, uint32_t, int...
#include <stdio.h>             // for NULL

#include "cne_common.h"        // for __cne_packed, __cne_cache_aligned
#include "cnet_const.h"        // for iofunc_t

struct netif;
struct stk_s;

#ifdef __cplusplus
extern "C" {
#endif

struct rt6_entry;
struct ndp_entry;
struct cne_lpm;
struct ipfwd_info;

/* IPv6 Flow Entry */
struct ip6_flowentry {
    bool autoflowlabel_set; /* ipv6 socket option set */
    bool autoflowlabel;
    uint32_t flowlabel;
};

struct ipv6_stats {
    uint64_t ip6_ver_error;
    uint64_t ip6_hl_error;
    uint64_t vec6_pool_empty;
    uint64_t ip6_invalid_src_addr;
    uint64_t route6_lookup_failed;
    uint64_t ip6_forward_failed;
    uint64_t ip6_reassemble_failed;
    uint64_t ip6_proto_invalid;
    uint64_t ip6_mbuf_too_small;
    uint64_t ip6_option_invalid;
    uint64_t ip6_mforward_pkts;
    uint64_t ip6_mforward_failed;
    uint64_t ip6_mlookup_failed;
    uint64_t ip6_forwarding_disabled;
};

struct ipv6_entry {
    uint8_t ip6_forwarding;      /**< IP forwarding is enabled */
    uint8_t do_multicast;        /**< Allow multicast support */
    uint16_t reassem_ttl;        /**< reassemble TTL value */
    struct ipfwd_info *fwd_info; /**< Forwarding information */
    struct ipv6_stats stats;     /**< simple stats for protocol */
    iofunc_t fastpath;           /**< Fastpath function pointer */
    iofunc_t dhcp6;              /**< DHCP6 function pointer */
    iofunc_t setup;              /**< IP Setup routine */
} __cne_cache_aligned;

/* Internet protocol header structure */
/* Basic IPv6 packet header
 *
 *                        IPv6 Header Format
 *
 *    0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Version| Traffic Class |           Flow Label                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Payload Length        |  Next Header  |   Hop Limit   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                         Source Address                        +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +                      Destination Address                      +
 *  |                                                               |
 *  +                                                               +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/* IPv6 overlay header for the pseudo header */
struct ipv6_overlay {
    uint32_t node[2];
    struct in6_addr src; /**< Source ipv6 address */
    struct in6_addr dst; /**< Destination ipv6 address */
    uint32_t len; /**< Length of the upper-layer header and data (e.g. TCP header plus TCP data). */
    uint32_t pad0_nxtHdr; /**< Padding 0 and Next Header (i.e. Protocol type) */
} __cne_packed;

/**
 * @brief Dump the IPv6 statistics
 *
 * @param stk
 *   The stack instance pointer to dump from.
 * @return
 *   -1 on error, 0 on success
 */
CNDP_API int cnet_ipv6_stats_dump(struct stk_s *stk);

/**
 * @brief Dump information about IPv6 header
 *
 * @param msg
 *   User supplied message
 * @param ip
 *   The IPv6 header pointer
 * @return
 *   N/A
 */
CNDP_API void cnet_ipv6_dump(const char *msg, struct cne_ipv6_hdr *ip);

inline cne_be32_t
ip6_get_flowlabel(struct cne_ipv6_hdr *ip6h)
{
    return (ip6h->vtc_flow & IPV6_FLOWLABEL_MASK);
}

inline cne_be32_t
ip6_get_tclass(struct cne_ipv6_hdr *ip6h)
{
    return ((ip6h->vtc_flow & IPV6_TCLASS_MASK) >> IPV6_TCLASS_SHIFT);
}

inline cne_be32_t
ip6_get_version(struct cne_ipv6_hdr *ip6h)
{
    return ((ip6h->vtc_flow & IPV6_VERSION_MASK) >> IPV6_VERSION_SHIFT);
}

#if CNET_IP6_DUMP_ENABLED
#define IP6_DUMP(ip)                                                                  \
    do {                                                                              \
        cne_printf("[cyan]([orange]%s[cyan]:[orange]%d[cyan]) ", __func__, __LINE__); \
        cnet_ipv6_dump(NULL, ip);                                                     \
    } while (0)
#else
#define IP6_DUMP(ip) \
    do {             \
    } while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CNET_IPv6_H */
