/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_IPv4_H
#define __CNET_IPv4_H

/**
 * @file
 * CNET IPv4 routines.
 */

#include <net/cne_ip.h>          // for cne_ipv4_hdr
#include <cne_inet.h>            // for _in_addr
#include <cnet_protosw.h>        // for
#include <endian.h>              // for htobe16
#include <netinet/in.h>          // for IN_CLASSA, IN_CLASSB, IN_CLASSC, IN_CLASSD
#include <stdint.h>              // for uint16_t, uint8_t, uint64_t, uint32_t, int...
#include <stdio.h>               // for NULL

#include "cne_common.h"        // for __cne_packed, __cne_cache_aligned
#include "cnet_const.h"        // for iofunc_t

struct netif;
struct stk_s;

#ifdef __cplusplus
extern "C" {
#endif

#define IP_MAX_MTU  ETHER_MAX_MTU
#define TTL_DEFAULT 64 /* Default TTL value */
#define TOS_DEFAULT 0  /* Default TOS value */

#define DEFAULT_IPV4_HDR_SIZE 20
#define IPv4_VER_LEN_VALUE    ((IPv4_VERSION << 4) | (sizeof(struct cne_ipv4_hdr) / 4))

struct rt4_entry;
struct arp_entry;
struct cne_lpm;
struct ipfwd_info;

struct ipv4_stats {
    uint64_t ip_ver_error;
    uint64_t ip_hl_error;
    uint64_t vec_pool_empty;
    uint64_t ip_invalid_src_addr;
    uint64_t ip_checksum_error;
    uint64_t route_lookup_failed;
    uint64_t ip_forward_failed;
    uint64_t ip_reassemble_failed;
    uint64_t ip_proto_invalid;
    uint64_t ip_mbuf_too_small;
    uint64_t ip_option_invalid;
    uint64_t ip_mforward_pkts;
    uint64_t ip_mforward_failed;
    uint64_t ip_mlookup_failed;
    uint64_t ip_forwarding_disabled;
};

struct ipv4_entry {
    uint8_t ip_forwarding;       /**< IP forwarding is enabled */
    uint8_t do_multicast;        /**< Allow multicast support */
    uint16_t reassem_ttl;        /**< reassemble TTL value */
    struct ipfwd_info *fwd_info; /**< Forwarding information */
    struct ipv4_stats stats;     /**< simple stats for protocol */
    iofunc_t fastpath;           /**< Fastpath function pointer */
    iofunc_t dhcp;               /**< DHCP function pointer */
    iofunc_t setup;              /**< IP Setup routine */
} __cne_cache_aligned;

#define IPv4(a, b, c, d) \
    ((uint32_t)(((a)&0xff) << 24) | (((b)&0xff) << 16) | (((c)&0xff) << 8) | ((d)&0xff))

/* Internet protocol header structure */
/* Basic IPv4 packet header
 *
 *                        IPv4 Header Format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Ver   | hlen  |      TOS      |         Total length          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Ident                 |flags|     fragment offset     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    TTL        |    Protocol   |       Header Checksum         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Source Address (32  Bits)                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 Destination Address (32  Bits)                |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                             data                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define _ISFRAG(off) ((off) & (_OFF_MF | _OFF_MASK))
#define _OFF_MASK    0x1fff
#define _OFF_MF      0x2000
#define _OFF_DF      0x4000

/* IP overlay header for the pseudo header */
struct ipv4_overlay {
    uint32_t node[2];
    uint8_t pad0;  /**< overlays ttl */
    uint8_t proto; /**< Protocol type */
    uint16_t len;  /**< Protocol length, overlays cksum */
    uint32_t src;  /**< Source address */
    uint32_t dst;  /**< Destination address */
} __cne_packed;

/* Timestamp Option structure */
struct ipoptions {
    uint8_t type;    /**< Type or opcode value */
    uint8_t len;     /**< Length of option */
    uint8_t ptr;     /**< pointer value */
    uint8_t flags;   /**< flags value */
    uint8_t data[0]; /**< Start of data */
};

#define MAX_TIMESTAMP_SIZE 40
#define MAX_OPTION_SIZE    MAX_TIMESTAMP_SIZE

/* Macro to get the network mask from an IP address in host byte order. */
#define __netmask(_ip)                  \
    (((_ip) == 0UL)     ? 0UL           \
     : IN_CLASSA((_ip)) ? IN_CLASSA_NET \
     : IN_CLASSB((_ip)) ? IN_CLASSB_NET \
     : IN_CLASSC((_ip)) ? IN_CLASSC_NET \
     : IN_CLASSD((_ip)) ? IN_CLASSD_NET \
                        : 0UL)

#define __netbytes(_ip)               \
    ((uint8_t)(((_ip) == 0UL)     ? 0 \
               : IN_CLASSA((_ip)) ? 1 \
               : IN_CLASSB((_ip)) ? 2 \
               : IN_CLASSC((_ip)) ? 3 \
               : IN_CLASSD((_ip)) ? 4 \
                                  : 0))

/*
 * Adjust the checksum to reflect that the TTL had been decremented.
 *
 * Flip the bits on the checksum, decrement the high byte of the checksum,
 * fold in any carry, and then flip the bits back.  Rather than convert
 * the checksum to host byte order and then back to network byte order,
 * just convert the increment to network byte order.  Note: in 1's
 * complement arithmetic, subtracting by x is the same as adding the 1's
 * complement of x.  So, in 16 bit arithmetic, rather than subtracting by
 * (1<<8), we can add by (1<<8)^0xffff.  Since it's all constants, that
 * should be evaluated by the compiler at compile time.
 *
 * Doing the ^0xffff to initially flip the bits keeps the upper bits from
 * also being flipped. Using the ~ operation at the end doesn't matter,
 * because the upper bits get tossed when we assign it to the 16 bit sum
 * field, so let the compiler do whatever is fastest.
 */
static inline void
ipv4_adjust_cksum(struct cne_ipv4_hdr *hdr)
{
    int32_t cksum;

    hdr->time_to_live--;

    /* increment checksum high byte */
    cksum = (int32_t)(hdr->hdr_checksum ^ 0xFFFF) + (int32_t)htobe16(((1 << 8) ^ 0xFFFF));

    /* Fold the carry bit into the checksum */
    hdr->hdr_checksum = ~(cksum + (cksum >> 16));
}

/**
 * @brief Dump the IPv4 statistics
 *
 * @param stk
 *   The stack instance pointer to dump from.
 * @return
 *   -1 on error, 0 on success
 */
CNDP_API int cnet_ipv4_stats_dump(struct stk_s *stk);

/**
 * @brief Dump information about IPv4 header
 *
 * @param msg
 *   User supplied message
 * @param ip
 *   The IPv4 header pointer
 * @return
 *   N/A
 */
CNDP_API void cnet_ipv4_dump(const char *msg, struct cne_ipv4_hdr *ip);

#if CNET_IP4_DUMP_ENABLED
#define IP4_DUMP(ip)                                                                  \
    do {                                                                              \
        cne_printf("[cyan]([orange]%s[cyan]:[orange]%d[cyan]) ", __func__, __LINE__); \
        cnet_ipv4_dump(NULL, ip);                                                     \
    } while (0)
#else
#define IP4_DUMP(ip) \
    do {             \
    } while (0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CNET_IPv4_H */
