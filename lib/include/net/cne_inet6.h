/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __CNE_INET6_H
#define __CNE_INET6_H

/**
 * @file
 * CNE INET routines.
 */

#include <immintrin.h>
#include <stdbool.h>
#include <bsd/string.h>
#include <net/ethernet.h>

#include <cne_common.h>
#include <cne_inet.h>

#ifndef __CNE_INET_H
#error "Do not include this file directly use cne_inet.h instead."
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define IPV6_FLOWINFO_MASK            htobe32(0x0FFFFFFF)
#define IPV6_FLOWLABEL_MASK           htobe32(0x000FFFFF)
#define IPV6_VERSION_MASK             htobe32(0xF0000000)
#define IPV6_FLOWLABEL_STATELESS_FLAG htobe32(0x00080000)

/* Sysctl settings for net ipv6.auto_flowlabels */
#define IP6_AUTO_FLOW_LABEL_OFF    0
#define IP6_AUTO_FLOW_LABEL_OPTOUT 1
#define IP6_AUTO_FLOW_LABEL_OPTIN  2
#define IP6_AUTO_FLOW_LABEL_FORCED 3

#define IP6_AUTO_FLOW_LABEL_MAX IP6_AUTO_FLOW_LABEL_FORCED

#define IP6_DEFAULT_AUTO_FLOW_LABELS IP6_AUTO_FLOW_LABEL_OPTOUT

#define IP6_MAX_FLOW_LABEL_RANGE        0xFFFFF
#define IP6_AUTO_FLOWLABELS_PATH        "/proc/sys/net/ipv6/auto_flowlabels"
#define IP6_FLOWLABEL_STATE_RANGES_PATH "/proc/sys/net/ipv6/flowlabel_state_ranges"

#define IPV6_TCLASS_MASK   (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define IPV6_TCLASS_SHIFT  20
#define IPV6_VERSION_SHIFT 28

#define IP6_MAX_MTU ETHER_MAX_MTU

#define DEFAULT_IPV6_HDR_SIZE 40 /* Minimum octets required for IPv6 header is 40 octest */

/* Compare two IPv6 Addresses */
static inline int
inet6_addr_cmp(struct in6_addr *c1, struct in6_addr *c2)
{
    return (c1->s6_addr32[0] == c2->s6_addr32[0] && c1->s6_addr32[1] == c2->s6_addr32[1] &&
            c1->s6_addr32[2] == c2->s6_addr32[2] && c1->s6_addr32[3] == c2->s6_addr32[3]);
}

/* Given an address to a in6_addr structure zero it */
static inline void
inet6_addr_zero(struct in6_addr *f)
{
    for (int i = 0; i < 4; i++)
        f->s6_addr32[i] = 0;
}

/* Copy the inet address for IPv6 addresses */
static inline void
inet6_addr_copy(struct in6_addr *t, struct in6_addr *f)
{
    if (f)
        for (int i = 0; i < 4; i++)
            t->s6_addr32[i] = f->s6_addr32[i];
    else
        inet6_addr_zero(t);
}

/* Copy the inet address from 16 octets of ip6 address */
static inline void
inet6_addr_copy_from_octs(struct in6_addr *t, uint8_t s6addr[])
{
    for (int i = 0; i < 16; i++)
        t->s6_addr[i] = s6addr[i];
}

/* Copy the inet address from 16 octets of ip6 address */
static inline void
inet6_addr_copy_octs2octs(uint8_t dst_s6addr[], uint8_t src_s6addr[])
{
    for (int i = 0; i < 16; i++)
        dst_s6addr[i] = src_s6addr[i];
}

/* Convert the inet address for IPv6 addresses from network to host order*/
static inline void
inet6_addr_ntoh(struct in6_addr *t, struct in6_addr *f)
{
    if (f)
        for (int i = 0; i < 4; i++)
            t->s6_addr32[i] = be32toh(f->s6_addr32[i]);
    else
        inet6_addr_zero(t);
}

/* Swap the two IPv6 addresses */
static inline void
inet6_addr_swap(struct in6_addr *t, struct in6_addr *f)
{
    struct in6_addr d;

    inet6_addr_copy(&d, t);
    inet6_addr_copy(t, f);
    inet6_addr_copy(f, &d);
}

/* __mask6_size(struct in6_addr *mask6) - return the number of bits in mask6 */
static __inline__ int
__mask6_size(struct in6_addr *mask6)
{
    uint8_t *mask = mask6->s6_addr;
    int i, k;

    for (k = 0; k < 16; k++) {
        if (mask[k] != 0xFF)
            break;
    }

    for (i = 0; i < 8; i++)
        if ((mask[k] & (1 << (7 - i))) == 0)
            break;

    return (k * 8) + i;
}

/* size_to_mask6( int len6, struct in6_addr *mask6 ) - return the mask for the mask size */
static __inline__ void
__size_to_mask6(int len6, struct in6_addr *mask6)
{
    int len = 0;

    if (len6 > 128) {
        CNE_ERR("Length is > 128\n");
        return;
    }

    /* Initialize the mask to zero */
    for (int i = 0; i < 4; i++)
        mask6->s6_addr32[i] = 0;

    for (int i = 0; i < 4 && len6 > 0; i++) {
        if (len6 > 32)
            len = 32;
        else
            len = len6;

        len6 = len6 - len;

        if (len == 0)
            mask6->s6_addr32[i] = 0x00000000;
        else if (len == 8)
            mask6->s6_addr32[i] = 0xFF000000;
        else if (len == 16)
            mask6->s6_addr32[i] = 0xFFFF0000;
        else if (len == 24)
            mask6->s6_addr32[i] = 0xFFFFFF00;
        else if (len == 32)
            mask6->s6_addr32[i] = 0xFFFFFFFF;
        else {
            int j;

            for (j = 0; j < len; j++)
                mask6->s6_addr32[i] |= (1 << (31 - j));
        }
    }
}

/* Given an address to a in6_addr structure check if it's all ones*/
static inline bool
inet6_addr_is_all_ones(struct in6_addr *f)
{
    for (int i = 0; i < 4; i++)
        if (f->s6_addr32[i] != 0xFFFFFFFF)
            return false;

    return true;
}

/* char * inet_ntop6(char * buff, int len, unsigned long ip_addr, unsigned long mask) - Convert
 * IPv6 address to ascii */
static inline char *
inet_ntop6(char *buff, int len, struct in6_addr *ip_addr, struct in6_addr *mask)
{
    char *orig              = buff;
    char b[IP6_ADDR_STRLEN] = {0};

    if (!buff || len < IP6_ADDR_STRLEN)
        return NULL;

    memset(buff, 0, len);

    if (inet_ntop(AF_INET6, ip_addr, b, sizeof(b)) == NULL)
        return NULL;

    if (mask && !inet6_addr_is_all_ones(mask)) {
        char lbuf[160] = {0};
        int n;

        snprintf(lbuf, sizeof(lbuf), "/%u", __mask6_size(mask));
        n = strlcpy(buff, b, len);
        buff += n;
        len -= n;
        strlcat(buff, lbuf, len);
    } else
        strlcpy(buff, b, len);

    return orig;
}

/* Compare two IPv6 Addresses with a mask value */
static inline int
inet6_addr_mask_cmp(struct in6_addr *c1, struct in6_addr *c2, struct in6_addr *n1)
{
    int val;

    if (n1->s6_addr32[0] == 0)
        return 0;

    val = ((c1->s6_addr32[0] & n1->s6_addr32[0]) == (c2->s6_addr32[0] & n1->s6_addr32[0]) &&
           (c1->s6_addr32[1] & n1->s6_addr32[1]) == (c2->s6_addr32[1] & n1->s6_addr32[1]) &&
           (c1->s6_addr32[2] & n1->s6_addr32[2]) == (c2->s6_addr32[2] & n1->s6_addr32[2]) &&
           (c1->s6_addr32[3] & n1->s6_addr32[3]) == (c2->s6_addr32[3] & n1->s6_addr32[3]));

    return val;
}

/* Given an address to a in6_addr structure check if it's non zero */
static inline bool
inet6_addr_is_non_zero(struct in6_addr *f)
{
    for (int i = 0; i < 4; i++)
        if (f->s6_addr32[i] != 0)
            return true;

    return false;
}

/* Given an address to a in6_addr structure check if it's zero */
static inline bool
inet6_addr_is_zero(struct in6_addr *f)
{
    return (!inet6_addr_is_non_zero(f));
}

/* Given an address to a in6_addr structure check if it's any */
static inline bool
inet6_addr_is_any(struct in6_addr *f)
{
    return inet6_addr_is_zero(f);
}

static inline void
inet6_all_node_multicast_addr(struct in6_addr *all_node_mcast)
{
    unsigned char *addrbuf = (unsigned char *)all_node_mcast;
    /*
     * RFC 4291:
     */

    addrbuf[0] = 0xFF;
    addrbuf[1] = 0x02;
    memset(&addrbuf[2], 0, 13);
    addrbuf[15] = 0x01;
}

static inline void
inet6_all_router_multicast_addr(struct in6_addr *all_node_mcast)
{
    unsigned char *addrbuf = (unsigned char *)all_node_mcast;
    /*
     * RFC 4291:
     */

    addrbuf[0] = 0xFF;
    addrbuf[1] = 0x02;
    memset(&addrbuf[2], 0, 13);
    addrbuf[15] = 0x02;
}

static inline void
inet6_ns_multicast_addr(struct in6_addr *ns_mcast, struct in6_addr *target)
{
    unsigned char *addrbuf = (unsigned char *)ns_mcast;
    /*  RFC 4291:
        Solicited-Node Address: FF02:0:0:0:0:1:FFXX:XXXX
        A Solicited-Node multicast address is formed by taking the
        low-order 24 bits of an address (unicast or anycast) and
        appending those bits to the prefix FF02:0:0:0:0:1:FF00::/104
        resulting in a multicast address in the range:
             FF02:0:0:0:0:1:FF00:0000 to FF02:0:0:0:0:1:FFFF:FFFF
    */

    addrbuf[0] = 0xFF;
    addrbuf[1] = 0x02;
    memset(&addrbuf[2], 0, 9);
    addrbuf[11] = 0x01;
    addrbuf[12] = 0xFF;
    memcpy(&addrbuf[13], &target->s6_addr[13], 3);
}

static inline void
inet6_unspec_addr(struct in6_addr *all_node_mcast)
{
    unsigned char *addrbuf = (unsigned char *)all_node_mcast;
    /*
     * RFC 4291:
     */
    memset(&addrbuf[0], 0, 16);
}

static inline bool
inet6_is_unspec_addr(struct in6_addr *addr)
{
    return (addr->s6_addr32[0] == 0 && addr->s6_addr32[1] == 0 && addr->s6_addr32[2] == 0 &&
            addr->s6_addr32[3] == 0);
}

static inline bool
inet6_is_multicast_addr(struct in6_addr *addr)
{
    return (addr->s6_addr[0] == 0xFF);
}

static inline bool
inet6_is_ns_multicast_addr(struct in6_addr *addr)
{
    unsigned char *addrbuf   = (unsigned char *)addr;
    unsigned char allzero[9] = {0};
    /*  RFC 4291:
        Solicited-Node Address: FF02:0:0:0:0:1:FFXX:XXXX
        A Solicited-Node multicast address is formed by taking the
        low-order 24 bits of an address (unicast or anycast) and
        appending those bits to the prefix FF02:0:0:0:0:1:FF00::/104
        resulting in a multicast address in the range:
             FF02:0:0:0:0:1:FF00:0000 to FF02:0:0:0:0:1:FFFF:FFFF
    */

    return (addrbuf[0] == 0xFF && addrbuf[1] == 0x02 && memcmp(&addrbuf[2], allzero, 9) == 0 &&
            addrbuf[11] == 0x01 && addrbuf[12] == 0xFF);
}
static inline void
ip6_flow_hdr(struct cne_ipv6_hdr *hdr, uint32_t tclass, uint32_t flowlabel)
{
    *(__be32 *)hdr =
        htonl((IPv6_VERSION << IPV6_VERSION_SHIFT) | (tclass << IPV6_TCLASS_SHIFT)) | flowlabel;
}
#ifdef __cplusplus
}
#endif

#endif /* __CNE_INET6_H */
