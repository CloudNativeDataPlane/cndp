/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_INET4_H
#define __CNET_INET4_H

/**
 * @file
 * CNET INET routines.
 */

#include <immintrin.h>
#include <stdbool.h>

#include <cnet_inet.h>
#include <cnet_ether.h>

#ifndef __CNET_INET_H
#error "Do not include this file directly use cnet_inet.h instead."
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Compare two IPv4 Addresses */
static inline int
inet_addr_cmp(struct in_addr *c1, struct in_addr *c2)
{
    return c1->s_addr == c2->s_addr;
}

/* Copy the inet address for IPv4 addresses */
static inline void
inet_addr_copy(struct in_addr *t, struct in_addr *f)
{
    t->s_addr = f->s_addr;
}

/* Swap the two words of an IPv4 address */
static inline void
inet_addr_swap(uint32_t *t, uint32_t *f)
{
    uint32_t d;

    d  = *t;
    *t = *f;
    *f = d;
}

#ifndef _NTOP4_
#define _NTOP4_
static __inline__ char *
inet_ntop4(struct in_addr *ip_addr, struct in_addr *mask)
{
    static char v4buf[128];
    char lbuf[64];

    inet_ntop(AF_INET, &ip_addr->s_addr, lbuf, sizeof(lbuf));
    if (mask && mask->s_addr && (mask->s_addr != 0xFFFFFFFF)) {
        int bits = (32 - __builtin_ctzl(mask->s_addr));

        snprintf(v4buf, sizeof(v4buf), "%s/%d", lbuf, bits);
    } else
        strcpy(v4buf, lbuf);

    return v4buf;
}
#endif

#ifndef _MTOA_
#define _MTOA_
static inline char *
inet_mtoa(struct ether_addr *eaddr)
{
    static char buff[64];

    snprintf(buff, sizeof(buff), "%02x:%02x:%02x:%02x:%02x:%02x", eaddr->ether_addr_octet[0],
             eaddr->ether_addr_octet[1], eaddr->ether_addr_octet[2], eaddr->ether_addr_octet[3],
             eaddr->ether_addr_octet[4], eaddr->ether_addr_octet[5]);

    return buff;
}
#endif

/* convert a MAC address from network byte order to host 64bit number */
static inline uint64_t
inet_mtoh64(struct ether_addr *eaddr, uint64_t *value)
{
    *value =
        ((uint64_t)eaddr->ether_addr_octet[5] << 0) + ((uint64_t)eaddr->ether_addr_octet[4] << 8) +
        ((uint64_t)eaddr->ether_addr_octet[3] << 16) +
        ((uint64_t)eaddr->ether_addr_octet[2] << 24) +
        ((uint64_t)eaddr->ether_addr_octet[1] << 32) + ((uint64_t)eaddr->ether_addr_octet[0] << 40);
    return *value;
}

/* convert a host 64bit number to MAC address in network byte order */
static inline struct ether_addr *
inet_h64tom(uint64_t value, struct ether_addr *eaddr)
{
    eaddr->ether_addr_octet[5] = ((value >> 0) & 0xFF);
    eaddr->ether_addr_octet[4] = ((value >> 8) & 0xFF);
    eaddr->ether_addr_octet[3] = ((value >> 16) & 0xFF);
    eaddr->ether_addr_octet[2] = ((value >> 24) & 0xFF);
    eaddr->ether_addr_octet[1] = ((value >> 32) & 0xFF);
    eaddr->ether_addr_octet[0] = ((value >> 40) & 0xFF);
    return eaddr;
}

/* Compare two IPv4 Addresses with a mask value */
static inline int
inet_addr_mask_cmp(struct in_addr *c1, struct in_addr *c2, struct in_addr *n1)
{
    int val;

    if (n1->s_addr == 0)
        return 0;

    val = (c1->s_addr & n1->s_addr) == (c2->s_addr & n1->s_addr);

    return val;
}

/* Given an address to a in_caddr structure zero it */
static inline void
in_caddr_zero(struct in_caddr *f)
{
    struct in_caddr z = {0};
    *f                = *(struct in_caddr *)&z;
}

/* Copy the 'f' in_caddr structure to 't' in_caddr structure */
static inline void
in_caddr_copy(struct in_caddr *t, struct in_caddr *f)
{
    *t = *f;
}

#if 0
static inline bool
vec_equal(__m256i a, __m256i b) {
    __m256i pcmp = _mm256_cmpeq_epi32(a, b);  // epi8 is fine too
    unsigned bitmask = _mm256_movemask_epi8(pcmp);
    return (bitmask == 0xffffffffU);
}
#endif

/* Compare the two in_caddr structures to determine if equal */
static inline int
in_caddr_compare(struct in_caddr *p1, struct in_caddr *p2)
{
#if 0
	__m256i v1, v2;

	v1 = _mm256_loadu_si256((__m256i const *)p1);
	v2 = _mm256_loadu_si256((__m256i const *)p2);

	return vec_equal(v1, v2);
#else
    return (p1->cin_len == p2->cin_len) && (p1->cin_family == p2->cin_family) &&
           (p1->cin_addr.s_addr == p2->cin_addr.s_addr) && (p1->cin_port == p2->cin_port);
#endif
}

#define in_caddr_eq(p1, p2) in_caddr_compare((p1), (p2))

/* Compare the two in_caddr structures to determine if equal */
static inline int
in_caddr_neq(struct in_caddr *p1, struct in_caddr *p2)
{
    return !in_caddr_compare(p1, p2);
}

/* Compare the two in_caddr structures to determine if equal */
static inline int
in_caddr_gt(struct in_caddr *p1, struct in_caddr *p2)
{
    return memcmp(p1, p2, p1->cin_len) > 0;
}

/* Compare the two in_caddr structures to determine if equal */
static inline int
in_caddr_lt(struct in_caddr *p1, struct in_caddr *p2)
{
    return memcmp(p1, p2, p1->cin_len) < 0;
}

static inline void
in_caddr_and(struct in_caddr *p1, struct in_caddr *p2)
{
    p1->cin_addr.s_addr &= p2->cin_addr.s_addr;
}

static inline void
in_caddr_mask(struct in_caddr *na, struct in_caddr *da, struct in_caddr *ma)
{
    na->cin_addr.s_addr = da->cin_addr.s_addr & ma->cin_addr.s_addr;
}

/* Fill in the in_caddr structure information. */
static inline void
in_caddr_create(struct in_caddr *sa, struct in_addr *pa, int type, int len, int port)
{
    uint32_t ip = pa->s_addr;

    in_caddr_zero(sa);

    CNE_DEBUG("addr %08x, len %d ", ip, len);
    if (len == 0) {
        len = __numbytes(ip);
        CNE_DEBUG(" ctz %d, bytes %d\n", __builtin_ctz(ip), len);
    }
    CNE_DEBUG("\n");

    sa->cin_len         = len;
    sa->cin_family      = type;
    sa->cin_port        = port;
    sa->cin_addr.s_addr = ip;
}

/* Fill in the in_caddr structure information. */
static inline void
in_caddr_init(struct in_caddr *sa, int type, int len, int port)
{
    in_caddr_zero(sa);
    sa->cin_len    = len;
    sa->cin_family = type;
    sa->cin_port   = port;
}

/* Fill in the in_caddr structure information. */
static inline void
in_caddr_update(struct in_caddr *sa, int type, int len, int port)
{
    sa->cin_len    = len;
    sa->cin_family = type;
    sa->cin_port   = port;
}

#ifdef __cplusplus
}
#endif

#endif /* __CNET_INET4_H */
