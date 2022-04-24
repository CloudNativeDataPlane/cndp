/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNE_INET4_H
#define __CNE_INET4_H

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

/* mask_size(uint32_t mask) - return the number of bits in mask */
static __inline__ int
__mask_size(uint32_t mask)
{
    if (mask == 0)
        return 0;
    else if (mask == 0xFF000000)
        return 8;
    else if (mask == 0xFFFF0000)
        return 16;
    else if (mask == 0xFFFFFF00)
        return 24;
    else if (mask == 0xFFFFFFFF)
        return 32;
    else {
        int i;
        for (i = 0; i < 32; i++)
            if ((mask & (1 << (31 - i))) == 0)
                break;
        return i;
    }
}

/* size_to_mask( int len ) - return the mask for the mask size */
static __inline__ uint32_t
__size_to_mask(int len)
{
    uint32_t mask = 0;

    if (len > 32)
        CNE_ERR_RET("Length is > 32\n");

    if (len == 0)
        mask = 0x00000000;
    else if (len == 8)
        mask = 0xFF000000;
    else if (len == 16)
        mask = 0xFFFF0000;
    else if (len == 24)
        mask = 0xFFFFFF00;
    else if (len == 32)
        mask = 0xFFFFFFFF;
    else {
        int i;

        for (i = 0; i < len; i++)
            mask |= (1 << (31 - i));
    }
    return mask;
}

/* char * inet_ntop4(char * buff, int len, unsigned long ip_addr, unsigned long mask) - Convert
 * IPv4 address to ascii */
static inline char *
inet_ntop4(char *buff, int len, struct in_addr *ip_addr, struct in_addr *mask)
{
    char *orig              = buff;
    char b[IP4_ADDR_STRLEN] = {0};

    if (!buff || len < IP4_ADDR_STRLEN)
        return NULL;

    memset(buff, 0, len);

    if (inet_ntop(AF_INET, ip_addr, b, sizeof(b)) == NULL)
        return NULL;

    if (mask && mask->s_addr != 0xFFFFFFFF) {
        char lbuf[64] = {0};
        int n;

        snprintf(lbuf, sizeof(lbuf), "/%u", __mask_size(mask->s_addr));
        n = strlcpy(buff, b, len);
        buff += n;
        len -= n;
        strlcat(buff, lbuf, len);
    } else
        strlcpy(buff, b, len);

    return orig;
}

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

/* Compare the two in_caddr structures to determine if equal */
static inline int
in_caddr_compare(struct in_caddr *p1, struct in_caddr *p2)
{
#ifdef USE_AVX_INSTRUCTIONS
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

    if (len == 0)
        len = cne_numbytes(ip);

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

#endif /* __CNE_INET4_H */
