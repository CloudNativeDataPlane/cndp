/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) <2010>, Intel Corporation. All rights reserved.
 */
/* Created 2010 by Keith Wiles @ intel.com */

#ifndef __INET_H
#define __INET_H

#ifdef CNE_MACHINE_CPUFLAG_SSE4_2
#include <nmmintrin.h>
#else
#include <cne_jhash.h>
#endif
#include <stdio.h>             // for snprintf
#include <stdint.h>            // for uint32_t, uint16_t, uint8_t, uint64_t
#include <bsd/string.h>        // for strlcat, strlcpy
#include <arpa/inet.h>         // for inet_ntop
#include <netinet/in.h>        // for IPPROTO_ICMP, IPPROTO_IGMP, IPPROTO_IP
#include <cne_ether.h>         // for _MTOA_, cne_ether_hdr
#include <cne_net.h>
#include <net/cne_icmp.h>        // for cne_icmp_hdr
#include <net/ethernet.h>        // for ether_addr
#include <smmintrin.h>           // for _mm_crc32_u32
#include <string.h>              // for strlen
#include <sys/socket.h>          // for AF_INET, AF_INET6

#include "net/cne_ip.h"         // for cne_ipv4_hdr, cne_ipv6_hdr
#include "net/cne_tcp.h"        // for cne_tcp_hdr
#include "net/cne_udp.h"        // for cne_udp_hdr

#ifdef __cplusplus
extern "C" {
#endif

#define IPv4_VERSION 4

#define CNE_IPADDR_V4      0x01
#define CNE_IPADDR_NETWORK 0x04

#define CNE_INADDRSZ    4
#define CNE_PREFIXMAX   128
#define CNE_V4PREFIXMAX 32

struct pg_ipaddr {
    uint8_t family;
    union {
        struct in_addr ipv4;
    };
    unsigned int prefixlen; /* in case of network only */
};

#define CNE_ISFRAG(off) ((off) & (CNE_OFF_MF | CNE_OFF_MASK))
#define CNE_OFF_MASK    0x1fff
#define CNE_OFF_MF      0x2000
#define CNE_OFF_DF      0x4000

/**
 * struct cne_ipv4_hdr.proto values in the IP Header.
 *  1     ICMP        Internet Control Message            [RFC792]
 *  2     IGMP        Internet Group Management          [RFC1112]
 *  4     IP          IP in IP (encapsulation)           [RFC2003]
 *  6     TCP         Transmission Control                [RFC793]
 * 17     UDP         User Datagram                   [RFC768,JBP]
 * 41     IPv6        Ipv6                               [Deering]
 * 43     IPv6-Route  Routing Header for IPv6            [Deering]
 * 44     IPv6-Frag   Fragment Header for IPv6           [Deering]
 * 47     GRE         Generic Routing Encapsulation [RFC2784,2890]
 * 58     IPv6-ICMP   ICMP for IPv6                      [RFC1883]
 * 59     IPv6-NoNxt  No Next Header for IPv6            [RFC1883]
 * 60     IPv6-Opts   Destination Options for IPv6       [RFC1883]
 */
#define CNE_IPPROTO_NONE    0
#define CNE_IPPROTO_IP      IPPROTO_IP
#define CNE_IPPROTO_ICMP    IPPROTO_ICMP
#define CNE_IPPROTO_IGMP    IPPROTO_IGMP
#define CNE_IPPROTO_IPV4    IPPROTO_IPV4
#define CNE_IPPROTO_TCP     IPPROTO_TCP
#define CNE_IPPROTO_UDP     IPPROTO_UDP
#define CNE_IPPROTO_RAW     IPPROTO_RAW
#define CNE_IPPROTO_USR_DEF 255
#define CNE_IPPROTO_MAX     256

#define IPv4(a, b, c, d) \
    ((uint32_t)(((a)&0xff) << 24) | (((b)&0xff) << 16) | (((c)&0xff) << 8) | ((d)&0xff))

/* IP overlay header for the pseudo header */
typedef struct ipOverlay_s {
    uint32_t node[2];
    uint8_t pad0;  /* overlays ttl */
    uint8_t proto; /* Protocol type */
    uint16_t len;  /* Protocol length, overlays cksum */
    uint32_t src;  /* Source address */
    uint32_t dst;  /* Destination address */
} __attribute__((__packed__)) ipOverlay_t;

typedef unsigned int seq_t; /* TCP Sequence type */

/* The UDP/IP Pseudo header */
typedef struct udpip_s {
    ipOverlay_t ip;         /* IPv4 overlay header */
    struct cne_udp_hdr udp; /* UDP header for protocol */
} __attribute__((__packed__)) udpip_t;

enum {
    URG_FLAG = 0x20,
    ACK_FLAG = 0x10,
    PSH_FLAG = 0x08,
    RST_FLAG = 0x04,
    SYN_FLAG = 0x02,
    FIN_FLAG = 0x01
};

/* The TCP/IPv4 Pseudo header */
typedef struct tcpip_s {
    ipOverlay_t ip;         /* IPv4 overlay header */
    struct cne_tcp_hdr tcp; /* TCP header for protocol */
} __attribute__((__packed__)) tcpip_t;

/* Common defines for Ethernet */
#define ETH_HW_TYPE   1  /* Ethernet hardware type */
#define ETH_HDR_SIZE  14 /* Ethernet MAC header length */
#define ETH_ADDR_SIZE 6  /* Ethernet MAC address length */

typedef union {
    uint16_t _16[3];
    uint8_t _8[6];
} mac_e;

typedef union {
    uint16_t _16[2];
    uint32_t _32;
} ip4_e;

typedef struct pkt_hdr_s {
    struct cne_ether_hdr eth; /**< Ethernet header */
    union {
        struct cne_ipv4_hdr ipv4; /**< IPv4 Header */
        struct cne_ipv6_hdr ipv6; /**< IPv6 Header */
        tcpip_t tip;              /**< TCP + IPv4 Headers */
        udpip_t uip;              /**< UDP + IPv4 Headers */
        struct cne_icmp_hdr icmp; /**< ICMP + IPv4 Headers */
        uint64_t pad[8];          /**< Length of structures */
    } u;
} pkt_hdr_t;

typedef struct ipv4_5tuple {
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t proto;
} __attribute__((__packed__)) ipv4_5tuple_t;

typedef struct l3_4route_s {
    ipv4_5tuple_t key;
    uint8_t ifid;
} __attribute__((__packed__)) l3_4route_t;

/*********************************************************************************/
/**
 * Use crc32 instruction to perform a 6 byte hash.
 *
 * @param data
 *   Data to perform hash on.
 * @param data_len
 *   How many bytes to use to calculate hash value. (Not Used)
 * @param init_val
 *   Value to initialize hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
cne_hash6_crc(const void *data, __attribute__((unused)) uint32_t data_len, uint32_t init_val)
{
#ifdef CNE_MACHINE_CPUFLAG_SSE4_2
    const uint32_t *p32 = (const uint32_t *)data;
    const uint16_t val  = *(const uint16_t *)p32;

    return _mm_crc32_u32(val, _mm_crc32_u32(*p32++, init_val));
#else
    return cne_jhash(data, data_len, init_val);
#endif
}

/* ethAddrCopy( u16_t * to, u16_t * from ) - Swap two Ethernet addresses */
static __inline__ void
ethAddrCopy(void *t, void *f)
{
    uint16_t *d = (uint16_t *)t;
    uint16_t *s = (uint16_t *)f;

    *d++ = *s++;
    *d++ = *s++;
    *d   = *s;
}

/* ethSwap(u16_t * to, u16_t * from) - Swap two 16 bit values */
static __inline__ void
uint16Swap(void *t, void *f)
{
    uint16_t *d = (uint16_t *)t;
    uint16_t *s = (uint16_t *)f;
    uint16_t v;

    v  = *d;
    *d = *s;
    *s = v;
}

/* ethAddrSwap( u16_t * to, u16_t * from ) - Swap two ethernet addresses */
static __inline__ void
ethAddrSwap(void *t, void *f)
{
    uint16_t *d = (uint16_t *)t;
    uint16_t *s = (uint16_t *)f;

    uint16Swap(d++, s++);
    uint16Swap(d++, s++);
    uint16Swap(d, s);
}

/* inetAddrCopy( void * t, void * f ) - Copy IPv4 address */
static __inline__ void
inetAddrCopy(void *t, void *f)
{
    uint32_t *d = (uint32_t *)t;
    uint32_t *s = (uint32_t *)f;

    *d = *s;
}

/* inetAddrSwap( void * t, void * f ) - Swap two IPv4 addresses */
static __inline__ void
inetAddrSwap(void *t, void *f)
{
    uint32_t *d = (uint32_t *)t;
    uint32_t *s = (uint32_t *)f;
    uint32_t v;

    v  = *d;
    *d = *s;
    *s = v;
}

#ifndef _MASK_SIZE_
#define _MASK_SIZE_
/* mask_size(uint32_t mask) - return the number of bits in mask */
static __inline__ int
mask_size(uint32_t mask)
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
#endif

/* size_to_mask( int len ) - return the mask for the mask size */
static __inline__ uint32_t
size_to_mask(int len)
{
    uint32_t mask = 0;

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

#ifndef _NTOP4_
#define _NTOP4_

/* Max IP address with mask '123.123.123.123' = 15, 3 for mask '/32' + 1 for NULL */
#define IP_ADDR_STRLEN (15 + 3 + 1)

/* char * inet_ntop4(char * buff, int len, unsigned long ip_addr, unsigned long mask) - Convert
 * IPv4 address to ascii */
static __inline__ char *
inet_ntop4(char *buff, int len, unsigned long ip_addr, unsigned long mask)
{
    char *orig = buff;
    char b[64] = {0};

    if (!buff || len < IP_ADDR_STRLEN)
        return NULL;

    memset(buff, 0, len);

    if (inet_ntop(AF_INET, &ip_addr, b, sizeof(b)) == NULL)
        return NULL;

    if (mask != 0xFFFFFFFF) {
        char lbuf[64] = {0};
        int n;

        snprintf(lbuf, sizeof(lbuf), "/%u", mask_size(mask));
        n = strlcpy(buff, b, len);
        buff += n;
        len -= n;
        strlcat(buff, lbuf, len);
    } else
        strlcpy(buff, b, len);

    return orig;
}
#endif

static __inline__ const char *
inet_ntop6(char *buff, int len, uint8_t *ip6)
{
    return inet_ntop(AF_INET6, ip6, buff, len);
}

#ifndef _MTOA_
#define _MTOA_
/* char * inet_mtoa(char * buff, int len, struct ether_addr * eaddr) - Convert MAC address to
 * ascii */
static __inline__ char *
inet_mtoa(char *buff, int len, struct ether_addr *eaddr)
{
    snprintf(buff, len, "%02x:%02x:%02x:%02x:%02x:%02x", eaddr->ether_addr_octet[0],
             eaddr->ether_addr_octet[1], eaddr->ether_addr_octet[2], eaddr->ether_addr_octet[3],
             eaddr->ether_addr_octet[4], eaddr->ether_addr_octet[5]);
    return buff;
}
#endif

/* convert a MAC address from network byte order to host 64bit number */
static __inline__ uint64_t
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
static __inline__ struct ether_addr *
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

/**
 * Convert an IPv4/v6 address into a binary value.
 *
 * @param buf
 *   Location of string to convert
 * @param flags
 *   Set of flags for converting IPv4/v6 addresses and netmask.
 * @param res
 *   Location to put the results
 * @param ressize
 *   Length of res in bytes.
 * @return
 *   0 on OK and -1 on error
 */
int _atoip(const char *buf, int flags, void *res, unsigned ressize);

#ifdef __cplusplus
}
#endif

#endif /* __INET_H */
