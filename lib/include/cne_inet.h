/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
 */

#ifndef __CNE_INET_H
#define __CNE_INET_H

/**
 * @file
 * CNE INET information.
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cne_byteorder.h>
#include <net/cne_ether.h>
#include <net/cne_ip.h>
#include <net/cne_udp.h>
#include <net/cne_tcp.h>
#include <net/cne_icmp.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { IPv4_VERSION = 4, IPv6_VERSION = 6 };

/* Common defines for IPv */
enum {
    IPV4_ADDR_LEN = 4, /* IPv4 Address length */
    IPV6_ADDR_LEN = 16 /* IPv6 Address length */
};

/* Common Channel address, internet style. */
struct in_caddr {
    uint8_t cin_family;
    uint8_t cin_len;
    uint16_t cin_port;
    union {
        struct in_addr cin_addr;
        struct in6_addr cin6_addr;
    };
};

/* macros for casting struct in_caddr */
#define CIN_PORT(sa)   (sa)->cin_port
#define CIN_FAMILY(sa) (sa)->cin_family
#define CIN_LEN(sa)    (sa)->cin_len
#define CIN_ADDR(sa)   (sa)->cin_addr
#define CIN_CADDR(sa)  (sa)->cin_addr.s_addr
#define CIN6_ADDR(sa)  (sa)->cin6_addr
#define CIN6_CADDR(sa) (sa)->cin6_addr.s6_addr

/* IP overlay header for the pseudo header */
typedef struct ip_overlay_s {
    uint32_t node[2];
    uint8_t pad0;  /* overlays ttl */
    uint8_t proto; /* Protocol type */
    uint16_t len;  /* Protocol length, overlays cksum */
    uint32_t src;  /* Source address */
    uint32_t dst;  /* Destination address */
} __attribute__((__packed__)) ip_overlay_t;

/* IP6 overlay header for the pseudo header */
typedef struct ip6_overlay_s {
    uint8_t src[16];      /**< IP address of source host. */
    uint8_t dst[16];      /**< IP address of destination host(s). */
    uint32_t payload_len; /**< IP payload size, including ext. headers */
    uint8_t zero[3];      /**< Hop limits. */
    uint8_t proto;        /**< Protocol, next header. */
} __attribute__((__packed__)) ip6_overlay_t;

typedef unsigned int seq_t; /* TCP Sequence type */

/* The UDP/IP Pseudo header */
typedef struct udpip_s {
    union {
        ip_overlay_t ip4;  /* IPv4 overlay header */
        ip6_overlay_t ip6; /* IPv6 overlay header */
    };
    struct cne_udp_hdr udp; /* UDP header for protocol */
} __attribute__((__packed__)) udpip_t;

/* The TCP/IPv4 Pseudo header */
typedef struct tcpip_s {
    union {
        ip_overlay_t ip4;  /* IPv4 overlay header */
        ip6_overlay_t ip6; /* IPv6 overlay header */
    };
    struct cne_tcp_hdr tcp; /* TCP header for protocol */
} __attribute__((__packed__)) tcpip_t;

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
    CNE_STD_C11
    union {
        struct cne_ipv4_hdr ipv4; /**< IPv4 Header */
        struct cne_ipv6_hdr ipv6; /**< IPv6 Header */
        tcpip_t tip;              /**< TCP + IPv4 Headers */
        udpip_t uip;              /**< UDP + IPv4 Headers */
        struct cne_icmp_hdr icmp; /**< ICMP + IPv4 Headers */
        uint64_t pad[8];          /**< Length of structures */
    };
} pkt_hdr_t;

typedef struct ipv4_5tuple {
    uint32_t ip_dst;
    uint32_t ip_src;
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t proto;
} __cne_packed ipv4_5tuple_t;

typedef struct l3_4route_s {
    ipv4_5tuple_t key;
    uint8_t ifid;
} __cne_packed l3_4route_t;

#define IBUF_SIZE 256

#define INET_MASK_STRLEN  4
#define INET6_MASK_STRLEN 8 /* First 64-bits are the prefix of IPv6 Address */
#define IP4_ADDR_STRLEN   (INET_ADDRSTRLEN + INET_MASK_STRLEN)
#define IP6_ADDR_STRLEN   (INET6_ADDRSTRLEN + INET6_MASK_STRLEN)

#ifdef __cplusplus
}
#endif

#endif /* __CNE_INET_H */

#include <cne_inet4.h>
#ifdef CNET_ENABLE_IP6
#include <cne_inet6.h>
#endif
