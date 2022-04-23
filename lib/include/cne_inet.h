/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNE_INET_H
#define __CNE_INET_H

/**
 * @file
 * CNET INET information.
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
    struct in_addr cin_addr;
};

/* macros for casting struct in_caddr */
#define CIN_PORT(sa)   (sa)->cin_port
#define CIN_FAMILY(sa) (sa)->cin_family
#define CIN_LEN(sa)    (sa)->cin_len
#define CIN_ADDR(sa)   (sa)->cin_addr
#define CIN_CADDR(sa)  (sa)->cin_addr.s_addr

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

/* The TCP/IPv4 Pseudo header */
typedef struct tcpip_s {
    ipOverlay_t ip;         /* IPv4 overlay header */
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

#define INET_MASK_STRLEN 4
#define IP4_ADDR_STRLEN  (INET_ADDRSTRLEN + INET_MASK_STRLEN)

#ifdef __cplusplus
}
#endif

#endif /* __CNE_INET_H */

#include <cne_inet4.h>
