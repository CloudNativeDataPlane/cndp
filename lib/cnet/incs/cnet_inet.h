/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_INET_H
#define __CNET_INET_H

/**
 * @file
 * CNET INET information.
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cne_byteorder.h>

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

#ifdef __cplusplus
}
#endif

#define IBUF_SIZE 256

static inline char *
inet_caddr_print(const char *msg, const struct in_caddr *addr)
{
    char *buf;
    char ip[64];
    static char ibuf[IBUF_SIZE];

    buf = &ibuf[0];

    snprintf(buf, IBUF_SIZE, "%s Family %d Len %d: %s:%d", (msg == NULL) ? "" : msg,
             CIN_FAMILY(addr), CIN_LEN(addr), inet_ntop(AF_INET, &CIN_CADDR(addr), ip, sizeof(ip)),
             be16toh(CIN_PORT(addr)));

    return buf;
}

static inline char *
inet_saddr_print(const char *msg, const struct sockaddr *addr)
{
    const struct sockaddr_in *saddr = (const struct sockaddr_in *)addr;
    char *buf;
    char ip[64];
    static char ibuf[IBUF_SIZE];

    buf = &ibuf[0];
    snprintf(buf, IBUF_SIZE, "%s Family %d: %s", (msg == NULL) ? "" : msg, addr->sa_family,
             inet_ntop(AF_INET, &saddr->sin_addr, ip, sizeof(ip)));
    return buf;
}

#include <cnet_inet4.h>

#endif /* __CNET_INET_H */
