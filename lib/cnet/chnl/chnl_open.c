/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <bsd/string.h>
#include <cnet.h>           // for cnet, cnet_add_singleton
#include <cne_vec.h>        // for vec_len, vec_set_len, vec_at_index, vec_max...
#include <cne_log.h>        // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_ERR, CNE_LO...
#include <cne_strings.h>
#include <cnet_netif.h>        // for netif, netif::(anonymous), _IFF_RUNNING
#include <stdio.h>             // for snprintf, NULL
#include <stdlib.h>            // for calloc, free
#include <string.h>            // for memcpy, strncmp

#include "chnl_priv.h"
#include <cnet_chnl.h>
#include <cnet_chnl_opt.h>
#include "chnl_open_priv.h"

typedef struct {
    const char *name;   /**< Name of the open type */
    uint16_t otype;     /**< Type of open to perform */
    uint16_t nb_fields; /**< Number of fields in string to expect. */
} chnl_open_t;

// clang-format off
/**
 * A list of string types and number of fields in string. It is possible
 * to have more then one string type with different number of fields.
 */
static chnl_open_t open_types[] = {
    {"udp-listen",   UDP4_LISTEN,  2}, /* udp-listen:<port> */
    {"udp-listen",   UDP4_LISTEN,  3}, /* udp-listen:<ipaddr>:<port> */
    {"udp-connect",  UDP4_CONNECT, 3}, /* udp->connect:<ipaddr>:<port> */

    {"udp4-listen",  UDP4_LISTEN,  2}, /* udp4-listen:<port> */
    {"udp4-listen",  UDP4_LISTEN,  3}, /* udp4-listen:<ipaddr>:<port> */
    {"udp4-connect", UDP4_CONNECT, 3}, /* udp4->connect:<ipaddr>:<port> */

    {"udp6-listen",  UDP6_LISTEN,  2}, /* udp6-listen:<port> */
    {"udp6-listen",  UDP6_LISTEN,  3}, /* udp6-listen:<ipaddr>:<port> */
    {"udp6-connect", UDP6_CONNECT, 3}, /* udp6->connect:<ipaddr>:<port> */

    {"tcp-listen",   TCP4_LISTEN,  2}, /* tcp-listen:<port> */
    {"tcp-listen",   TCP4_LISTEN,  3}, /* tcp-listen:<ipaddr>:<port> */
    {"tcp-connect",  TCP4_CONNECT, 3}, /* tcp-connect:<ipaddr>:<port> */

    {"tcp4-listen",  TCP4_LISTEN,  2}, /* tcp4-listen:<port> */
    {"tcp4-listen",  TCP4_LISTEN,  3}, /* tcp4-listen:<ipaddr>:<port> */
    {"tcp4-connect", TCP4_CONNECT, 3}, /* tcp4-connect:<ipaddr>:<port> */

    {"tcp6-listen",  TCP6_LISTEN,  2}, /* tcp6-listen:<port> */
    {"tcp6-listen",  TCP6_LISTEN,  3}, /* tcp6-listen:<ipaddr>:<port> */
    {"tcp6-connect", TCP6_CONNECT, 3}, /* tcp6-connect:<ipaddr>:<port> */
    {NULL, MAX_OPEN_TYPES, 0}
    };
// clang-format on

static int
create_chnl(int otype, int domain, int type, const char *name, int port, int flags, chnl_cb_t cb)
{
    int cd;
    uint32_t opt;

    if (!cb)
        CNE_ERR_RET("channel callback is NULL\n");

    cd = channel(domain, type, 0, cb);
    if (cd < 0)
        CNE_ERR_RET("channel call failed\n");

    opt = 1;
    chnl_set_opt(cd, SO_CHANNEL, SO_REUSEADDR, &opt, sizeof(uint32_t));

    opt = (flags & CHNL_ENABLE_UDP_CHECKSUM) ? 1 : 0;
    chnl_set_opt(cd, 0, SO_UDP_CHKSUM, &opt, sizeof(uint32_t));

    if (name) {
        if (domain == AF_INET) {
            struct in_caddr addr;

            in_caddr_zero(&addr);

            if (inet_pton(AF_INET, name, (void *)&addr.cin_addr.s_addr) != 1)
                CNE_ERR_RET("Unable to convert IP4 address to network order\n");
            addr.cin_family = domain;
            addr.cin_len    = sizeof(struct in_addr);
            addr.cin_port   = htobe16(port);

            if (otype == TCP4_LISTEN || otype == UDP4_LISTEN) {
                if (chnl_bind(cd, (struct sockaddr *)&addr, sizeof(struct in_caddr)) == -1)
                    CNE_ERR_RET("chnl_bind() failed\n");
            } else if (otype == TCP4_CONNECT || otype == UDP4_CONNECT) {
                if (chnl_connect(cd, (struct sockaddr *)&addr, sizeof(struct in_caddr)))
                    CNE_ERR_RET("chnl_connect() failed\n");
            }
        } else if (domain == AF_INET6)
            CNE_ERR_RET("IPv6 is not supported\n");
    } else {
        if ((otype == TCP4_LISTEN || otype == TCP6_LISTEN) && type == SOCK_STREAM)
            chnl_listen(cd, CNET_TCP_BACKLOG_COUNT);
    }

    return cd;
}

int
chnl_open(const char *str, int flags, chnl_cb_t fn)
{
    chnl_open_t *pt;
    char *info[8] = {};
    char tmp_line[128];
    char *ipaddr = NULL, *pstr;
    int domain, typ, port_id, nb_fields;

    if (this_stk == NULL)
        CNE_ERR_RET("CNET instance pointer is NULL\n");

    if (strlcpy(tmp_line, str, sizeof(tmp_line)) >= sizeof(tmp_line))
        CNE_ERR_RET("open string (%s) too long\n", str);

    nb_fields = cne_strtok(tmp_line, ":", info, cne_countof(info));
    if (nb_fields < 0)
        CNE_ERR_RET("invalid number of fields for [orange]%s[]\n", str);

    /* find the correct open string type with the correct number of fields */
    for (pt = open_types; pt->name != NULL; pt++) {
        if (!strncasecmp(info[0], pt->name, strlen(pt->name))) {
            if (nb_fields == pt->nb_fields)
                break;
        }
    }
    if (pt->nb_fields == MAX_OPEN_TYPES)
        CNE_ERR_RET("unable to find chnl_open(%s) with %d fields\n", str, nb_fields);

    domain = AF_UNSPEC;
    typ    = 0;
    ipaddr = (char *)(uintptr_t) "0.0.0.0";

    switch (pt->otype) {
    case UDP4_LISTEN:
    case UDP6_LISTEN:
        domain = (pt->otype == UDP4_LISTEN) ? AF_INET : AF_INET6;
        typ    = SOCK_DGRAM;

        if (pt->nb_fields == 2)
            pstr = info[1];
        else {
            ipaddr = info[1];
            pstr   = info[2];
        }
        break;

    case UDP4_CONNECT:
    case UDP6_CONNECT:
        domain = (pt->otype == UDP4_CONNECT) ? AF_INET : AF_INET6;
        typ    = SOCK_DGRAM;

        ipaddr = info[1];
        pstr   = info[2];
        break;

    case TCP4_LISTEN:
    case TCP6_LISTEN:
        if (!CNET_ENABLE_TCP)
            CNE_ERR_RET(" [cyan]TCP is disabled[]");
        domain = (pt->otype == TCP4_LISTEN) ? AF_INET : AF_INET6;
        typ    = SOCK_STREAM;

        if (pt->nb_fields == 2)
            pstr = info[1];
        else {
            ipaddr = info[1];
            pstr   = info[2];
        }
        break;

    case TCP4_CONNECT:
    case TCP6_CONNECT:
        if (!CNET_ENABLE_TCP)
            CNE_ERR_RET(" [cyan]TCP is disabled[]");
        domain = (pt->otype == TCP4_CONNECT) ? AF_INET : AF_INET6;
        typ    = SOCK_STREAM;

        ipaddr = info[1];
        pstr   = info[2];
        break;

    default:
        CNE_ERR_RET("Invalid channel open type %s\n", str);
    }

    errno   = 0;
    port_id = strtol(pstr, NULL, 0); /* Can be decimal or hex value with 0x prefix */
    if (errno == ERANGE || port_id < 0 || port_id > UINT16_MAX)
        CNE_ERR_RET("invalid port number %s\n", pstr);

    return create_chnl(pt->otype, domain, typ, ipaddr, port_id, flags, fn);
}
