/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2025 Intel Corporation.
 */

#include <cne_fib.h>              // for fib_create, fib_add...
#include <cne_inet4.h>            // for inet_mtoh64 and inet_h64tom
#include <cne_strings.h>          // for cne_strtok
#include <net/cne_ether.h>        // for ether_addr

#include "main.h"

#define FIB_RULE_IP   0 /**< Index for IP address in a string array */
#define FIB_RULE_MAC  1 /**< Index for MAC address in a string array  */
#define FIB_RULE_PORT 2 /**< Index for TX port in a string array */

struct ipv4_l3fwd_fib_rule {
    uint32_t ip;
    uint8_t depth;
    struct ether_addr nh;
    uint16_t tx_port;
};

static struct cne_fib *fib;

static int
l3fwd_fib_populate(struct fwd_info *fwd, struct cne_fib *fib)
{
    for (uint16_t i = 0; i < fwd->fib_size; i++) {
        struct ether_addr *addr = NULL;
        char *address[2];
        struct ether_addr eaddr;
        uint64_t eaddr_uint;
        char *entry[3];
        struct in_addr ip;
        uint32_t ip_addr;
        uint8_t mask;
        uint64_t nexthop;
        int tx_port;

        /* Parse the comma separated FIB entry */
        if (cne_strtok(fwd->fib_rules[i], ",", entry, cne_countof(entry)) != 3)
            CNE_ERR_RET("invalid number of fields for entry [orange]%u[]\n", i);

        tx_port           = atoi(entry[FIB_RULE_PORT]);
        jcfg_lport_t *dst = jcfg_lport_by_index(fwd->jinfo, tx_port);

        if (!dst)
            /* Cannot find a local port to match the entry */
            CNE_ERR_RET("Invalid TX port index value [orange]%s[]\n", entry[FIB_RULE_PORT]);

        /* Parse the IP address and mask */
        if (cne_strtok(entry[FIB_RULE_IP], "/", address, cne_countof(address)) != 2)
            CNE_ERR_RET("invalid number of ip and mask syntax\n");

        if (inet_pton(AF_INET, address[0], (void *)&ip) != 1)
            CNE_ERR_RET("Failed to convert IP4 address to network order\n");

        ip_addr = ntohl(ip.s_addr);
        mask    = (uint8_t)atoi(address[1]);

        addr = cne_ether_aton(entry[FIB_RULE_MAC], &eaddr);
        if (addr == NULL)
            CNE_ERR_RET("Ethernet address is invalid [orange](%s)[]\n", entry[FIB_RULE_MAC]);
        inet_mtoh64(&eaddr, &eaddr_uint);

        /* Store both TX port and destination MAC in FIB's nexthop field. */
        nexthop = ((uint64_t)tx_port << 48) | eaddr_uint;

        if (cne_fib_add(fib, ip_addr, mask, nexthop) < 0)
            CNE_ERR_RET(
                "Failed to add FIB entry for IP address [orange]%s and lport [orange]%d[]\n",
                address[0], tx_port);
    }

    return 0;
}

int
l3fwd_fib_lookup(uint32_t *ip, struct ether_addr *eaddr, uint16_t *tx_port, int n)
{
    uint64_t nhop[n], *nexthop = &nhop[0];

    memset(nexthop, 0, n);

    cne_fib_lookup_bulk(fib, ip, nexthop, n);

    for (uint16_t i = 0; i < n; i++) {
        inet_h64tom(nexthop[i], &eaddr[i]);
        tx_port[i] = (uint16_t)(nexthop[i] >> 48);
    }

    return 0;
}

int
l3fwd_fib_init(struct fwd_info *fwd)
{
    struct cne_fib_conf config;
    config.max_routes = 1 << 16;
    config.default_nh = 0xFFFFFFFFFFFF;
    config.type       = CNE_FIB_DUMMY;

    fib = cne_fib_create("l3fwd_fib", &config);
    if (!fib)
        CNE_ERR_RET("Failed to create FIB");

    if (l3fwd_fib_populate(fwd, fib) < 0)
        CNE_ERR_RET("Failed to populate FIB");
    ;

    /* Deallocate the entries now that we have the table populated. */
    for (int i = 0; i < fwd->fib_size; ++i)
        free(fwd->fib_rules[i]);
    free(fwd->fib_rules);

    return 0;
}
