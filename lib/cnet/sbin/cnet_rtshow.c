/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
 */

#include <string.h>             // for strcmp
#include <cnet.h>               // for cnet_add_instance
#include <cnet_netif.h>         // for cnet_netif_from_index
#include <cnet_route.h>         // for
#include <cnet_route4.h>        // for cnet_route4_show
#include <cnet_ipv4.h>          // for cnet_ipv4_stats_dump
#include <cnet_ipv6.h>          // for cnet_ipv6_stats_dump
#include <stdint.h>             // for int32_t
#include <stdio.h>              // for printf
#include <getopt.h>

#include "cnet_reg.h"
#include "cnet_rtshow.h"
#include "cne_common.h"        // for __cne_unused
#include "cnet_const.h"        // for CNET_UTILS_PRIO

struct stk_s;

#define RTSHOW_USAGE                              \
    "Usage: rtshow [options]\n"                   \
    "  options:\n"                                \
    "  -4       - Show interface stats\n"         \
    "  -? | -h  - Display the help information\n" \
    "  No options then show the route table\n"    \
    "\n"

int
cnet_rtshow(stk_t *stk, int argc, char **argv)
{
    int opt, ip_stats;
    char *iface = NULL;

    optind   = 0;
    ip_stats = 0;
    while ((opt = getopt(argc, argv, "?h4")) != -1) {
        switch (opt) {
        case 'h':
            /* fall through */
        case '?':
            /* fall through */
        default:
            cne_printf(RTSHOW_USAGE);
            break;

        case '4':
            ip_stats = 4;
            break;

            /* TODO: Add IPv6 support */
        }
    }
    if (optind < argc)
        iface = argv[optind];

    if (stk->ipv6) {
        if (iface == NULL) {
            if (!ip_stats)
                cnet_route6_show();
            else
                cnet_ipv6_stats_dump(stk);
            return 0;
        } else {
            if (!ip_stats)
                cnet_route6_show();
            else
                cnet_ipv6_stats_dump(stk);
        }
    } else {
        if (iface == NULL) {
            if (!ip_stats)
                cnet_route4_show();
            else
                cnet_ipv4_stats_dump(stk);
            return 0;
        } else {
            if (!ip_stats)
                cnet_route4_show();
            else
                cnet_ipv4_stats_dump(stk);
        }
    }

    return 0;
}
