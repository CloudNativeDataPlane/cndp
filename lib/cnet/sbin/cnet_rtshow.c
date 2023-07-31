/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
 */

#include <string.h>             // for strcmp
#include <cnet.h>               // for cnet_add_instance
#include <cnet_netif.h>         // for cnet_netif_from_index
#include <cnet_route.h>         // for
#include <cnet_route4.h>        // for cnet_route4_show
#include <cnet_route6.h>        // for cnet_route6_show
#include <cnet_ipv4.h>          // for cnet_ipv4_stats_dump
#include <cnet_ipv6.h>          // for cnet_ipv6_stats_dump
#include <stdint.h>             // for int32_t
#include <stdio.h>              // for printf
#include <getopt.h>

#include "cnet_reg.h"
#include "cnet_rtshow.h"
#include "cne_common.h"        // for __cne_unused
#include "cnet_const.h"        // for CNET_UTILS_PRIO

int
cnet_rtshow(int ip4, int ip6)
{
    if (ip4)
        cnet_route4_show();
    if (ip6)
        cnet_route6_show();

    return 0;
}
