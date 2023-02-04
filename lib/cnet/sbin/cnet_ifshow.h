/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
 */

#ifndef __CNET_IFSHOW_H
#define __CNET_IFSHOW_H

/**
 * @file
 * CNET interface show routines.
 */

#include <sys/queue.h>
#include <stdint.h>        // for uint32_t
#include <stdio.h>         // for printf
#include <net/if.h>

#include <cne_common.h>
#include <cnet_netif.h>        // for _IFF_ALLMULTI, _IFF_BROADCAST, _IFF_LINK0

#ifdef __cplusplus
extern "C" {
#endif

static inline void
cnet_print_flags(uint32_t flags)
{
    const char *ifflags[] = {"up",         "broadcast", "debug",     "loopback", "p2p",
                             "notrailers", "running",   "noarp",     "promisc",  "allmulti",
                             "master",     "slave",     "multicast", "portsel",  "automedia",
                             "dynamic",    "lowerup"};

    cne_printf("[magenta]flags[]:< [cyan]");
    for (int i = 0; i < cne_countof(ifflags); i++)
        if (flags & (1UL << i))
            cne_printf("%s ", ifflags[i]);
    cne_printf("[]>");
}

/**
 * @brief Show the configuration information of a given interface or all if not given.
 *
 * @param ifname
 *   Interface name to show or NULL to show all interfaces.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_ifshow(char *ifname);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_IFSHOW_H */
