/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_ETHER_H
#define __CNET_ETHER_H

/**
 * @file
 * CNET Ethernet routines.
 */

#include <stdint.h>
#include <net/ethernet.h>

#ifdef __cplusplus
extern "C" {
#endif

/* eth_swap(uint16_t * to, uint16_t * from) - Swap two 16 bit values */
static inline void
eth_swap(uint16_t *t, uint16_t *f)
{
    uint16_t v;

    v  = *t;
    *t = *f;
    *f = v;
}

/* eth_addr_swap( struct ether_addr * to, struct ether_addr * from ) - Swap two
   ethernet addresses */
static inline void
eth_addr_swap(struct ether_addr *t, struct ether_addr *f)
{
    uint16_t *d = (uint16_t *)t;
    uint16_t *s = (uint16_t *)f;

    eth_swap(d++, s++);
    eth_swap(d++, s++);
    eth_swap(d, s);
}

#ifdef __cplusplus
}
#endif

#endif /* __CNET_ETHER_H */
