/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_DRV_H
#define __CNET_DRV_H

/**
 * @file
 * CNET Driver routines.
 */

#include <pktdev.h>              // for pktdev_info
#include <net/ethernet.h>        // for ether_addr
#include <cne_atomic.h>          // for atomic_uint_least16_t
#include <stdint.h>              // for uint16_t, uint32_t
#include <net/if.h>

#include "cne_common.h"        // for __cne_cache_aligned
#include "cnet_const.h"        // for iofunc_t

struct cnet;

#ifdef __cplusplus
extern "C" {
#endif

struct netif;

struct drv_entry {
    struct netif *netif;     /**< Pointer to netif structure */
    struct pktdev_info info; /**< pktdev information */
} __cne_cache_aligned;

/**
 * @brief Create the driver structure and initialize it
 *
 * @param cnet
 *   The cnet structure pointer to attach the driver structure
 * @return
 *   -1 on error or 0 on success
 */
int cnet_drv_create(struct cnet *cnet);

/**
 * @brief Destroy the driver structure and initialize it
 *
 * @param cnet
 *   The cnet structure pointer to dettach the driver structure
 * @return
 *   -1 on error or 0 on success
 */
int cnet_drv_destroy(struct cnet *cnet);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_DRV_H */
