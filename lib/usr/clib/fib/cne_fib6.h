/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2023 Intel Corporation
 */

#ifndef _CNE_FIB6_H_
#define _CNE_FIB6_H_

/**
 * @file
 *
 * CNE FIB6 library.
 *
 * FIB (Forwarding information base) implementation
 * for IPv6 Longest Prefix Match
 */
// IWYU pragma: no_include "private_fib6.h"

#include <stdint.h>        // for uint8_t, uint64_t, uint32_t
#include <cne_common.h>

#include <cne_fib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cne_fib6;
struct cne_rib6;

/**
 * Create FIB
 *
 * @param name
 *  FIB name
 * @param conf
 *  Structure containing the configuration
 * @return
 *  Handle to FIB object on success or NULL on error.
 */
struct cne_fib6 *cne_fib6_create(const char *name, struct cne_fib_conf *conf);

/**
 * Free an FIB object.
 *
 * @param fib
 *   FIB object handle
 * @return
 *   None
 */
void cne_fib6_free(struct cne_fib6 *fib);

/**
 * Add a route to the FIB.
 *
 * @param fib
 *   FIB object handle
 * @param ip
 *   IPv6 prefix address to be added to the FIB
 * @param depth
 *   Prefix length
 * @param next_hop
 *   Next hop to be added to the FIB
 * @return
 *   0 on success, negative value otherwise
 */
int cne_fib6_add(struct cne_fib6 *fib, const uint8_t ip[IPV6_ADDR_LEN], uint8_t depth,
                 uint64_t next_hop);

/**
 * Delete a rule from the FIB.
 *
 * @param fib
 *   FIB object handle
 * @param ip
 *   IPv6 prefix address to be deleted from the FIB
 * @param depth
 *   Prefix length
 * @return
 *   0 on success, negative value otherwise
 */
int cne_fib6_delete(struct cne_fib6 *fib, const uint8_t ip[IPV6_ADDR_LEN], uint8_t depth);

/**
 * Lookup multiple IP addresses in the FIB.
 *
 * @param fib
 *   FIB object handle
 * @param ips
 *   Array of IPv6s to be looked up in the FIB
 * @param next_hops
 *   Next hop of the most specific rule found for IP.
 *   This is an array of eight byte values.
 *   If the lookup for the given IP failed, then corresponding element would
 *   contain default nexthop value configured for a FIB.
 * @param n
 *   Number of elements in ips (and next_hops) array to lookup.
 *  @return
 *   -EINVAL for incorrect arguments, otherwise 0
 */
int cne_fib6_lookup_bulk(struct cne_fib6 *fib, uint8_t ips[][IPV6_ADDR_LEN], uint64_t *next_hops,
                         int n);

/**
 * Get pointer to the dataplane specific struct
 *
 * @param fib
 *   FIB6 object handle
 * @return
 *   Pointer on the dataplane struct on success
 *   NULL othervise
 */
void *cne_fib6_get_dp(struct cne_fib6 *fib);

/**
 * Get pointer to the RIB6
 *
 * @param fib
 *   FIB object handle
 * @return
 *   Pointer on the RIB6 on success
 *   NULL othervise
 */
struct cne_rib6 *cne_fib6_get_rib(struct cne_fib6 *fib);

/**
 * Set lookup function based on type
 *
 * @param fib
 *   FIB object handle
 * @param type
 *   type of lookup function
 *
 * @return
 *   0 on success
 *   -EINVAL on failure
 */
int cne_fib6_select_lookup(struct cne_fib6 *fib, enum cne_fib_lookup_type type);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_FIB6_H_ */
