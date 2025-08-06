/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _PRIVATE_FIB6_H_
#define _PRIVATE_FIB6_H_

/**
 * @file
 *
 * CNE FIB6 private information.
 *
 * FIB (Forwarding information base) implementation
 * for IPv6 Longest Prefix Match
 */

#include <stdint.h>

#include <cne_common.h>
#include "cne_fib6.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum depth value possible for IPv6 FIB. */
#define CNE_FIB6_MAXDEPTH 128

struct cne_fib6;
struct cne_rib6;

/** Modify FIB function */
typedef int (*cne_fib6_modify_fn_t)(struct cne_fib6 *fib, const uint8_t ip[IPV6_ADDR_LEN],
                                    uint8_t depth, uint64_t next_hop, int op);
/** FIB bulk lookup function */
typedef void (*cne_fib6_lookup_fn_t)(void *fib, uint8_t ips[][IPV6_ADDR_LEN], uint64_t *next_hops,
                                     const unsigned int n);

#ifdef __cplusplus
}
#endif

#endif /* _PRIVATE_FIB6_H_ */
