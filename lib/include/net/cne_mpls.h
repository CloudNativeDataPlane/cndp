/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016 6WIND S.A.
 */

#ifndef _CNE_MPLS_H_
#define _CNE_MPLS_H_

/**
 * @file
 *
 * MPLS-related defines
 */

#include <stdint.h>
#include <endian.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * MPLS header.
 */
struct cne_mpls_hdr {
    uint16_t tag_msb; /**< Label(msb). */
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t tag_lsb : 4; /**< Label(lsb). */
    uint8_t tc : 3;      /**< Traffic class. */
    uint8_t bs : 1;      /**< Bottom of stack. */
#else
    uint8_t bs : 1;      /**< Bottom of stack. */
    uint8_t tc : 3;      /**< Traffic class. */
    uint8_t tag_lsb : 4; /**< label(lsb) */
#endif
    uint8_t ttl; /**< Time to live. */
} __attribute__((__packed__));

#ifdef __cplusplus
}
#endif

#endif /* CNE_MPLS_H_ */
