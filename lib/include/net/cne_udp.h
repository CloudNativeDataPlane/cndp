/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.
 * Copyright (c) 2019-2022 Intel Corporation.
 * All rights reserved.
 */

#ifndef _CNE_UDP_H_
#define _CNE_UDP_H_

/**
 * @file
 *
 * UDP-related defines
 */

#include <stdint.h>

#include <cne_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * UDP Header
 */
struct cne_udp_hdr {
    cne_be16_t src_port;    /**< UDP source port. */
    cne_be16_t dst_port;    /**< UDP destination port. */
    cne_be16_t dgram_len;   /**< UDP datagram length */
    cne_be16_t dgram_cksum; /**< UDP datagram checksum */
} __attribute__((__packed__));

#ifdef __cplusplus
}
#endif

#endif /* CNE_UDP_H_ */
