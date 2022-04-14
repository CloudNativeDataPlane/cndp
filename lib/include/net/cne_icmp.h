/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.
 * Copyright (c) 2013 6WIND S.A.
 * All rights reserved.
 */

#ifndef _CNE_ICMP_H_
#define _CNE_ICMP_H_

/**
 * @file
 *
 * ICMP-related defines
 */

#include <stdint.h>

#include <cne_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ICMP Header
 */
struct cne_icmp_hdr {
    uint8_t icmp_type;      /* ICMP packet type. */
    uint8_t icmp_code;      /* ICMP packet code. */
    cne_be16_t icmp_cksum;  /* ICMP packet checksum. */
    cne_be16_t icmp_ident;  /* ICMP packet identifier. */
    cne_be16_t icmp_seq_nb; /* ICMP packet sequence number. */
} __attribute__((__packed__));

/* ICMP packet types */
#define CNE_IP_ICMP_ECHO_REPLY   0
#define CNE_IP_ICMP_ECHO_REQUEST 8

#ifdef __cplusplus
}
#endif

#endif /* CNE_ICMP_H_ */
