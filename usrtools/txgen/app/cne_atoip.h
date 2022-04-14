/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

/**
 * @file
 *
 * String-related utility functions for IP addresses
 */

#ifndef _ATOIP_H_
#define _ATOIP_H_

#include <netinet/in.h>        // for in_addr
#include <stdint.h>            // for uint8_t

#ifdef __cplusplus
extern "C" {
#endif

#define _IPADDR_V4      0x01
#define _IPADDR_V6      0x02
#define _IPADDR_NETWORK 0x04

#define _INADDRSZ    4
#define _IN6ADDRSZ   16
#define _PREFIXMAX   128
#define _V4PREFIXMAX 32

struct _ipaddr {
    uint8_t family;
    union {
        struct in_addr ipv4;
    };
    unsigned int prefixlen; /* in case of network only */
};

/**
 * Convert an IPv4/v6 address into a binary value.
 *
 * @param buf
 *   Location of string to convert
 * @param flags
 *   Set of flags for converting IPv4/v6 addresses and netmask.
 * @param res
 *   Location to put the results
 * @param ressize
 *   Length of res in bytes.
 * @return
 *   0 on OK and -1 on error
 */
int _atoip(const char *buf, int flags, void *res, unsigned ressize);

#ifdef __cplusplus
}
#endif

#endif /* _ATOIP_H_ */
