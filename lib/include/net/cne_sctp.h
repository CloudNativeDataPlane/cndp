/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.
 * Copyright (c) 2019-2022 Intel Corporation.
 * All rights reserved.
 */

/**
 * @file
 *
 * SCTP-related defines
 */

#ifndef _CNE_SCTP_H_
#define _CNE_SCTP_H_

#include <stdint.h>

#include <cne_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SCTP Header
 */
struct cne_sctp_hdr {
    cne_be16_t src_port; /**< Source port. */
    cne_be16_t dst_port; /**< Destin port. */
    cne_be32_t tag;      /**< Validation tag. */
    cne_be32_t cksum;    /**< Checksum. */
} __attribute__((__packed__));

#ifdef __cplusplus
}
#endif

#endif /* CNE_SCTP_H_ */
