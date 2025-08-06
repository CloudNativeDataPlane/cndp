/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _CNE_NET_CRC_H_
#define _CNE_NET_CRC_H_

/**
 * @file
 */

#include <stdint.h>        // for uint32_t
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** CRC types */
enum cne_net_crc_type { CNE_NET_CRC16_CCITT = 0, CNE_NET_CRC32_ETH, CNE_NET_CRC_REQS };

/** CRC compute algorithm */
enum cne_net_crc_alg {
    CNE_NET_CRC_SCALAR = 0,
    CNE_NET_CRC_SSE42,
    CNE_NET_CRC_NEON,
};

/**
 * This API set the CRC computation algorithm (i.e. scalar version,
 * x86 64-bit sse4.2 intrinsic version, etc.) and internal data
 * structure.
 *
 * @param alg
 *   This parameter is used to select the CRC implementation version.
 *   - CNE_NET_CRC_SCALAR
 *   - CNE_NET_CRC_SSE42 (Use 64-bit SSE4.2 intrinsic)
 *   - CNE_NET_CRC_NEON (Use ARM Neon intrinsic)
 */
void cne_net_crc_set_alg(enum cne_net_crc_alg alg);

/**
 * CRC compute API
 *
 * @param data
 *   Pointer to the packet data for CRC computation
 * @param data_len
 *   Data length for CRC computation
 * @param type
 *   CRC type (enum cne_net_crc_type)
 *
 * @return
 *   CRC value
 */
uint32_t cne_net_crc_calc(const void *data, uint32_t data_len, enum cne_net_crc_type type);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_NET_CRC_H_ */
