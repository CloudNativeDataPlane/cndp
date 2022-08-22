/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_IPV4_H_
#define _TXGEN_IPV4_H_

#include <stdint.h>        // for uint32_t, uint8_t

#include "seq.h"          // for pkt_seq_t
#include "txgen.h"        // for pktmbuf_t

#ifdef __cplusplus
extern "C" {
#endif

void txgen_ipv4_ctor(pkt_seq_t *pkt, void *hdr);
void txgen_send_ping4(uint32_t pid, uint8_t seq_idx);
void txgen_process_ping4(pktmbuf_t *m, uint32_t pid, uint32_t vlan);

#ifdef __cplusplus
}
#endif

#endif /*  _TXGEN_IPV4_H_ */
