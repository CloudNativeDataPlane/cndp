/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef _IPV6_H_
#define _IPV6_H_

#include <stdint.h>        // for uint32_t, uint8_t

#include "seq.h"          // for pkt_seq_t
#include "txgen.h"        // for pktmbuf_t

#ifdef __cplusplus
extern "C" {
#endif

void txgen_ipv6_ctor(pkt_seq_t *pkt, void *hdr);
void txgen_send_ping6(uint32_t pid, uint8_t seq_idx);
void txgen_process_ping6(pktmbuf_t *m, uint32_t pid, uint32_t vlan);

#ifdef __cplusplus
}
#endif

#endif /*  _IPV6_H_ */
