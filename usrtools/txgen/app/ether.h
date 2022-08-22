/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_ETHER_H_
#define _TXGEN_ETHER_H_

#include <pktdev.h>

#include "seq.h"              // for pkt_seq_t
#include "cne_lport.h"        // for lport_stats_t

struct cne_ether_hdr;

#ifdef __cplusplus
extern "C" {
#endif

typedef lport_stats_t eth_stats_t;

struct port_info_s;

char *txgen_ether_hdr_ctor(struct port_info_s *info, pkt_seq_t *pkt, struct cne_ether_hdr *eth);

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_ETHER_H_ */
