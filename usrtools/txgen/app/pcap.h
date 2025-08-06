/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _TXGEN_PCAP_H_
#define _TXGEN_PCAP_H_

/**
 * @file
 */

#include <_pcap.h>        // for pcap_info_t

#include "pktmbuf.h"        // for pktmbuf_t

#ifdef __cplusplus
extern "C" {
#endif

struct port_info_s;

/**
 *
 * txgen_pcap_mbuf_ctor - Callback routine to construct PCAP packets.
 *
 * DESCRIPTION
 * Callback routine to construct a set of PCAP packet buffers.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void txgen_pcap_mbuf_ctor(struct port_info_s *info, pktmbuf_t *m);

/**
 *
 * txgen_pcap_parse - Parse a PCAP file.
 *
 * DESCRIPTION
 * Parse a pcap file into packet buffers.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
int txgen_pcap_parse(pcap_info_t *pcap, struct port_info_s *info);

/**
 *
 * txgen_page_pcap - Display the PCAP data page.
 *
 * DESCRIPTION
 * Display the PCAP data page for a given port.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void txgen_page_pcap(struct port_info_s *info);

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_PCAP_H_ */
