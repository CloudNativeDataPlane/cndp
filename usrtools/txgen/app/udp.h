/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_UDP_H_
#define _TXGEN_UDP_H_

#include <cne_inet.h>

#include "seq.h"        // for pkt_seq_t

#ifdef __cplusplus
extern "C" {
#endif

#define VXLAN_PORT_ID 4789
/**
 *
 * txgen_udp_hdr_ctor - UDP header constructor routine.
 *
 * DESCRIPTION
 * Construct the UDP header in a packer buffer.
 *
 * RETURNS: Next header location
 *
 * SEE ALSO:
 */
void *txgen_udp_hdr_ctor(pkt_seq_t *pkt, void *hdr, int type);

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_UDP_H_ */
