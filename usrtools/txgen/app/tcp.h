/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_TCP_H_
#define _TXGEN_TCP_H_

#include <cne_inet.h>

#include "seq.h"        // for pkt_seq_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 *
 * txgen_tcp_hdr_ctor - TCP header constructor routine.
 *
 * DESCRIPTION
 * Construct a TCP header in the packet buffer provided.
 *
 * RETURNS: Next header location
 *
 * SEE ALSO:
 */
void *txgen_tcp_hdr_ctor(pkt_seq_t *pkt, void *hdr, int type);

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_TCP_H_ */
