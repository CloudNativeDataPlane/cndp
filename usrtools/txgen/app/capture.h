/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation.
 */

#ifndef _TXGEN_CAPTURE_H_
#define _TXGEN_CAPTURE_H_

#include <stddef.h>        // for size_t
#include <inttypes.h>
#include <pktmbuf.h>        // for pktmbuf_info_t, pktmbuf_t
#include <stdint.h>         // for uint16_t, uint32_t, uint64_t, uint8_t

#include "port-cfg.h"        // for port_info_t

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cap_hdr_s {
    uint64_t tstamp;
    uint16_t pkt_len;
    uint16_t data_len;
    uint8_t pkt[0];
} cap_hdr_t;

/* packet capture data */
typedef struct capture_s {
    pktmbuf_info_t *mp; /**< Memory region to store packets */
    cap_hdr_t *tail;    /**< Current tail pointer in the pkt buffer */
    cap_hdr_t *end;     /**< Points to just before the end[-1] of the buffer */
    size_t used;        /**< Memory used by captured packets */
    uint16_t port;      /**< port for this memzone */
} capture_t;

/* Capture initialization */
void txgen_packet_capture_init(capture_t *capture);        //, int socket_id);

/* Enable/disable capture for port */
void txgen_set_capture(port_info_t *info, uint32_t onOff);

/* Perform capture of packets */
void txgen_packet_capture_bulk(pktmbuf_t **pkts, uint32_t nb_dump, capture_t *capture);

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_CAPTURE_H_ */
