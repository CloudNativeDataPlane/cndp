/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2025 Intel Corporation.
 */

#ifndef _BINDINGS_H_
#define _BINDINGS_H_

/**
 *
 * Wrapper functions for CNE inline functions required for Rust Bindgen tool.
 *
 */

#include <stdint.h>         // for uint64_t, uint32_t, uint8_t
#include <pktmbuf.h>        // for pktmbuf_pool_create, pktmbuf_info_t
#include <xskdev.h>         // for xskdev_info_t

#ifdef __cplusplus
extern "C" {
#endif

uint16_t _pktdev_rx_burst(uint16_t lport_id, pktmbuf_t **rx_pkts, const uint16_t nb_pkts);

uint16_t _pktdev_tx_burst(uint16_t lport_id, pktmbuf_t **tx_pkts, uint16_t nb_pkts);

void _pktmbuf_free_bulk(pktmbuf_t **mbufs, unsigned int count);

void _pktmbuf_info_name_set(pktmbuf_info_t *pi, const char *str);

const void *_pktmbuf_write(const void *buf, uint32_t len, pktmbuf_t *m, uint32_t off);

int _pktmbuf_alloc_bulk(pktmbuf_info_t *pi, pktmbuf_t **mbufs, unsigned count);

uint16_t _xskdev_rx_burst(xskdev_info_t *xi, void **bufs, const uint16_t nb_pkts);

uint16_t _xskdev_tx_burst(xskdev_info_t *xi, void **bufs, uint16_t nb_pkts);

#ifdef __cplusplus
}
#endif

#endif /* _BINDINGS_H_ */
