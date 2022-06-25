/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _RUSTHELPER_H_
#define _RUSTHELPER_H_

/**
 * @file
 *
 * Wrapper functions for CNDP inline functions required for Rust Bindgen tool.
 *
 */

#include <stdint.h>         // for uint64_t, uint32_t, uint8_t
#include <strings.h>        // for strcasecmp
#include <stdbool.h>        // for bool
#include <pktdev.h>         // for pktdev_rx_burst, pktdev_tx_burst
#include <pktmbuf.h>        // for pktmbuf_pool_create, pktmbuf_info_t

#ifdef __cplusplus
extern "C" {
#endif

uint16_t pktdev_rx_burst_fn(uint16_t lport_id, pktmbuf_t **rx_pkts, const uint16_t nb_pkts);

uint16_t pktdev_tx_burst_fn(uint16_t lport_id, pktmbuf_t **tx_pkts, uint16_t nb_pkts);

void pktmbuf_free_bulk_fn(pktmbuf_t **mbufs, unsigned int count);

void swap_mac_addresses(uint8_t *data);

void swap_mac_addresses_pktmbuf(pktmbuf_t *pkt_mbuf);

#ifdef __cplusplus
}
#endif

#endif /* _RUSTHELPER_H_ */
