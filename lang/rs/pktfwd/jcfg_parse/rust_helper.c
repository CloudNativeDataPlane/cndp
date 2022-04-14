/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include "rust_helper.h"

// static linine functions are not currently supported by rust bindgen
// See: https://github.com/rust-lang/rust-bindgen/issues/1344
uint16_t
pktdev_rx_burst_fn(uint16_t lport_id, pktmbuf_t **rx_pkts, const uint16_t nb_pkts)
{
    return pktdev_rx_burst(lport_id, rx_pkts, nb_pkts);
}

uint16_t
pktdev_tx_burst_fn(uint16_t lport_id, pktmbuf_t **tx_pkts, uint16_t nb_pkts)
{
    return pktdev_tx_burst(lport_id, tx_pkts, nb_pkts);
}

void
pktmbuf_free_bulk_fn(pktmbuf_t **mbufs, unsigned int count)
{
    return pktmbuf_free_bulk(mbufs, count);
}

void
swap_mac_addresses_pktmbuf(pktmbuf_t *pkt_mbuf)
{
    uint8_t *data = (uint8_t *)(pkt_mbuf->buf_addr) + pkt_mbuf->data_off;
    swap_mac_addresses(data);
}

void
swap_mac_addresses(uint8_t *data)
{
    struct ether_header *eth    = (struct ether_header *)data;
    struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
    struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
    struct ether_addr tmp;

    tmp       = *src_addr;
    *src_addr = *dst_addr;
    *dst_addr = tmp;
}
