/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

#include <pktdev.h>          // for pktdev_rx_burst, pktdev_tx_burst
#include <xskdev.h>          // for xskdev_rx_burst, xskdev_tx_burst
#include "bindings.h"        // Rust bindings

// static linine functions are not currently supported by rust bindgen
// See: https://github.com/rust-lang/rust-bindgen/issues/1344
// Wrap the inline functions in CNE with C functions to generate Rust bindings.
inline uint16_t
_pktdev_rx_burst(uint16_t lport_id, pktmbuf_t **rx_pkts, const uint16_t nb_pkts)
{
    return pktdev_rx_burst(lport_id, rx_pkts, nb_pkts);
}

inline uint16_t
_pktdev_tx_burst(uint16_t lport_id, pktmbuf_t **tx_pkts, uint16_t nb_pkts)
{
    return pktdev_tx_burst(lport_id, tx_pkts, nb_pkts);
}

inline void
_pktmbuf_free_bulk(pktmbuf_t **mbufs, unsigned int count)
{
    return pktmbuf_free_bulk(mbufs, count);
}

inline void
_pktmbuf_info_name_set(pktmbuf_info_t *pi, const char *str)
{
    pktmbuf_info_name_set(pi, str);
}

inline const void *
_pktmbuf_write(const void *buf, uint32_t len, pktmbuf_t *m, uint32_t off)
{
    return pktmbuf_write(buf, len, m, off);
}

inline int
_pktmbuf_alloc_bulk(pktmbuf_info_t *pi, pktmbuf_t **mbufs, unsigned count)
{
    return pktmbuf_alloc_bulk(pi, mbufs, count);
}

inline uint16_t
_xskdev_rx_burst(xskdev_info_t *xi, void **bufs, const uint16_t nb_pkts)
{
    return xskdev_rx_burst(xi, bufs, nb_pkts);
}

inline uint16_t
_xskdev_tx_burst(xskdev_info_t *xi, void **bufs, const uint16_t nb_pkts)
{
    return xskdev_tx_burst(xi, bufs, nb_pkts);
}
