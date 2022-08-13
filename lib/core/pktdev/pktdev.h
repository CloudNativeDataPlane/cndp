/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef __PKTDEV_H
#define __PKTDEV_H

#include <cne_common.h>
#include <errno.h>            // for EINVAL, ENOTSUP
#include <stddef.h>           // for NULL
#include <stdint.h>           // for uint16_t, uint32_t, uint64_t, uint8_t
#include <x86intrin.h>        // _mm_shuffle_xxx
#include <mempool.h>          // for mempool_t
#include <pktmbuf.h>          // for pktmbuf_t
#include <emmintrin.h>        // for _mm_loadu_si128, _mm_set_epi8, _mm_storeu_s...
#include <stdbool.h>          // for bool
#include <tmmintrin.h>        // for _mm_shuffle_epi8

/**
 * @file
 *   A simple Ethernet interface routines for AF_XDP and related virtual interfaces.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define PKTDEV_FOREACH(x) for (int x = 0; x < CNE_MAX_ETHPORTS; x++)

/**
 * Fallback default preferred Rx/Tx lport parameters.
 * These are used if an application requests default parameters
 * but the PMD does not provide preferred values.
 */
#define PKTDEV_FALLBACK_RX_RINGSIZE 512
#define PKTDEV_FALLBACK_TX_RINGSIZE 512
#define PKTDEV_FALLBACK_RX_NBQUEUES 1
#define PKTDEV_FALLBACK_TX_NBQUEUES 1
#define PKTDEV_ADMIN_STATE_DOWN     0xFFFF

#include <cne_lport.h>

/**
 * Ethernet device RX queue information structure.
 * Used to retrieve information about configured queue.
 */
struct pktdev_rxq_info {
    mempool_t *mp;    /**< mempool used by that queue. */
    uint16_t nb_desc; /**< configured number of RXDs. */
} __cne_cache_min_aligned;

/**
 * Ethernet device TX queue information structure.
 * Used to retrieve information about configured queue.
 */
struct pktdev_txq_info {
    uint16_t nb_desc; /**< configured number of TXDs. */
} __cne_cache_min_aligned;

/**
 * Preferred Rx/Tx lport parameters.
 * There are separate instances of this structure for transmission
 * and reception respectively.
 */
struct pktdev_portconf {
    uint16_t burst_size; /**< Device-preferred burst size */
    uint16_t ring_size;  /**< Device-preferred size of queue rings */
};

/**
 * Ethernet device information
 */

/**
 * A structure used to retrieve the contextual information of
 * an Ethernet device, such as the controlling driver of the
 * device, etc...
 */
struct pktdev_info {
    const char *driver_name; /**< Device Driver name. */
    unsigned int if_index;   /**< Index to bound host interface, or 0 if none.
         Use if_indextoname() to translate into an interface name. */
    bool admin_state;        /**< State of the interface up or down */
    uint16_t min_mtu;        /**< Minimum MTU allowed */
    uint16_t max_mtu;        /**< Maximum MTU allowed */
    uint32_t min_rx_bufsize; /**< Minimum size of RX buffer. */
    uint32_t max_rx_pktlen;  /**< Maximum configurable length of RX pkt. */
    uint32_t min_tx_bufsize; /**< Minimum size of TX buffer. */
    uint8_t hash_key_size;   /**< Hash key size in bytes */
    /** Bit mask of RSS offloads, the bit offset also means flow type */
    uint32_t speed_capa; /**< Supported speeds bitmap (ETH_LINK_SPEED_). */
    /** Rx parameter recommendations */
    struct pktdev_portconf default_rxportconf;
    /** Tx parameter recommendations */
    struct pktdev_portconf default_txportconf;
    /** Generic device capabilities (PKTDEV_DEV_CAPA_). */
    uint64_t dev_capa;
} __cne_cache_aligned;

#include <pktdev_api.h>         // for pktdev_admin_state
#include <pktdev_core.h>        // for cne_pktdev, pktdev_data, pktdev_devices

#include "cne_common.h"        // for CNE_MAX_ETHPORTS, __cne_cache_min_aligned
#include "cne_log.h"           // for CNE_LOG_ERR

// IWYU pragma: no_forward_declare cne_mempool

/**
 *
 * Retrieve a burst of input packets from a receive queue of an Ethernet/virtual
 * device. The retrieved packets are stored in *pktmbuf* structures whose
 * pointers are supplied in the *rx_pkts* array.
 *
 * The pktdev_rx_burst() function loops, parsing the RX ring of the
 * receive queue, up to *nb_pkts* packets, and for each completed RX
 * descriptor in the ring, it performs the following operations:
 *
 * - Initialize the *pktmbuf* data structure associated with the
 *   RX descriptor according to the information provided by the NIC into
 *   that RX descriptor.
 *
 * - Store the *pktmbuf* data structure into the next entry of the
 *   *rx_pkts* array.
 *
 * - Replenish the RX descriptor with a new *pktmbuf* buffer
 *   allocated from the memory pool associated with the receive queue at
 *   initialization time.
 *
 * The pktdev_rx_burst() function returns the number of packets
 * actually retrieved, which is the number of *pktmbuf* data structures
 * effectively supplied into the *rx_pkts* array.
 * A return value equal to *nb_pkts* indicates that the RX queue contained
 * at least *rx_pkts* packets, and this is likely to signify that other
 * received packets remain in the input queue. Applications implementing
 * a "retrieve as much received packets as possible" policy can check this
 * specific case and keep invoking the pktdev_rx_burst() function until
 * a value less than *nb_pkts* is returned.
 *
 * This receive method has the following advantages:
 *
 * - It allows a run-to-completion network stack engine to retrieve and
 *   to immediately process received packets in a fast burst-oriented
 *   approach, avoiding the overhead of unnecessary intermediate packet
 *   queue/dequeue operations.
 *
 * - Conversely, it also allows an asynchronous-oriented processing
 *   method to retrieve bursts of received packets and to immediately
 *   queue them for further parallel processing by another logical core,
 *   for instance. However, instead of having received packets being
 *   individually queued by the driver, this approach allows the caller
 *   of the pktdev_rx_burst() function to queue a burst of retrieved
 *   packets at a time and therefore dramatically reduce the cost of
 *   enqueue/dequeue operations per packet.
 *
 * - It allows the pktdev_rx_burst() function of the driver to take
 *   advantage of burst-oriented hardware features (CPU cache,
 *   prefetch instructions, and so on) to minimize the number of CPU
 *   cycles per packet.
 *
 * To summarize, the proposed receive API enables many
 * burst-oriented optimizations in both synchronous and asynchronous
 * packet processing environments with no overhead in both cases.
 *
 * The pktdev_rx_burst() function does not provide any error
 * notification to avoid the corresponding overhead. As a hint, the
 * upper-level application might check the status of the device link once
 * being systematically returned a 0 value for a given number of tries.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @param rx_pkts
 *   The address of an array of pointers to *pktmbuf* structures that
 *   must be large enough to store *nb_pkts* pointers in it.
 * @param nb_pkts
 *   The maximum number of packets to retrieve.
 * @return
 *   The number of packets actually retrieved, which is the number
 *   of pointers to *pktmbuf* structures effectively supplied to the
 *   *rx_pkts* array.
 *   returns 0xFFFF on admin_state_down
 */
static inline uint16_t
pktdev_rx_burst(uint16_t lport_id, pktmbuf_t **rx_pkts, const uint16_t nb_pkts)
{
    struct cne_pktdev *dev = &pktdev_devices[lport_id];
    uint16_t nb_rx;

#ifdef PKTDEV_DEBUG
    if (dev->rx_pkt_burst == NULL)
        return 0;
#endif

    /* Check packet stream status */
    if (!pktdev_admin_state(lport_id)) {
        CNE_DEBUG("Packet stream is disabled for '%d'\n", lport_id);
        return PKTDEV_ADMIN_STATE_DOWN;
    }

    nb_rx = (*dev->rx_pkt_burst)(dev->data->rx_queue, rx_pkts, nb_pkts);

    return nb_rx;
}

/**
 * Send a burst of output packets on a transmit queue of an Ethernet/virtual device.
 *
 * The pktdev_tx_burst() function is invoked to transmit output packets
 * on the output queue *queue_id* of the device designated by its *lport_id*.
 *
 * The *nb_pkts* parameter is the number of packets to send which are
 * supplied in the *tx_pkts* array of *pktmbuf* structures, each of them
 * allocated from a pool created with pktmbuf_pool_create().
 * The pktdev_tx_burst() function loops, sending *nb_pkts* packets,
 * up to the number of transmit descriptors available in the TX ring of the
 * transmit queue.
 * For each packet to send, the pktdev_tx_burst() function performs
 * the following operations:
 *
 * - Pick up the next available descriptor in the transmit ring.
 *
 * - Free the network buffer previously sent with that descriptor, if any.
 *
 * - Initialize the transmit descriptor with the information provided
 *   in the *pktmbuf data structure.
 *
 * In the case of a segmented packet composed of a list of *pktmbuf* buffers,
 * the pktdev_tx_burst() function uses several transmit descriptors
 * of the ring.
 *
 * The pktdev_tx_burst() function returns the number of packets it
 * actually sent. A return value equal to *nb_pkts* means that all packets
 * have been sent, and this is likely to signify that other output packets
 * could be immediately transmitted again. Applications that implement a
 * "send as many packets to transmit as possible" policy can check this
 * specific case and keep invoking the pktdev_tx_burst() function until
 * a value less than *nb_pkts* is returned.
 *
 * It is the responsibility of the pktdev_tx_burst() function to
 * transparently free the memory buffers of packets previously sent.
 *
 * @see pktdev_tx_prepare to perform some prior checks or adjustments
 * for offloads.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @param tx_pkts
 *   The address of an array of *nb_pkts* pointers to *pktmbuf* structures
 *   which contain the output packets.
 * @param nb_pkts
 *   The maximum number of packets to transmit.
 * @return
 *   The number of output packets actually stored in transmit descriptors of
 *   the transmit ring. The return value can be less than the value of the
 *   *tx_pkts* parameter when the transmit ring is full or has been filled up.
 *   returns 0xFFFF on admin_state_down
 */
static inline uint16_t
pktdev_tx_burst(uint16_t lport_id, pktmbuf_t **tx_pkts, uint16_t nb_pkts)
{
    struct cne_pktdev *dev;

#ifdef PKTDEV_DEBUG
    if (lport_id >= CNE_MAX_ETHPORTS)
        return 0;
#endif

    dev = &pktdev_devices[lport_id];

#ifdef PKTDEV_DEBUG
    if (dev->tx_pkt_burst == NULL)
        return 0;
#endif

    /* Check packet stream status */
    if (!pktdev_admin_state(lport_id)) {
        CNE_DEBUG("Packet stream is disabled for '%d'\n", lport_id);
        return PKTDEV_ADMIN_STATE_DOWN;
    }

    return (*dev->tx_pkt_burst)(dev->data->tx_queue, tx_pkts, nb_pkts);
}

/**
 * Process a burst of output packets on a transmit queue of an Ethernet device.
 *
 * The pktdev_tx_prepare() function is invoked to prepare output packets to be
 * transmitted on the output queue *queue_id* of the device designated
 * by its *lport_id*.
 * The *nb_pkts* parameter is the number of packets to be prepared which are
 * supplied in the *tx_pkts* array of *pktmbuf* structures, each of them
 * allocated from a pool created with pktmbuf_pool_create().
 * For each packet to send, the pktdev_tx_prepare() function performs
 * the following operations:
 *
 * - Check if packet meets devices requirements for tx offloads.
 *
 * - Check limitations about number of segments.
 *
 * - Check additional requirements when debug is enabled.
 *
 * - Update and/or reset required checksums when tx offload is set for packet.
 *
 * Since this function can modify packet data, provided mbufs must be safely
 * writable (e.g. modified data cannot be in shared segment).
 *
 * The pktdev_tx_prepare() function returns the number of packets ready to be
 * sent. A return value equal to *nb_pkts* means that all packets are valid and
 * ready to be sent, otherwise stops processing on the first invalid packet and
 * leaves the rest packets untouched.
 *
 * When this functionality is not implemented in the driver, all packets are
 * are returned untouched.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 *   The value must be a valid lport id.
 * @param tx_pkts
 *   The address of an array of *nb_pkts* pointers to *pktmbuf* structures
 *   which contain the output packets.
 * @param nb_pkts
 *   The maximum number of packets to process.
 * @return
 *   The number of packets correct and ready to be sent. The return value can be
 *   less than the value of the *tx_pkts* parameter when some packet doesn't
 *   meet devices requirements with errno set appropriately:
 *   - EINVAL: offload flags are not correctly set
 *   - ENOTSUP: the offload feature is not supported by the hardware
 */
static inline uint16_t
pktdev_tx_prepare(uint16_t lport_id, pktmbuf_t **tx_pkts, uint16_t nb_pkts)
{
    struct cne_pktdev *dev;

    dev = &pktdev_devices[lport_id];

    if (!dev->tx_pkt_prepare)
        return nb_pkts;

    return (*dev->tx_pkt_prepare)(dev->data->tx_queue, tx_pkts, nb_pkts);
}

/**
 * Swap the MAC addresses in a ethernet packet using AVX instructions
 *
 * @param data
 *    Pointer to the start of the L2 header
 * @return
 *    The MAC addresses will be swapped.
 */
static inline void
pktdev_mac_swap(void *data)
{
    /**
     * shuffle mask be used to shuffle the 16 bytes.
     * byte 0-5 wills be swapped with byte 6-11.
     * byte 12-15 will keep unchanged.
     */
    __m128i shfl_msk = _mm_set_epi8(15, 14, 13, 12, 5, 4, 3, 2, 1, 0, 11, 10, 9, 8, 7, 6);

    __m128i hdr = _mm_loadu_si128((const __m128i_u *)data);
    hdr         = _mm_shuffle_epi8(hdr, shfl_msk);
    _mm_storeu_si128((__m128i_u *)data, hdr);
}

#ifdef __cplusplus
}
#endif

#endif /* __PKTDEV_H */
