/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef __TXBUFF_H
#define __TXBUFF_H

/**
 * @file
 * Routines and structures to allow an application to send single mbufs or packets
 * while enqueuing the packets to an array and flush the packets to the output port
 * when the number of packets fills the array.
 *
 * Using this method allows for buffered packet to be sent in bulk and not one at a
 * time.
 */

#include <stdint.h>            // for uint16_t, uint32_t
#include <cne_common.h>        // for CNDP_API, CNE_STD_C11
#include <pktmbuf.h>           // for pktmbuf_t

#ifdef __cplusplus
extern "C" {
#endif

struct txbuff;

/**
 * Error callback function for txbuff sends.
 *
 * @param buffer
 *   The txbuff_t pointer.
 * @param unsent
 *   The number of unsent packets on a flush call.
 * @param sent
 *   The number of sent packets on a flush call.
 */
typedef void (*txbuff_error_fn)(struct txbuff *buffer, uint16_t unsent, uint16_t sent);

/**
 * Structure used to buffer packets for future TX
 * Used by APIs txbuff_add and txbuff_flush
 */
typedef struct txbuff {
    CNE_STD_C11
    union {
        void *info;        /**< xskdev_info_t pointer for TXBUFF_XSKDEV_FLAG */
        uint16_t lport_id; /**< lport ID for pktdev API */
    };
    txbuff_error_fn error_cb; /**< TX Buffer error callback function */
    void *userdata;           /**< Userdata for error and count callbacks */
    uint32_t txtype;          /**< the type of txbuff pktdev or xskdev */
    uint16_t size;            /**< Size of buffer for buffered tx */
    uint16_t length;          /**< Number of packets in the array */
    pktmbuf_t *pkts[];        /**< Pending packets to be sent on explicit flush or when full */
} txbuff_t;

/**
 * Types of txbuff transmit routines
 */
enum { TXBUFF_PKTDEV_FLAG = 0, TXBUFF_XSKDEV_FLAG = 1 };

/**
 * Calculate the size of the tx buffer.
 *
 * @param sz
 *   Number of stored packets.
 */
#define TXBUFF_SIZE(sz) (sizeof(txbuff_t) + (sz) * sizeof(pktmbuf_t *))

/**
 * Initialize default values for buffered transmitting and return txbuff pointer for pktdev
 *
 * @param size
 *   Buffer size
 * @param cbfn
 *   Callback on error function, if null use txbuff_drop_callback().
 * @param cb_arg
 *   Argument for callback function.
 * @param lport_id
 *   The lport ID to be used with pktdev_tx_burst() call.
 * @return
 *   NULL on error or pointer to structure txbuff
 */
CNDP_API txbuff_t *txbuff_pktdev_create(uint16_t size, txbuff_error_fn cbfn, void *cb_arg,
                                        uint16_t lport_id);

/**
 * Initialize default values for buffered transmitting and return txbuff pointer for xskdev
 *
 * @param size
 *   Buffer size
 * @param cbfn
 *   Callback on error function, if null use txbuff_drop_callback().
 * @param cb_arg
 *   Argument for callback function.
 * @param xinfo
 *   The xskdev info pointer, used with xskdev_tx_burst() function
 * @return
 *   NULL on error or pointer to structure txbuff
 */
CNDP_API txbuff_t *txbuff_xskdev_create(uint16_t size, txbuff_error_fn cbfn, void *cb_arg,
                                        void *xinfo);

/**
 * Free memory (and any buffered packets) associated with a txbuff
 *
 * @param buffer
 *   Pointer to the txbuff structure
 */
CNDP_API void txbuff_free(txbuff_t *buffer);

/**
 * Configure a callback for buffered packets which cannot be sent
 *
 * Register a specific callback to be called when an attempt is made to send
 * all packets buffered on an ethernet lport, but not all packets can
 * successfully be sent. The callback registered here will be called only
 * from calls to txbuff_add() and txbuff_flush() APIs.
 * The callback configured by default just frees the packets back to the original
 * mempool. If additional behaviour is required, for example, to count dropped
 * packets, or to retry transmission of packets which cannot be sent, this
 * function should be used to register a suitable callback function to implement
 * the desired behaviour.
 *
 * @param buffer
 *   Pointer to the txbuff structure
 * @param callback
 *   The function to be used as the callback
 * @param userdata
 *   Arbitrary parameter to be passed to the callback function
 * @return
 *   0 on success, or -1 on error
 */
CNDP_API int txbuff_set_err_callback(txbuff_t *buffer, txbuff_error_fn callback, void *userdata);

/**
 * Callback function for silently dropping unsent buffered packets.
 *
 * This function can be passed to txbuff_set_err_callback() to
 * adjust the default behavior when buffered packets cannot be sent. This
 * function drops any unsent packets silently and is used by txbuff
 * operations as default behavior.
 *
 * NOTE: this function should not be called directly, instead it should be used
 *       as a callback for packet buffering.
 *
 * @param buffer
 *   Pointer to the txbuff structure
 * @param sent
 *   The number of sent packets in the pkts array
 * @param unsent
 *   The number of unsent packets in the pkts array
 */
CNDP_API void txbuff_drop_callback(txbuff_t *buffer, uint16_t sent, uint16_t unsent);

/**
 * Callback function for counting unsent buffered packets.
 *
 * This function can be passed to txbuff_set_err_callback() to
 * adjust the default behavior when buffered packets cannot be sent. This
 * function drops any unsent packets, but also updates a user-supplied counter
 * to track the overall number of packets dropped. The counter should be an
 * uint64_t variable.
 *
 * NOTE: this function should not be called directly, instead it should be used
 *       as a callback for packet buffering.
 *
 * NOTE: when configuring this function as a callback with
 *       txbuff_set_err_callback(), the final userdata parameter
 *       should point to an uint64_t value.
 *
 * @param buffer
 *   Pointer to the txbuff structure
 * @param sent
 *   The number of sent packets in the pkts array
 * @param unsent
 *   The number of unsent packets in the pkts array
 */
CNDP_API void txbuff_count_callback(txbuff_t *buffer, uint16_t sent, uint16_t unsent);

/**
 * Send any packets queued up for transmission on a lport and HW queue
 *
 * This causes an explicit flush of packets previously buffered via the
 * txbuff_add() function. It returns the number of packets successfully
 * sent to the NIC, and calls the error callback for any unsent packets. Unless
 * explicitly set up otherwise, the default callback simply frees the unsent
 * packets back to the original mempool.
 *
 * @param buffer
 *   Buffer of packets to be transmit.
 * @return
 *   The number of packets successfully sent to the Ethernet device. The error
 *   callback is called for any packets which could not be sent.
 */
CNDP_API uint16_t txbuff_flush(txbuff_t *buffer);

/**
 * Buffer a single packet for future transmission on a lport
 *
 * This function takes a single mbuf/packet and buffers it for later
 * transmission on the particular lport specified. Once the buffer is
 * full of packets, an attempt will be made to transmit all the buffered
 * packets. In case of error, where not all packets can be transmitted, a
 * callback is called with the unsent packets as a parameter. If no callback
 * is explicitly set up, the unsent packets are just freed back to the owning
 * mempool. The function returns the number of packets actually sent i.e.
 * 0 if no buffer flush occurred, otherwise the number of packets successfully
 * flushed
 *
 * @param buffer
 *   Buffer used to collect packets to be sent.
 * @param tx_pkt
 *   Pointer to the packet mbuf to be sent.
 * @return
 *   0 = packet has been buffered for later transmission or packets were flushed,
 *       but none were transmitted
 *   N > 0 = packet has been buffered, and the buffer was subsequently flushed,
 *     causing N packets to be sent, and the error callback to be called for
 *     the rest.
 */
CNDP_API uint16_t txbuff_add(txbuff_t *buffer, pktmbuf_t *tx_pkt);

/**
 * Return the number of pkts in the txbuff list.
 *
 * @param buffer
 *   The txbuff_t pointer
 * @returns
 *   -1 on buffer being NULL or the number of pkts in the list.
 */
static inline int
txbuff_count(txbuff_t *buffer)
{
    return (!buffer) ? -1 : buffer->length;
}

#ifdef __cplusplus
}
#endif

#endif /* __TXBUFF_H */
