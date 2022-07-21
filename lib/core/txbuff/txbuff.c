/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <stdlib.h>         // for free, calloc, NULL
#include <stdint.h>         // for uint16_t, uint64_t
#include <pktmbuf.h>        // for pktmbuf_free_bulk, pktmbuf_t
#include <pktdev.h>         // for pktdev_tx_burst
#include <xskdev.h>         // for xskdev_tx_burst

#include "txbuff.h"

void
txbuff_drop_callback(txbuff_t *buffer, uint16_t sent, uint16_t unsent)
{
    if (buffer)
        pktmbuf_free_bulk(&buffer->pkts[sent], unsent);
}

void
txbuff_count_callback(txbuff_t *buffer, uint16_t sent, uint16_t unsent)
{
    if (buffer) {
        txbuff_drop_callback(buffer, sent, unsent);

        if (buffer->userdata)
            *((uint64_t *)buffer->userdata) += unsent;
    }
}

int
txbuff_set_err_callback(txbuff_t *buffer, txbuff_error_fn cbfn, void *userdata)
{
    if (!buffer)
        return -1;

    buffer->error_cb = cbfn;
    buffer->userdata = userdata;

    return 0;
}

/**
 * Initialize default values for buffered transmitting (private API)
 *
 * @param buffer
 *   Tx buffer to be initialized.
 * @param size
 *   Buffer size
 * @param cbfn
 *   Callback on error function, if null use txbuff_drop_callback().
 * @param cb_arg
 *   Argument for callback function.
 * @return
 *   0 if no error or -1 on error
 */
static int
txbuff_init(txbuff_t *buffer, uint16_t size, txbuff_error_fn cbfn, void *cb_arg)
{
    if (!buffer)
        return -1;

    buffer->size = size;

    if (!cbfn)
        cbfn = txbuff_drop_callback;

    return txbuff_set_err_callback(buffer, cbfn, cb_arg);
}

txbuff_t *
txbuff_pktdev_create(uint16_t size, txbuff_error_fn cbfn, void *cb_arg, uint16_t lport_id)
{
    txbuff_t *buffer;

    buffer = calloc(1, TXBUFF_SIZE(size));
    if (buffer) {
        buffer->txtype   = TXBUFF_PKTDEV_FLAG;
        buffer->lport_id = lport_id;
        if (txbuff_init(buffer, size, cbfn, cb_arg)) {
            free(buffer);
            return NULL;
        }
    }
    return buffer;
}

txbuff_t *
txbuff_xskdev_create(uint16_t size, txbuff_error_fn cbfn, void *cb_arg, void *xinfo)
{
    txbuff_t *buffer;

    buffer = calloc(1, TXBUFF_SIZE(size));
    if (buffer) {
        buffer->txtype = TXBUFF_XSKDEV_FLAG;
        buffer->info   = xinfo;
        if (txbuff_init(buffer, size, cbfn, cb_arg)) {
            free(buffer);
            return NULL;
        }
    }
    return buffer;
}

void
txbuff_free(txbuff_t *buffer)
{
    if (buffer) {
        pktmbuf_free_bulk(buffer->pkts, buffer->length);
        free(buffer);
    }
}

uint16_t
txbuff_flush(txbuff_t *buffer)
{
    uint16_t sent = 0;
    uint16_t npkts;

    if (!buffer)
        return sent;

    npkts = buffer->length;
    if (npkts) {
        buffer->length = 0;

        switch (buffer->txtype) {
        case TXBUFF_PKTDEV_FLAG:
            sent = pktdev_tx_burst(buffer->lport_id, buffer->pkts, npkts);
            if (sent == PKTDEV_ADMIN_STATE_DOWN)
                return sent;
            break;

        case TXBUFF_XSKDEV_FLAG:
            sent = xskdev_tx_burst(buffer->info, (void **)buffer->pkts, npkts);
            break;

        default:
            break;
        }

        npkts -= sent;
        if (npkts && buffer->error_cb)
            buffer->error_cb(buffer, sent, npkts);
    }
    return sent;
}

uint16_t
txbuff_add(txbuff_t *buffer, pktmbuf_t *tx_pkt)
{
    buffer->pkts[buffer->length++] = tx_pkt;
    if (buffer->length < buffer->size)
        return 0;

    return txbuff_flush(buffer);
}
