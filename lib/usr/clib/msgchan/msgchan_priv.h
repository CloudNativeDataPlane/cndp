/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef _MSGCHAN_PRIV_H_
#define _MSGCHAN_PRIV_H_

#include <sys/queue.h>
#include <cne_common.h>
#include <cne_ring.h>
#include <cne_ring_api.h>
#include "msgchan.h"

/**
 * @file
 * Private Message Channels information
 *
 * Private data structures and information for msgchan library. The external msgchan pointer
 * is a void pointer and converted to the msg_chan_t structure pointer in the code.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define MC_COOKIE ('C' << 24 | 'h' << 16 | 'a' << 8 | 'n')

typedef struct msg_chan {
    TAILQ_ENTRY(msg_chan) next;      /**< Next entry in the global list. */
    struct msg_chan *parent;         /**< Pointer to parent channel. */
    char name[MC_NAME_SIZE];         /**< The name of the message channel */
    uint32_t cookie;                 /**< Cookie value to test for valid entry */
    bool mutex_inited;               /**< Flag to detect mutex is inited */
    pthread_mutex_t mutex;           /**< Mutex to protect the attached list */
    cne_ring_t *rings[2];            /**< Pointers to the send/recv rings */
    int child_count;                 /**< Number of children */
    TAILQ_HEAD(, msg_chan) children; /**< List of attached children */
    uint64_t send_calls;             /**< Number of send calls */
    uint64_t send_cnt;               /**< Number of objects sent */
    uint64_t recv_calls;             /**< Number of receive calls */
    uint64_t recv_cnt;               /**< Number of objects received */
    uint64_t recv_timeouts;          /**< Number of receive timeouts */
} msg_chan_t;

#ifdef __cplusplus
}
#endif

#endif /* _MSGCHAN_PRIV_H_ */
