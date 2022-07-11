/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 Cisco Systems, Inc.  All rights reserved.
 */

#ifndef _MEMIF_SOCKET_H_
#define _MEMIF_SOCKET_H_

#include <sys/queue.h>
#include <sys/un.h>
#include <cne_event.h>
#include "memif.h"

struct cne_memif_socket_dev_list_elt {
    TAILQ_ENTRY(cne_memif_socket_dev_list_elt) next;
    struct cne_pktdev *dev; /**< pointer to device internals */
};

#define CNE_MEMIF_SOCKET_HASH_NAME "memif-sh"
#define UNIX_PATH_MAX              108

struct cne_memif_socket {
    struct cne_ev_handle ev_handle; /**< ev handle */
    char filename[UNIX_PATH_MAX];   /**< socket filename */

    TAILQ_HEAD(, cne_memif_socket_dev_list_elt) dev_queue;
    /**< Queue of devices using this socket */
    uint8_t listener; /**< if not zero socket is listener */
};

/* Control message queue. */
struct cne_memif_msg_queue_elt {
    cne_memif_msg_t msg; /**< control message */
    TAILQ_ENTRY(cne_memif_msg_queue_elt) next;
    int fd; /**< fd to be sent to peer */
};

struct cne_memif_control_channel {
    struct cne_ev_handle ev_handle;                  /**< interrupt handle */
    TAILQ_HEAD(, cne_memif_msg_queue_elt) msg_queue; /**< control message queue */
    struct cne_memif_socket *socket;                 /**< pointer to socket */
    struct cne_pktdev *dev;                          /**< pointer to device */
};

/**
 * Remove device from socket device list. If no device is left on the socket,
 * remove the socket as well.
 *
 * @param dev
 *   memif device
 */
void cne_memif_socket_remove_device(struct cne_pktdev *dev);

/**
 * Enqueue disconnect message to control channel message queue.
 *
 * @param cc
 *   control channel
 * @param reason
 *   const string stating disconnect reason (96 characters)
 * @param err_code
 *   error code
 */
void cne_memif_msg_enq_disconnect(struct cne_memif_control_channel *cc, const char *reason,
                                  int err_code);

/**
 * Initialize memif socket for specified device. If socket doesn't exist, create socket.
 *
 * @param dev
 *   memif device
 * @param socket_filename
 *   socket filename
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int cne_memif_socket_init(struct cne_pktdev *dev, const char *socket_filename);

/**
 * Disconnect memif device. Close control channel and shared memory.
 *
 * @param dev
 *   memif device
 */
void cne_memif_disconnect(struct cne_pktdev *dev);

/**
 * If device is properly configured, enable connection establishment.
 *
 * @param dev
 *   memif device
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int cne_memif_connect_server(struct cne_pktdev *dev);

/**
 * If device is properly configured, send connection request.
 *
 * @param dev
 *   memif device
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int cne_memif_connect_client(struct cne_pktdev *dev);

#endif /* MEMIF_SOCKET_H */
