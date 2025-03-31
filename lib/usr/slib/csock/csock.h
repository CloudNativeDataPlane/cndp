/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Intel Corporation
 */

/**
 * @file
 *
 * CNDP Socket-related utility functions
 *
 * Routines to support a stdio connection with a TTY or socket connection.
 *
 * Note: This library is shared between CNDP and non-CNDP applications and can not contain
 *       CNDP routines or macros.
 */

#ifndef _CSOCK_H_
#define _CSOCK_H_

#include <stdint.h>           // for uint32_t
#include <stddef.h>           // for size_t
#include <sys/types.h>        // for ssize_t

#ifdef __cplusplus
extern "C" {
#endif

#define CSOCK_API __attribute__((visibility("default")))

/**
 * short definition to mark a function parameter unused
 */
#define __csock_unused __attribute__((__unused__))

enum {
    CSOCK_MAX_HOST_NAME_LENGTH = 128,  /**< Maximum host name length */
    CSOCK_MAX_SOCK_INFO_LENGTH = 1024, /**< Maximum host address length, could be a path */
    DEFAULT_CSOCK_RX_LEN       = 4096, /**< Default size of the RX buffer */
    DEFAULT_CSOCK_TX_LEN       = 4096, /**< Default size of the TX buffer */

    CSOCK_IS_SERVER    = (1 << 0), /**< The connection is a server socket */
    CSOCK_IS_CLIENT    = (1 << 1), /**< The connection is a client socket */
    CSOCK_NON_BLOCKING = (1 << 2), /**< The connection is non blocking */
    CSOCK_GROUP_WRITE  = (1 << 3), /**< The connection is a group write */
    CSOCK_EOF          = (1 << 4), /**< The connection has gotten a EOF */
    CSOCK_STDIO_TYPE   = (1 << 5), /**< Use stdin/stdout and not a socket */
};

typedef void csock_t; /**< Forward declarations */

/**
 * The client function to call for a connection, which is a standard pthread function.
 *
 * @param c
 *   The csock_t pointer, which is a opaque void pointer
 * @return
 *   NULL on success or a value for pthread_exit() call failure
 */
typedef void *(csock_client_fn_t)(csock_t * c);

/**
 * Template for the write function
 */
typedef ssize_t(csock_write_t)(csock_t *c, char *data, size_t len);

/**
 * Template for the read function
 */
typedef ssize_t(csock_read_t)(csock_t *c, char *data, size_t len);

/**
 * Template for the close function
 */
typedef int(csock_close_t)(csock_t *c);

/**
 * Configuration structure
 */
typedef struct csock_cfg {
    uint32_t flags;  /**< Flags for server or client or non-blocking or ... */
    char *host_addr; /**< Host address or path */

    csock_client_fn_t *client_fn; /**< Client function pointer */
    csock_read_t *read_fn;        /**< Read function */
    csock_write_t *write_fn;      /**< Write function */
    csock_close_t *close_fn;      /**< Close function */
} csock_cfg_t;

/**
 * Create a cloud socket data structure
 *
 * @param cfg
 *   Client configuration information.
 * @return
 *   The pointer to the csock_t structure or NULL on error.
 */
CSOCK_API csock_t *csock_create(csock_cfg_t *cfg);

/**
 * Destroy the csock structure and release resources.
 *
 * @param c
 *   The csock_t pointer, which is a opaque void pointer
 * @return
 *   N/A
 */
CSOCK_API void csock_destroy(csock_t *c);

/**
 * Start the cloud server connection
 *
 * @param c
 *   The csock_t pointer, which is a opaque pointer
 * @return
 *   0 on success or -1 on error
 */
CSOCK_API int csock_server_start(csock_t *c);

/**
 * Accept a connection from the remote client.
 *
 * @param s
 *   The csock_t pointer, which is the server side data
 * @return
 *   NULL on error or a new csock_t structure pointer.
 */
CSOCK_API csock_t *csock_accept(csock_t *s);

/**
 * Read data from a socket or TTY devices
 *
 * @param c
 *   The csock_t pointer, which is a opaque pointer
 * @param data
 *   The data buffer to place the received data.
 * @param len
 *   Size of the data buffer.
 * @return
 *   -1 on error or the number of bytes in the data buffer.
 *   The data buffer is not null terminated.
 */
CSOCK_API ssize_t csock_read(csock_t *c, char *data, size_t len);

/**
 * Write data to a socket or TTY devices
 *
 * @param c
 *   The csock_t pointer, which is a opaque pointer
 * @param data
 *   The data buffer to get the data to send.
 * @param len
 *   Size of the data in the buffer.
 * @return
 *   -1 on error or the number of bytes written.
 */
CSOCK_API ssize_t csock_write(csock_t *c, char *data, size_t len);

/**
 * Close a socket or tty connection
 *
 * @param c
 *   The csock_t pointer, which is a opaque pointer
 * @return
 *   0 on success or -1 on error
 */
CSOCK_API int csock_close(csock_t *c);

/**
 * Get the peer connection address
 *
 * @param c
 *   The csock_t pointer, which is a opaque pointer
 * @return
 *   NULL on error or pointer to sockaddr structure
 */
CSOCK_API struct sockaddr *csock_get_peer(csock_t *c);

/**
 * Return non-zero if connection had a EOF condition
 *
 * @param _c
 *   The csock_t pointer, which is a opaque pointer
 * @return
 *   non-zero if EOF
 */
CSOCK_API int csock_eof(csock_t *_c);

/**
 * Return the current FD value for the connection.
 *
 * @param c
 *   The csock_t pointer, which is a opaque pointer
 * @return
 *   -1 on error or FD value
 */
CSOCK_API int csock_get_fd(csock_t *c);

/**
 * Set the connection FD value
 *
 * @param _c
 *   The csock_t pointer, which is a opaque pointer
 * @param fd
 *   The FD value for a connection
 * @return
 *   0 on success or -1 on error
 */
CSOCK_API int csock_set_fd(csock_t *_c, int fd);

/**
 * Return non-zero if the connection is closed
 *
 * @param c
 *   The csock_t structure pointer
 * @return
 *   1 if the connection is closed or 0 if not closed
 */
CSOCK_API int csock_is_closed(csock_t *c);

#ifdef __cplusplus
}
#endif

#endif /* _CSOCK_H_ */
