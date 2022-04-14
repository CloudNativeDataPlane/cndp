/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * @file
 *
 * CNDP Socket-related data structures.
 *
 * Create and support socket or stdio for user interactive support. A type of stdio is
 * replacement to support TTY or socket stdio.
 */

#ifndef _CSOCK_PRIVATE_H_
#define _CSOCK_PRIVATE_H_

#include "csock.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Internal string to use STDIN/STDOUT */
#define CSOCK_USE_STDIO "{stdio}"

typedef struct c_sock {
    int fd;         /**< file descriptor for I/O */
    int running;    /**< Server is running */
    uint32_t flags; /**< Flags for server or client or non-blocking or ... */
    char host_name[CSOCK_MAX_HOST_NAME_LENGTH]; /**< Hostname to connect to */
    char sock_addr[CSOCK_MAX_SOCK_INFO_LENGTH]; /**< socket info Host Address or path */
    union {
        struct sockaddr sa;       /**< Socket address INET */
        struct sockaddr_un un;    /**< Socket path UDS */
    } addr;                       /**< Union for different address types */
    struct sockaddr peer;         /**< Peer address information */
    size_t addr_len;              /**< Address length or path length */
    int port;                     /**< Socket port address */
    csock_client_fn_t *client_fn; /**< Client function pointer */
    csock_read_t *read_fn;        /**< Read function */
    csock_write_t *write_fn;      /**< Write function */
    csock_close_t *close_fn;      /**< Close function */
} c_sock_t;

#ifdef __cplusplus
}
#endif

#endif /* _CSOCK_PRIVATE_H_ */
