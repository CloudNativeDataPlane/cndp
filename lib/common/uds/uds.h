/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

/**
 * @file
 *
 * uds-related utility functions
 */

#ifndef _UDS_H_
#define _UDS_H_

#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>        // for sockaddr_un

#include "cne_common.h"        // for CNDP_API

#ifdef __cplusplus
extern "C" {
#endif

#define UDS_MAX_CMD_LEN      56
#define UDS_MAX_GRP_NAME_LEN 32

typedef struct uds_group {
    char name[UDS_MAX_GRP_NAME_LEN]; /**< UDS endpoint group name */
    void *priv;                      /**< private space to hold per-group app data */
} uds_group_t;

/**< returned by uds_cb to indicate UDS should not send its output buffer. This is usually
 * used when the application sends its own data, not necessarily json formatted.
 */
#define UDS_NO_OUTPUT -2

struct uds_client;

typedef struct uds_client uds_client_t;
typedef struct uds_client {
    char *buffer;                  /**< Output buffers pointer */
    const char *cmd;               /**< Command buffer */
    const char *params;            /**< Parameters for command */
    const char *params2;           /**< second parameter */
    int buf_len;                   /**< length of buffer data */
    int used;                      /**< Amount of used data in buffer */
    int s;                         /**< Accepted socket ID */
    struct uds_info *info;         /**< Pointer to info data */
    struct cmsghdr *cmsg;          /**< pointer to ancillary data, if present */
    const struct uds_group *group; /**< Pointer to group info */
    int socket_client;             /**< set to 1 - client, 0 - listener */
} uds_client_t;

typedef struct uds_info {
    volatile int running;   /**< Indicates if a socket is running */
    int sock;               /**< Socket descriptor */
    struct sockaddr_un sun; /**< Path to local domain socket */
    void *priv;             /**< Private space to hold app specific data */
    int xsk_uds_state;      /**< current stage in handshake with UDS */
    int xsk_map_fd;         /**< xsk map file descriptor received from UDS */
} uds_info_t;

enum {
    UDS_START = 0,     /**< initial state */
    UDS_CONNECTED,     /**< xskdev_connect() returned non-null*/
    UDS_HOST_OK,       /**< received a /host_ok message*/
    UDS_GOT_FD,        /**< successfully retrieved xsk_map_fd */
    UDS_FD_NAK,        /**< error on retrieving xsk_map_fd */
    UDS_FIN,           /**< received a /fin msg */
    UDS_HOST_NAK,      /**< received a /host_nak response */
    UDS_HOST_ERR,      /**< timeout waiting for /host_ok response */
    UDS_BUSY_POLL_ACK, /**< busy poll socket cfg success */
    UDS_BUSY_POLL_NAK, /**< busy poll socket cfg failure */
};

#define UDS_CONNECT_MSG       "/connect"
#define UDS_HOST_OK_MSG       "/host_ok"
#define UDS_HOST_NAK_MSG      "/host_nak"
#define UDS_XSK_MAP_FD_MSG    "/xsk_map_fd"
#define UDS_XSK_SOCKET_MSG    "/xsk_socket"
#define UDS_FD_ACK_MSG        "/fd_ack"
#define UDS_FD_NAK_MSG        "/fd_nak"
#define UDS_FIN_MSG           "/fin"
#define UDS_FIN_ACK_MSG       "/fin_ack"
#define UDS_CFG_BUSY_POLL_MSG "/config_busy_poll"
#define UDS_CFG_BUSY_POLL_ACK "/config_busy_poll_ack"
#define UDS_CFG_BUSY_POLL_NAK "/config_busy_poll_nak"

/**
 * callback returns json data in buffer, up to buf_len long.
 * returns 0 on success, UDS_NO_OUTPUT on success and to indicate that UDS should not send
 * any output in its buffer, or an otherwise negative value indicate failure.
 */
typedef int (*uds_cb)(uds_client_t *client, const char *cmd, const char *params);

/**
 * Register a new command to the uds interface
 *
 * @param grp
 *   UDS command group to register the callback for
 * @param cmd
 *   The command string including the '/' e.g. '/pktdev:stats'
 * @param fn
 *   The function to callback for this command
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int uds_register(const uds_group_t *grp, const char *cmd, uds_cb fn);

/**
 * Create a uds instance.
 *
 * @param runtime_dir
 *   The base directory to create the local domain socket file.
 * @param uds_name
 *   The name of the local domain socket.
 * @param err_str
 *   The error return pointer, used to send back error messages, Can be NULL
 * @param priv
 *   The private data to be passed to uds_info_t, Can be NULL
 * @return
 *   The uds_info_t pointer or NULL on error
 */
CNDP_API uds_info_t *uds_create(const char *runtime_dir, const char *uds_name, const char **err_str,
                                void *priv);

/**
 * Returns default UDS instance.
 *
 * @return
 *   The uds_info_t pointer or NULL on error.
 */
CNDP_API uds_info_t *uds_get_default(void *priv);

/**
 * Register a new command group to the uds interface.
 *
 * @param info
 *   UDS socket information
 * @param group
 *   Group name
 * @param priv
 *   Private data to be associated with the command group.
 * @return
 *   Pointer to group handle on success, NULL on error, with errno indicating
 *   reason for failure.
 */
CNDP_API const uds_group_t *uds_create_group(const uds_info_t *info, const char *group, void *priv);

/**
 * Destroy a command group, freeing all associated callbacks.
 *
 * @param group
 *   UDS command group handle to destroy.
 * @return
 *   0 on success, -1 on failure, with errno indicating reason for failure.
 */
CNDP_API int uds_destroy_group(const uds_group_t *group);

/**
 * Get command group by name for this UDS interface.
 *
 * @param info
 *   UDS socket information
 * @param name
 *   Group name to look up. Set to NULL to get root command group.
 * @return
 *   Pointer to group handle on success, NULL on error, with errno indicating
 *   reason for failure.
 */
CNDP_API const uds_group_t *uds_get_group_by_name(const uds_info_t *info, const char *name);

/**
 * Connect to a an exising UDS without creating it. Creates a uds_info_t instance.
 *
 * @param uds_name
 *   The name of the local domain socket to connect to.
 * @param err_str
 *   The error return pointer, used to send back error messages, Can be NULL
 * @param priv
 *   The private data to be passed to uds_info_t, Can be NULL
 * @return
 *   The uds_info_t pointer or NULL on error
 */
CNDP_API uds_info_t *uds_connect(const char *uds_name, const char **err_str, void *priv);

/**
 * Destroy and stop the uds threads and close sockets
 *
 * @param info
 *   The pointer returned from the uds_create() call.
 */
CNDP_API void uds_destroy(uds_info_t *info);

/**
 * A snprintf() like routine to add text or data to the output buffer.
 *
 * @param client
 *   The client pointer that holds the buffer to append the text data.
 * @param format
 *   The snprintf() like format string with variable arguments
 * @param ...
 *   Arguments for the format string to use
 * @return
 *   The number of bytes appended to the data buffer.
 */
CNDP_API int uds_append(uds_client_t *client, const char *format, ...);

/**
 * Return the command string pointer
 *
 * @param client
 *   The client structure pointer
 * @return
 *   NULL if not defined or the string pointer.
 */
CNDP_API const char *uds_cmd(uds_client_t *client);

/**
 * Return the params string pointer
 *
 * @param client
 *   The client structure pointer
 * @return
 *   NULL if not defined or the string pointer.
 */
CNDP_API const char *uds_params(uds_client_t *client);

#ifdef __cplusplus
}
#endif

#endif /* _UDS_H_ */
