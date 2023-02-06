/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */

#include <stdio.h>             // for NULL
#include <unistd.h>            // for gethostname
#include <sys/socket.h>        // for send, CMSG_DATA
#include <bsd/string.h>        // for strlcat, strlcpy
#include <sched.h>             // for sched_yield

#include "uds_connect.h"

#define MAX_NUM_TRIES 40000
#define HOST_NAME_LEN 32

static int
fin_ack(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    uds_info_t *uds = c->info;

    uds->xsk_uds_state = UDS_FIN;

    return UDS_NO_OUTPUT;
}

static int
set_host_nak(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    uds_info_t *uds = c->info;

    uds->xsk_uds_state = UDS_HOST_NAK;

    return UDS_NO_OUTPUT;
}

static int
set_host_ok(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    uds_info_t *uds = c->info;

    uds->xsk_uds_state = UDS_HOST_OK;

    return UDS_NO_OUTPUT;
}

static int
fd_ack(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    if (!c || !c->cmsg)
        goto err;

    uds_info_t *uds = c->info;

    if (!uds)
        goto err;

    uds->xsk_map_fd    = *(int *)CMSG_DATA(c->cmsg);
    uds->xsk_uds_state = UDS_GOT_FD;

err:
    return UDS_NO_OUTPUT;
}

static int
fd_nak(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    uds_info_t *uds = c->info;

    uds->xsk_uds_state = UDS_FD_NAK;

    return UDS_NO_OUTPUT;
}

static int
config_busy_poll_ack(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    uds_info_t *uds = c->info;

    uds->xsk_uds_state = UDS_BUSY_POLL_ACK;

    return UDS_NO_OUTPUT;
}

static int
config_busy_poll_nak(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    uds_info_t *uds = c->info;

    uds->xsk_uds_state = UDS_BUSY_POLL_NAK;

    return UDS_NO_OUTPUT;
}

uds_info_t *
udsc_handshake(const char *uds_name)
{
    const char *err_msg               = NULL;
    char connect_msg[UDS_MAX_CMD_LEN] = {0};
    char hostname[HOST_NAME_LEN]      = {0};
    int len                           = 0;
    int num_of_tries                  = 0;
    uds_info_t *info                  = NULL;
    const uds_group_t *group          = NULL;

    /* NOTE: currently uds_connect creates an async client
     * to register protocol commands with and process information
     * exchanged on the UDS.
     */

    info = uds_connect(uds_name, &err_msg, NULL);
    if (!info)
        return NULL;
    /* get root group */
    group = uds_get_group_by_name(info, NULL);
    if (group == NULL)
        goto err;

    info->xsk_uds_state = UDS_CONNECTED;

    if (uds_register(group, UDS_HOST_OK_MSG, set_host_ok) < 0)
        goto err;

    if (uds_register(group, UDS_FD_ACK_MSG, fd_ack) < 0)
        goto err;

    if (uds_register(group, UDS_FD_NAK_MSG, fd_nak) < 0)
        goto err;

    if (uds_register(group, UDS_FIN_ACK_MSG, fin_ack) < 0)
        goto err;

    if (uds_register(group, UDS_HOST_NAK_MSG, set_host_nak) < 0)
        goto err;

    if (uds_register(group, UDS_CFG_BUSY_POLL_ACK, config_busy_poll_ack) < 0)
        goto err;

    if (uds_register(group, UDS_CFG_BUSY_POLL_NAK, config_busy_poll_nak) < 0)
        goto err;

    /* Sending a request of the form "/connect,$hostname" to the UDS
     * If hostname is correct, /host_ok will be sent by the UDS
     * and if incorrect, /host_nak is sent by the UDS.
     */
    strlcpy(connect_msg, UDS_CONNECT_MSG, sizeof(connect_msg));
    if (gethostname(hostname, sizeof(hostname)) < 0)
        goto err;

    strlcat(connect_msg, ",", sizeof(connect_msg));
    len = strlcat(connect_msg, hostname, sizeof(connect_msg));

    if (send(info->sock, connect_msg, len, 0) <= 0)
        goto err;

    do {
        num_of_tries++;
        sched_yield();
    } while (info->xsk_uds_state != UDS_HOST_OK && num_of_tries < MAX_NUM_TRIES);
    if (info->xsk_uds_state == UDS_HOST_OK)
        return info;
    else if (num_of_tries == MAX_NUM_TRIES)
        info->xsk_uds_state = UDS_HOST_ERR;

err:
    uds_destroy(info);
    uds_destroy_group(group);
    return NULL;
}

int
udsc_close(uds_info_t *info)
{
    int num_of_tries = 0;

    if (!info)
        return -1;
    if (send(info->sock, UDS_FIN_MSG, sizeof(UDS_FIN_MSG) - 1, 0) <= 0)
        return -1;

    do {
        num_of_tries++;
        sched_yield();
    } while (info->xsk_uds_state != UDS_FIN && num_of_tries < MAX_NUM_TRIES);

    if (num_of_tries == MAX_NUM_TRIES)
        return -1;

    return 0;
}
