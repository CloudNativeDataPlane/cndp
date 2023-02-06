/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Intel Corporation
 */

#include <stdio.h>        // for NULL
#include <errno.h>        // for ENODEV, errno
#include <pthread.h>

#include <cne_mutex_helper.h>
#include "metrics.h"

static uds_info_t *default_info;
static const uds_group_t *metrics_group;

static pthread_mutex_t metrics_mutex;

static inline void
__lock(void)
{
    int ret = pthread_mutex_lock(&metrics_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static inline void
__unlock(void)
{
    int ret = pthread_mutex_unlock(&metrics_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

int
metrics_register(const char *cmd, metrics_cb fn)
{
    int ret;

    __lock();
    if (metrics_group == NULL) {
        /* needs init first */
        errno = ENODEV;
        __unlock();
        return -1;
    }
    ret = uds_register(metrics_group, cmd, fn);
    __unlock();
    return ret;
}

int
metrics_init(void *priv_)
{
    default_info = uds_get_default(priv_);
    if (default_info == NULL)
        return -1;

    metrics_group = uds_create_group(default_info, "metrics", priv_);
    if (metrics_group == NULL)
        return -1;

    return 0;
}

int
metrics_destroy(void)
{
    int ret;

    __lock();
    if (metrics_group == NULL) {
        /* not initialized */
        errno = ENODEV;
        __unlock();
        return -1;
    }

    if (uds_destroy_group(metrics_group) == 0) {
        metrics_group = NULL;
        ret           = 0;
    } else {
        /* uds_destroy_group will provide errno */
        ret = -1;
    }
    __unlock();

    return ret;
}

const char *
metrics_cmd(metrics_client_t *_c)
{
    return uds_cmd(_c);
}

const char *
metrics_params(metrics_client_t *_c)
{
    return uds_params(_c);
}

int
metrics_port_stats(metrics_client_t *c, char *name, lport_stats_t *s)
{
    if (!c || !s)
        return -1;

    metrics_append(c, "\"%s_n_rx_bytes\":%ld", name, s->ibytes);
    metrics_append(c, ",\"%s_n_tx_bytes\":%ld", name, s->obytes);
    metrics_append(c, ",\"%s_n_rx_packets\":%ld", name, s->ipackets);
    metrics_append(c, ",\"%s_n_tx_packets\":%ld", name, s->opackets);
    metrics_append(c, ",\"%s_n_rx_errors\":%ld", name, s->ierrors);
    metrics_append(c, ",\"%s_n_tx_errors\":%ld", name, s->oerrors);
    metrics_append(c, ",\"%s_n_rx_missed\":%ld", name, s->imissed);
    metrics_append(c, ",\"%s_n_tx_dropped\":%ld", name, s->odropped);
    metrics_append(c, ",\"%s_n_rx_invalid_requests\":%ld", name, s->rx_invalid);
    metrics_append(c, ",\"%s_n_tx_invalid_requests\":%ld", name, s->tx_invalid);

    metrics_append(c, ",\"%s_n_rx_ring_empty\":%ld", name, s->rx_ring_empty);
    metrics_append(c, ",\"%s_n_rx_buf_allocs\":%ld", name, s->rx_buf_alloc);
    metrics_append(c, ",\"%s_n_rx_busypoll_wakeup\":%ld", name, s->rx_busypoll_wakeup);
    metrics_append(c, ",\"%s_n_rx_poll_wakeup\":%ld", name, s->rx_poll_wakeup);
    metrics_append(c, ",\"%s_n_rx_count\":%ld", name, s->rx_rcvd_count);
    metrics_append(c, ",\"%s_n_rx_burst_called\":%ld", name, s->rx_burst_called);

    metrics_append(c, ",\"%s_n_fq_add_called\":%ld", name, s->fq_add_called);
    metrics_append(c, ",\"%s_n_fq_add_count\":%ld", name, s->fq_add_count);
    metrics_append(c, ",\"%s_n_fq_full\":%ld", name, s->fq_full);
    metrics_append(c, ",\"%s_n_fq_alloc_zero\":%ld", name, s->fq_alloc_zero);
    metrics_append(c, ",\"%s_n_fq_reserve_failed\":%ld", name, s->fq_reserve_failed);

    metrics_append(c, ",\"%s_n_tx_kicks\":%ld", name, s->tx_kicks);
    metrics_append(c, ",\"%s_n_tx_failed_kicks\":%ld", name, s->tx_kick_failed);
    metrics_append(c, ",\"%s_n_tx_kick_again\":%ld", name, s->tx_kick_again);
    metrics_append(c, ",\"%s_tx_ring_full\":%ld", name, s->tx_ring_full);
    metrics_append(c, ",\"%s_tx_copied\":%ld", name, s->tx_copied);

    metrics_append(c, ",\"%s_cq_empty\":%ld", name, s->cq_empty);
    metrics_append(c, ",\"%s_cq_buf_freed\":%ld", name, s->cq_buf_freed);

    return 0;
}

CNE_INIT_PRIO(metrics_constructor, INIT)
{
    if (cne_mutex_create(&metrics_mutex, PTHREAD_MUTEX_RECURSIVE) < 0)
        CNE_RET("mutex init(metrics_mutex) failed\n");
}
