/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

/**
 * @file
 * Private information for idlemgr (Idle Manager)
 */

#ifndef _IDLE_MGR_PRIV_H_
#define _IDLE_MGR_PRIV_H_

#include "idlemgr.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct imgr_s {
    TAILQ_ENTRY(imgr_s) next;          /**< List of next idlemgr entries */
    char name[IDLE_MGR_MAX_NAME_SIZE]; /**< Name of the idle manager instance. */
    pthread_mutex_t mutex;             /**< Mutex used to add and delete file descriptors. */
    int mutex_inited;                  /**< non-zero if mutex is already initialized */
    int epoll_fd;                      /**< the epoll() fd value */
    uint16_t max_fds;                  /**< Max number of file descriptors to handle */
    uint16_t nb_fds;                   /**< Number of file descriptors currently in use */
    struct epoll_event *events;        /**< List of events being handled */
    uint32_t idle_timeout;             /**< Idle timeout in milliseconds to start waiting */
    uint32_t intr_timeout;             /**< Interrupt timeout value in milliseconds */
    uint64_t idle_timestamp;           /**< Rx idle timestamp value in CPU ticks */
    idlemgr_stats_t stats;             /**< Stats for idlemgr */
} imgr_t;

#ifdef __cplusplus
}
#endif

#endif /* _IDLE_MGR_PRIV_H_ */
