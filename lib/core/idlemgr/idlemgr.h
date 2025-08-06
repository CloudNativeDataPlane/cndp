/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2025 Intel Corporation
 */

/**
 * @file
 * The idlemgr (Idle Manager) will manage threads idleness when polling lports or
 * any file descriptor. When idle is detected it will call epoll_wait() to wait on
 * RX traffic for the added file descriptors.
 *
 * The current design in CNDP is 100% polling of the receive ring in AF_XDP
 * or PMD which means burning core power. The patch adds two parameters to
 * the jsonc file to control polling idle_timeout and intr_timeout
 * in thread section.
 *
 * The idlemgr library handles managing epoll and calling epoll_wait when the
 * idle_timeout value has been met, then it calls epoll_wait(). The idlemgr
 * operates on threads, using file descriptors as the method to wakeup a sleeping
 * thread. The caller needs to add file descriptors to the idlemgr instance and
 * then call idlemgr_process() with a flag if the thread thinks it is idle or
 * not.
 *
 * The first one gives the number of milliseconds to wait for the RX ring to
 * be idle, then call epoll() with a timeout of intr_timeout. When no Rx traffic
 * for a given time the idlemgr will call epoll(), which reduces the lcore load to
 * effectively zero and only waking up when packets arrive or a timeout occurs.
 *
 * In testing of performance it appears to be very little impact when interrupt
 * mode is enabled compared to when it is not enabled. Added some counters to help
 * determine how the new mode is operating.
 *
 * The idle_timeout value in the jsonc file for given thread is how this feature
 * is controlled. If not defined or set to zero interrupt mode is disabled. When
 * set to a non zero value will enable interrupt mode. The intr_timeout value
 * is only used if idle_timeout is non-zero and will be used in the poll() call
 * as the timeout value. Each of these values are in milliseconds.
 */

#ifndef _IDLE_MGR_H_
#define _IDLE_MGR_H_

#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void idlemgr_t; /**< void pointer to internal idlemgr structure */

#define IDLE_MGR_MAX_NAME_SIZE    32  /**< Maximum size of the idle manager name string */
#define IDLE_MGR_MAX_FDS          512 /**< Maximum number of the idle manager file descriptors */
#define IDLE_MGR_MAX_IDLE_TIMEOUT ((5 * 60) * MS_PER_S) /**< 5 minutes in milliseconds */
#define IDLE_MGR_MAX_INTR_TIMEOUT ((1 * 60) * MS_PER_S) /**< 1 minute in milliseconds */

typedef struct idlemgr_stats {
    uint64_t start_idle_timo;   /**< How many times did we start timeout */
    uint64_t stop_idle_timo;    /**< How many times did we stop timeout */
    uint64_t called_epoll;      /**< How many times did we call epoll_wait */
    uint64_t intr_timedout;     /**< How many times did we timeout */
    uint64_t intr_found_work;   /**< How many times did epoll_wait() return fds */
    uint64_t epoll_wait_failed; /**< How many times did epoll_wait() return error */
} idlemgr_stats_t;

/**
 * Create an idlemgr instance for a given thread.
 *
 * @param name
 *   The name of the idlemgr instance, normally the thread name.
 * @param max_fds
 *   The max number of file descriptors for this thread to manage
 * @param idle_timeout
 *   The number of milliseconds to determine when a thread is idle
 * @param intr_timeout
 *   The number of milliseconds to wait on epoll_wait event before timing out.
 * @return
 *   The idlemgr_t pointer or NULL on error.
 */
CNDP_API idlemgr_t *idlemgr_create(const char *name, uint16_t max_fds, uint32_t idle_timeout,
                                   uint32_t intr_timeout);

/**
 * Destroy an idlemgr instance using the given idlemgr_t pointer.
 *
 * @param imgr
 *   The idlemgr_t pointer to destroy
 * @return
 *   N/A
 */
CNDP_API void idlemgr_destroy(idlemgr_t *imgr);

/**
 * Set the idle and interrupt timeout values in milliseconds
 *
 * @param imgr
 *   The idlemgr_t pointer to set
 * @param idle
 *   The idle_timeout value to set in milliseconds
 * @param intr
 *   The intr_timeout value to set in milliseconds
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int idlemgr_set_timeouts(idlemgr_t *imgr, uint32_t idle, uint32_t intr);

/**
 * Get the idle and interrupt timeout values in milliseconds
 *
 * @param imgr
 *   The idlemgr_t pointer to set
 * @param idle
 *   The idle_timeout value pointer to get in milliseconds
 * @param intr
 *   The intr_timeout value pointer to get in milliseconds
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int idlemgr_get_timeouts(idlemgr_t *imgr, uint32_t *idle, uint32_t *intr);

/**
 * Add a file descriptor to the idlemgr instance
 *
 * @param imgr
 *   The idlemgr_t pointer to the idlemgr instance
 * @param fd
 *   The file descriptor to add to epoll and the idlemgr_t instance
 * @param eflags
 *   The flags to be used when setting struct epoll_event.events. If zero use EPOLLIN.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int idlemgr_add(idlemgr_t *imgr, int fd, uint32_t eflags);

/**
 * Delete a file descriptor from the idlemgr instance
 *
 * @param imgr
 *   The idlemgr_t pointer to the idlemgr instance
 * @param fd
 *   The file descriptor to delete from epoll and the idlemgr_t instance
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int idlemgr_del(idlemgr_t *imgr, int fd);

/**
 * Process the idlemgr instance and call epoll_wait if needed.
 *
 * This API needs to be called regularly to ensure that we can process idleness events.
 * Call this API frequently normally during each RX loop iteration.
 *
 * @param imgr
 *   The idlemgr_t pointer to the idlemgr instance
 * @param active
 *   When zero it means idle and non-zero means active.
 * @return
 *   The number of file descriptors(nfds) found to be active after epoll_wait() call.
 *   The nfds is the number of file descriptors returned from epoll_wait() call.
 *
 *   If nfds is zero, then this was a timeout.
 *   if nfds is < 0, then this was an error.
 *   If nfds is > 0, then it is the number of file descriptors active. Use API idlemgr_get_events
 *   to grab the struct epoll_event structure list to determine which file descriptors are active.
 */
CNDP_API int idlemgr_process(idlemgr_t *imgr, int active);

/**
 * Return the idle manager struct epoll_event list, after idlemgr_process() returned active FDs.
 *
 * @param imgr
 *   The idlemgr_t pointer to the idlemgr instance
 * @return
 *   NULL on error or pointer to idle manager event list.
 */
CNDP_API struct epoll_event *idlemgr_get_events(idlemgr_t *imgr);

/**
 * Find the idlemgr_t pointer by name.
 *
 * @param name
 *   The string name of the idlemgr used when created.
 * @return
 *   NULL On not found or idlemgr_t pointer if found
 */
CNDP_API idlemgr_t *idlemgr_find_by_name(const char *name);

/**
 * Grab the statistics of the idlemgr_t instance.
 *
 * @param imgr
 *   The idlemgr_t pointer to the idlemgr instance
 * @param stats
 *   Pointer to the location of the idlemgr_stats_t structure to be filled in.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int idlemgr_stats(idlemgr_t *imgr, idlemgr_stats_t *stats);

/**
 * Dump out information about the idlemgr_t instance
 *
 * @param imgr
 *   The idlemgr_t pointer to the idlemgr instance
 * @return
 *   N/A
 */
CNDP_API void idlemgr_dump(idlemgr_t *imgr);

/**
 * Dump out information about the idlemgr_t instances
 *
 * @return
 *   N/A
 */
CNDP_API void idlemgr_list_dump(void);

#ifdef __cplusplus
}
#endif

#endif /* _IDLE_MGR_H_ */
