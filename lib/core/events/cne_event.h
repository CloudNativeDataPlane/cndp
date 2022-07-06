/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

/**
 * @file
 * Event monitoring Helpers in CNE
 */

#ifndef _CNE_EVENT_H_
#define _CNE_EVENT_H_

#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <errno.h>
#include <bsd/string.h>

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum cne_ev_handle_type { CNE_EV_HANDLE_MEM, CNE_EV_HANDLE_EXT, CNE_EV_HANDLE_MAX };

/** Handle for interrupts. */
struct cne_ev_handle {
    int fd;       /**< event file descriptor */
    void *handle; /**< device driver handle (Wi ndows) */
    enum cne_ev_handle_type type;
};

/**
 * Function to be registered for the specific interrupt
 *
 * @param cb_arg
 *  address of parameter for callback.
 */
typedef void (*cne_ev_callback_fn)(void *cb_arg);

/**
 * Function to call after a callback is unregistered.
 * Can be used to close fd and free cb_arg.
 *
 * @param ev_handle
 *  Pointer to the event handle.
 * @param cb_arg
 *  address of parameter for callback.
 */
typedef void (*cne_ev_unregister_callback_fn)(struct cne_ev_handle *ev_handle, void *cb_arg);

/**
 *  buffer for reading on different devices
 */
struct cne_ev_read_buffer {
    char charbuf[16]; /* for others */
};

/**
 * It registers the callback for the specific event. Multiple
 * callbacks can be registered at the same time.
 *
 * @param ev_handle
 *  Pointer to the event handle.
 * @param cb_fn
 *  callback address.
 * @param cb_arg
 *  address of parameter for callback.
 *
 * @return
 *  - On success, zero.
 *  - On failure, a negative value.
 */

CNDP_API int cne_ev_callback_register(const struct cne_ev_handle *ev_handle,
                                      cne_ev_callback_fn cb_fn, void *cb_arg);

/**
 * It unregisters the callback for the specific event. Multiple
 * callbacks can be registered at the same time.
 *
 * @param ev_handle
 *  Pointer to the event handle.
 * @param cb_fn
 *  callback address.
 * @param cb_arg
 *  address of parameter for callback.
 *
 * @return
 *  - On success, zero.
 *  - On failure, a negative value.
 */

CNDP_API int cne_ev_callback_unregister(const struct cne_ev_handle *ev_handle,
                                        cne_ev_callback_fn cb_fn, void *cb_arg);

/**
 * Unregister the callback according to the specified event handle,
 * after it's no longer active. Fail if source is not active.
 *
 * @param ev_handle
 *  pointer to the event handle.
 * @param cb_fn
 *  callback address.
 * @param cb_arg
 *  address of parameter for callback, (void *)-1 means to remove all
 *  registered which has the same callback address.
 * @param ucb_fn
 *  callback to call before cb is unregistered (optional).
 *  can be used to close fd and free cb_arg.
 *
 * @return
 *  - On success, return the number of callback entities marked for remove.
 *  - On failure, a negative value.
 */
CNDP_API int cne_ev_callback_unregister_pending(const struct cne_ev_handle *ev_handle,
                                                cne_ev_callback_fn cb_fn, void *cb_arg,
                                                cne_ev_unregister_callback_fn ucb_fn);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_EVENT_H_ */
