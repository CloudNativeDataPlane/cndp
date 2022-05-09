/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

#ifndef _IBROKER_UINTR_H_
#define _IBROKER_UINTR_H_

/**
 * @file
 * CNE UIPI-Broker handler functions
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <x86gprintrin.h>
#include "ibroker_private.h"

/**
 * Internal function definition for UIPI interrupt handler.
 */
HIDE_API void uintr_handler(struct __uintr_frame *ui_frame, unsigned long vector);

/*
 * The defines below are taken from the UIPI example and draft docs for UIPI.
 *
 * These defines will need to be updated when the Kernel syscalls are updated.
 */
#define __NR_uintr_register_handler   443
#define __NR_uintr_unregister_handler 444
#define __NR_uintr_create_fd          445
#define __NR_uintr_register_sender    446
#define __NR_uintr_unregister_sender  447

/**
 * Register a UIPI handler function for the receiver thread
 *
 * @param ui_handler
 *   The function pointer to call when an interrupt is sent.
 * @param flags
 *   The flags to use, which is not used at this time.
 * @return
 *   0 on success or -1 on error.
 */
static inline int
uintr_register_handler(void *ui_handler, unsigned int flags)
{
    return syscall(__NR_uintr_register_handler, ui_handler, flags);
}

/**
 * Unregister a UIPI handler function, called from the receiver thread
 *
 * @param flags
 *   The flags to use, which is not used at this time.
 * @return
 *   0 on success or -1 on error.
 */
static inline int
uintr_unregister_handler(unsigned int flags)
{
    return syscall(__NR_uintr_unregister_handler, flags);
}

/**
 * Create a UIPI file descriptor for the given service ID
 *
 * @param sid
 *   The vector or service id to use for uintr_fd create call.
 * @param flags
 *   The flags to use, which is not used at this time.
 * @return
 *   0 on success or -1 on error.
 */
static inline int
uintr_create_fd(service_id_t sid, unsigned int flags)
{
    return syscall(__NR_uintr_create_fd, sid, flags);
}

/**
 * Register a UIPI sender
 *
 * @param ui_handler
 *   The function pointer to call when an interrupt is sent.
 * @param flags
 *   The flags to use, which is not used at this time.
 * @return
 *   0 on success or -1 on error.
 */
static inline int
uintr_register_sender(int uintr_fd, unsigned int flags)
{
    return syscall(__NR_uintr_register_sender, uintr_fd, flags);
}

/**
 * Unregister a UIPI sender
 *
 * @param uintr_fd
 *   The file descriptor of the sender to close.
 * @param flags
 *   The flags to use, which is not used at this time.
 * @return
 *   0 on success or -1 on error.
 */
static inline int
uintr_unregister_sender(int uintr_fd, unsigned int flags)
{
    return syscall(__NR_uintr_unregister_sender, uintr_fd, flags);
}

/**
 * Enable UIPI interrupts
 */
static inline void
uintr_start(void)
{
    _stui();
}

/**
 * Clear the UIPI interrupts
 */
static inline void
uintr_clear(void)
{
    _clui();
}

/**
 * Test if the UIPI is enabled
 *
 * @return
 *   True if enable or False if not enabled.
 */
static inline int
uintr_test(void)
{
    return _testui();
}

/**
 * Send a UIPI to a receiver or broker
 *
 * @param
 *   The service id for sending an interrupt
 * @return
 *   0 on success or -1 on error
 */
static inline int
uintr_senduipi(struct ibroker *ibroker, service_id_t sid)
{
    if (ibroker && SERVICE_IS_VALID(sid)) {
        struct ibroker_srv *srv = &ibroker->services[sid];

        if (srv->enabled) {
            _senduipi(srv->uipi_index);
            return 0;
        }
    }
    return -1;
}

#ifdef __cplusplus
}
#endif

#endif /* _IBROKER_UINTR_H_ */
