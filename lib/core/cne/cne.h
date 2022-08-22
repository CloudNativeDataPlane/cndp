/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include "cne_private.h"

#include <stdio.h>         // for FILE
#include <stdint.h>        // for uint16_t

#ifndef _CNE_H_
#define _CNE_H_

#include <cne_common.h>        // for CNDP_API

/**
 * @file
 *
 * API for CNE setup routines.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CNE_CAUGHT_SIGNAL, /**< Application caught a signal */
    CNE_CALLED_EXIT,   /**< Application called exit */
    CNE_USER_EXIT,     /**< User type exit, when exit function is called by application */
    MAX_EXIT_TYPES     /**< Number of exit types. */
};

/* Maybe defined first in the cne_private.h file, so guard for this case. */
#ifndef _CNE_PRIVATE_H_
/**
 * The typedef for the on exit function pointer.
 *
 * @param sig
 *   The signal number supplied in the signal handler function.
 * @param arg
 *   The user supplied argument used as an argument to the exit_fn function.
 * @param exit_type
 *   The type of exit signal or exit() was called, CNE_CAUGHT_SIGNAL or CNE_CALLED_EXIT
 */
typedef void (*on_exit_fn_t)(int sig, void *arg, int exit_type);
#endif

#define COPYRIGHT_MSG       "Copyright (c) 2020-2022 Intel Corporation. All rights reserved."
#define COPYRIGHT_MSG_SHORT "Copyright (c) 2020-2022 Intel Corporation"
#define POWERED_BY_CNDP     "Powered by CNDP"

/**
 * Set the get_id function pointer and finish initialization
 *
 * The API initializes the UID and other basic system configuration to enable
 * user application threads to work with CNDP APIs.
 *
 * This API, needs to be only called once per process, during the main thread startup.
 *
 * @return
 *   The initial UID for the main thread.
 */
CNDP_API int cne_init(void);

/**
 * Call signal handler and function pointer with argument, when a signal is caught or on exit.
 *
 * @param exit_fn
 *   The function pointer to call when a signal is caught. If the signal is not in the
 *   signals array then standard system operations are performed.
 * @param arg
 *   The user supplied argument used as an argument to the exit_fn function.
 * @param signals
 *   A integer array of signal value to handle via signal() function. Can be NULL pointer
 *   as long as the nb_signals is zero.
 * @param nb_signals
 *   The number of signal values in the signals array, can be zero.
 * @return
 *   0 on success or
 *   -1 if exit_fn is NULL or
 *   -1 if atexit() failed or
 *   -1 if signals is NULL with nb_signals non-zero.
 */
CNDP_API int cne_on_exit(on_exit_fn_t exit_fn, void *arg, int *signals, int nb_signals);

/**
 * Return the initial UID value for the main thread.
 *
 * @return
 *   The initial UID value.
 */
CNDP_API int cne_initial_uid(void);

/**
 * Return the UID value for the current instance.
 *
 * @return
 *   -1 if error or UID value for the instance.
 */
CNDP_API int cne_entry_uid(void);

/**
 * Register an instance/thread and return the uid value.
 *
 * Not thread safe. Mutual exclusion needs to be assured by user.
 * This API is used to register the main thread or when the developer uses
 * some other type of threading model and not the lib/usr/clib/thread library.
 *
 * @param name
 *   The name of the instance used for debugging
 * @return
 *   UID value or -1 on error
 */
CNDP_API int cne_register(const char *name);

/**
 * Unregister the instance and reclaim the UID value.
 *
 * Not thread safe. Mutual exclusion needs to be assured by user.
 * Release the UID value for the given thread index value or use the
 * current thread index value.
 *
 * @param tidx
 *   The instance value from the cne_registers() call. When tidx is -1 then
 *   use the current thread id value.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cne_unregister(int tidx);

/**
 * Set a private value with the uid value
 *
 * @param tidx
 *   The uid index value, if -1 then use the current thread index value.
 * @param v
 *   The private pointer value to save
 * @return
 *   0 in success or -1 on error
 */
CNDP_API int cne_set_private(int tidx, void *v);

/**
 * Get a private value with the uid value
 *
 * @param tidx
 *   The uid index value, if -1 then use the current thread index value.
 * @param v
 *   The private pointer to pointer value to retrieve
 * @return
 *   0 in success or -1 on error
 */
CNDP_API int cne_get_private(int tidx, void **v);

/**
 * Get the unique ID value using the internal ID get routine
 *
 * @return
 *   The unique ID value or -1 on error
 */
CNDP_API int cne_id(void);

/**
 * Return the max number of threads allowed
 *
 * @return
 *   The number of threads allowed or -1 on error.
 */
CNDP_API int cne_max_threads(void);

/**
 * Return the next thread ID value
 *
 * @param uid
 *   Starting UID
 * @param skip
 *   Skip the initial thread if set.
 * @param wrap
 *   Wrap the UID to the beginning
 * @return
 *   Return the next thread id or -1 on error
 */
CNDP_API int cne_next_id(int uid, int skip, int wrap);

/**
 * Return the number of active threads in the system.
 *
 * @return
 *   -1 on error or the number of active threads
 */
CNDP_API int cne_active_threads(void);

/**
 * Dump out information about CNE environment
 *
 * @param f
 *   File pointer to use to write the data, if NULL use stdout.
 */
CNDP_API void cne_dump(FILE *f);

/**
 * Function returning string for Copyright message."
 * @return
 *     string
 */
static inline const char *
copyright_msg(void)
{
    return COPYRIGHT_MSG;
}

/**
 * Function returning short string for Copyright message."
 * @return
 *     string
 */
static inline const char *
copyright_msg_short(void)
{
    return COPYRIGHT_MSG_SHORT;
}

/**
 * Function returning string for Copyright message."
 * @return
 *     string
 */
static inline const char *
powered_by(void)
{
    return POWERED_BY_CNDP;
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_H_ */
