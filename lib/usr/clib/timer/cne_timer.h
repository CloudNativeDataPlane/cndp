/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2023 Intel Corporation
 */

#ifndef _CNE_TIMER_H_
#define _CNE_TIMER_H_

/**
 * @file
 *
 * CNE Timer
 *
 * This library provides a timer service to CNE Data Plane execution
 * units that allows the execution of callback functions asynchronously.
 *
 * - Timers can be periodic or single (one-shot).
 * - The timers can be loaded from one core and executed on another. This has
 *   to be specified in the call to cne_timer_reset().
 * - High precision is possible. NOTE: this depends on the call frequency to
 *   cne_timer_manage() that check the timer expiration for the local core.
 * - If not used in an application, for improved performance, it can be
 *   disabled at compilation time by not calling the cne_timer_manage()
 *   to improve performance.
 *
 * This library provides an interface to add, delete and restart a
 * timer. The API is based on the BSD callout(9) API with a few
 * differences.
 *
 * See the CNE architecture documentation for more information about the
 * design of this library.
 */

#include <stdio.h>         // for FILE
#include <stdint.h>        // for uint64_t, int16_t, uint16_t
#include <stddef.h>
#include <cne_common.h>        // for CNE_STD_C11
#include <cne_atomic.h>        // for atomic_uint_least32_t

#ifdef __cplusplus
extern "C" {
#endif

#define CNE_TIMER_STOP     0  /**< State: timer is stopped. */
#define CNE_TIMER_PENDING  1  /**< State: timer is scheduled. */
#define CNE_TIMER_RUNNING  2  /**< State: timer function is running. */
#define CNE_TIMER_CONFIG   3  /**< State: timer is being configured. */
#define CNE_TIMER_NO_OWNER -2 /**< Timer has no owner. */

/**
 * Timer type: Periodic or single (one-shot).
 */
enum cne_timer_type { SINGLE, PERIODICAL };

/**
 * Timer status: A union of the state (stopped, pending, running,
 * config) and an owner (the id of the thread that owns the timer).
 */
union cne_timer_status {
    CNE_STD_C11
    struct {
        uint16_t state; /**< Stop, pending, running, config. */
        int16_t owner;  /**< The thread that owns the timer. */
    };
    CNE_ATOMIC(uint_least32_t) u32; /**< To atomic-set status + owner. */
};

/**
 * A structure that stores the timer statistics (per-thread).
 */
struct cne_timer_debug_stats {
    uint64_t reset;   /**< Number of success calls to cne_timer_reset(). */
    uint64_t stop;    /**< Number of success calls to cne_timer_stop(). */
    uint64_t manage;  /**< Number of calls to cne_timer_manage(). */
    uint64_t pending; /**< Number of pending/running timers. */
};

struct cne_timer;

/**
 * Callback function type for timer expiry.
 */
typedef void (*cne_timer_cb_t)(struct cne_timer *, void *);

#define MAX_SKIPLIST_DEPTH 10

/**
 * A structure describing a timer in CNE.
 */
struct cne_timer {
    uint64_t expire;                               /**< Time when timer expire. */
    struct cne_timer *sl_next[MAX_SKIPLIST_DEPTH]; /**< Skiplist for timers */
    volatile union cne_timer_status status;        /**< Status of timer. */
    uint64_t period;                               /**< Period of timer (0 if not periodic). */
    cne_timer_cb_t f;                              /**< Callback function. */
    void *arg;                                     /**< Argument to callback function. */
};

#ifdef __cplusplus
/**
 * A C++ static initializer for a timer structure.
 */
#define CNE_TIMER_INITIALIZER                                             \
    {                                                                     \
        0, {NULL}, {{CNE_TIMER_STOP, CNE_TIMER_NO_OWNER}}, 0, NULL, NULL, \
    }
#else
/**
 * A static initializer for a timer structure.
 */
#define CNE_TIMER_INITIALIZER            \
    {                                    \
        .status = {{                     \
            .state = CNE_TIMER_STOP,     \
            .owner = CNE_TIMER_NO_OWNER, \
        }},                              \
    }
#endif

/**
 * Initialize the timer library.
 *
 * Initializes internal variables (list, locks and so on) for the CNE
 * timer library.
 */
void cne_timer_subsystem_init(void);

/**
 * Initialize a timer handle.
 *
 * The cne_timer_init() function initializes the timer handle *tim*
 * for use. No operations can be performed on a timer before it is
 * initialized.
 *
 * @param tim
 *   The timer to initialize.
 */
void cne_timer_init(struct cne_timer *tim);

/**
 * Reset and start the timer associated with the timer handle.
 *
 * The cne_timer_reset() function resets and starts the timer
 * associated with the timer handle *tim*. When the timer expires after
 * *ticks* HPET cycles, the function specified by *fct* will be called
 * with the argument *arg* on core *tim_thread*.
 *
 * If the timer associated with the timer handle is already running
 * (in the RUNNING state), the function will fail. The user has to check
 * the return value of the function to see if there is a chance that the
 * timer is in the RUNNING state.
 *
 * If the timer is being configured on another core (the CONFIG state),
 * it will also fail.
 *
 * If the timer is pending or stopped, it will be rescheduled with the
 * new parameters.
 *
 * @param tim
 *   The timer handle.
 * @param ticks
 *   The number of cycles (see cne_get_hpet_hz()) before the callback
 *   function is called.
 * @param type
 *   The type can be either:
 *   - PERIODICAL: The timer is automatically reloaded after execution
 *     (returns to the PENDING state)
 *   - SINGLE: The timer is one-shot, that is, the timer goes to a
 *     STOPPED state after execution.
 * @param tim_thread
 *   The ID of the thread where the timer callback function has to be
 *   executed.
 * @param fct
 *   The callback function of the timer.
 * @param arg
 *   The user argument of the callback function.
 * @return
 *   - 0: Success; the timer is scheduled.
 *   - (-1): Timer is in the RUNNING or CONFIG state.
 */
int cne_timer_reset(struct cne_timer *tim, uint64_t ticks, enum cne_timer_type type,
                    unsigned tim_thread, cne_timer_cb_t fct, void *arg);

/**
 * Loop until cne_timer_reset() succeeds.
 *
 * Reset and start the timer associated with the timer handle. Always
 * succeed. See cne_timer_reset() for details.
 *
 * @param tim
 *   The timer handle.
 * @param ticks
 *   The number of cycles (see cne_get_hpet_hz()) before the callback
 *   function is called.
 * @param type
 *   The type can be either:
 *   - PERIODICAL: The timer is automatically reloaded after execution
 *     (returns to the PENDING state)
 *   - SINGLE: The timer is one-shot, that is, the timer goes to a
 *     STOPPED state after execution.
 * @param tim_thread
 *   The ID of the thread where the timer callback function has to be
 *   executed.
 * @param fct
 *   The callback function of the timer.
 * @param arg
 *   The user argument of the callback function.
 */
void cne_timer_reset_sync(struct cne_timer *tim, uint64_t ticks, enum cne_timer_type type,
                          unsigned tim_thread, cne_timer_cb_t fct, void *arg);

/**
 * Stop a timer.
 *
 * The cne_timer_stop() function stops the timer associated with the
 * timer handle *tim*. It may fail if the timer is currently running or
 * being configured.
 *
 * If the timer is pending or stopped (for instance, already expired),
 * the function will succeed. The timer handle tim must have been
 * initialized using cne_timer_init(), otherwise, undefined behavior
 * will occur.
 *
 * This function can be called safely from a timer callback. If it
 * succeeds, the timer is not referenced anymore by the timer library
 * and the timer structure can be freed (even in the callback
 * function).
 *
 * @param tim
 *   The timer handle.
 * @return
 *   - 0: Success; the timer is stopped.
 *   - (-1): The timer is in the RUNNING or CONFIG state.
 */
int cne_timer_stop(struct cne_timer *tim);

/**
 * Loop until cne_timer_stop() succeeds.
 *
 * After a call to this function, the timer identified by *tim* is
 * stopped. See cne_timer_stop() for details.
 *
 * @param tim
 *   The timer handle.
 */
void cne_timer_stop_sync(struct cne_timer *tim);

/**
 * Test if a timer is pending.
 *
 * The cne_timer_pending() function tests the PENDING status
 * of the timer handle *tim*. A PENDING timer is one that has been
 * scheduled and whose function has not yet been called.
 *
 * @param tim
 *   The timer handle.
 * @return
 *   - 0: The timer is not pending.
 *   - 1: The timer is pending.
 */
int cne_timer_pending(struct cne_timer *tim);

/**
 * Manage the timer list and execute callback functions.
 *
 * This function must be called periodically from CNE threads
 * main_loop(). It browses the list of pending timers and runs all
 * timers that are expired.
 *
 * The precision of the timer depends on the call frequency of this
 * function. However, the more often the function is called, the more
 * CPU resources it will use.
 */
void cne_timer_manage(void);

/**
 * Dump statistics about timers.
 *
 * @param f
 *   A pointer to a file for output
 */
void cne_timer_dump_stats(FILE *f);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_TIMER_H_ */
