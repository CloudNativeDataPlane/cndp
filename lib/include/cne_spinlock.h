/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#ifndef _CNE_SPINLOCK_H_
#define _CNE_SPINLOCK_H_

/**
 * @file
 *
 * CNE Spinlocks
 *
 * This file defines an API for read-write locks, which are implemented
 * in an architecture-specific way. This kind of lock simply waits in
 * a loop repeatedly checking until the lock becomes available.
 *
 * All locks must be initialised before use, and only initialised once.
 *
 */

#include <unistd.h>

#include <cne_cpuflags.h>
#include <cne_cycles.h>
#include <cne_branch_prediction.h>
#include <cne_common.h>
#include <cne_gettid.h>
#include <cne_system.h>
#include <cne_pause.h>
#include <cne_rtm.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNE_RTM_MAX_RETRIES  (20)
#define CNE_RTM_MAX_RETRIES  (20)
#define CNE_XABORT_LOCK_BUSY (0xff)

/**
 * The cne_spinlock_t type.
 */
typedef struct {
    volatile int locked; /**< lock status 0 = unlocked, 1 = locked */
} cne_spinlock_t;

/**
 * A static spinlock initializer.
 */
#define CNE_SPINLOCK_INITIALIZER \
    {                            \
        0                        \
    }

/**
 * Initialize the spinlock to an unlocked state.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static inline void
cne_spinlock_init(cne_spinlock_t *sl)
{
    sl->locked = 0;
}

#ifdef CNE_FORCE_INTRINSICS
/**
 * Take the spinlock.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static inline void cne_spinlock_lock(cne_spinlock_t *sl);

static inline void
cne_spinlock_lock(cne_spinlock_t *sl)
{
    int exp = 0;

    while (
        !__atomic_compare_exchange_n(&sl->locked, &exp, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
        while (__atomic_load_n(&sl->locked, __ATOMIC_RELAXED))
            cne_pause();
        exp = 0;
    }
}

/**
 * Release the spinlock.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static inline void cne_spinlock_unlock(cne_spinlock_t *sl);

static inline void
cne_spinlock_unlock(cne_spinlock_t *sl)
{
    __atomic_store_n(&sl->locked, 0, __ATOMIC_RELEASE);
}

/**
 * Try to take the lock.
 *
 * @param sl
 *   A pointer to the spinlock.
 * @return
 *   1 if the lock is successfully taken; 0 otherwise.
 */
static inline int cne_spinlock_trylock(cne_spinlock_t *sl);

static inline int
cne_spinlock_trylock(cne_spinlock_t *sl)
{
    int exp = 0;
    return __atomic_compare_exchange_n(&sl->locked, &exp, 1, 0, /* disallow spurious failure */
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

#else /* CNE_FORCE_INTRINSICS not defined */

static inline void
cne_spinlock_lock(cne_spinlock_t *sl)
{
    int lock_val = 1;
    asm volatile("1:\n"
                 "xchg %[locked], %[lv]\n"
                 "test %[lv], %[lv]\n"
                 "jz 3f\n"
                 "2:\n"
                 "pause\n"
                 "cmpl $0, %[locked]\n"
                 "jnz 2b\n"
                 "jmp 1b\n"
                 "3:\n"
                 : [locked] "=m"(sl->locked), [lv] "=q"(lock_val)
                 : "[lv]"(lock_val)
                 : "memory");
}

static inline void
cne_spinlock_unlock(cne_spinlock_t *sl)
{
    int unlock_val = 0;
    asm volatile("xchg %[locked], %[ulv]\n"
                 : [locked] "=m"(sl->locked), [ulv] "=q"(unlock_val)
                 : "[ulv]"(unlock_val)
                 : "memory");
}

static inline int
cne_spinlock_trylock(cne_spinlock_t *sl)
{
    int lockval = 1;

    asm volatile("xchg %[locked], %[lockval]"
                 : [locked] "=m"(sl->locked), [lockval] "=q"(lockval)
                 : "[lockval]"(lockval)
                 : "memory");

    return lockval == 0;
}
#endif

/**
 * Test if the lock is taken.
 *
 * @param sl
 *   A pointer to the spinlock.
 * @return
 *   1 if the lock is currently taken; 0 otherwise.
 */
static inline int
cne_spinlock_is_locked(cne_spinlock_t *sl)
{
    return __atomic_load_n(&sl->locked, __ATOMIC_ACQUIRE);
}

/**
 * The cne_spinlock_recursive_t type.
 */
typedef struct {
    cne_spinlock_t sl;  /**< the actual spinlock */
    volatile int user;  /**< core id using lock, -1 for unused */
    volatile int count; /**< count of time this lock has been called */
} cne_spinlock_recursive_t;

/**
 * A static recursive spinlock initializer.
 */
#define CNE_SPINLOCK_RECURSIVE_INITIALIZER \
    {                                      \
        CNE_SPINLOCK_INITIALIZER, -1, 0    \
    }

/**
 * Initialize the recursive spinlock to an unlocked state.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
static inline void
cne_spinlock_recursive_init(cne_spinlock_recursive_t *slr)
{
    cne_spinlock_init(&slr->sl);
    slr->user  = -1;
    slr->count = 0;
}

/**
 * Take the recursive spinlock.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
static inline void
cne_spinlock_recursive_lock(cne_spinlock_recursive_t *slr)
{
    int id = gettid();

    if (slr->user != id) {
        cne_spinlock_lock(&slr->sl);
        slr->user = id;
    }
    slr->count++;
}
/**
 * Release the recursive spinlock.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 */
static inline void
cne_spinlock_recursive_unlock(cne_spinlock_recursive_t *slr)
{
    if (--(slr->count) == 0) {
        slr->user = -1;
        cne_spinlock_unlock(&slr->sl);
    }
}

/**
 * Try to take the recursive lock.
 *
 * @param slr
 *   A pointer to the recursive spinlock.
 * @return
 *   1 if the lock is successfully taken; 0 otherwise.
 */
static inline int
cne_spinlock_recursive_trylock(cne_spinlock_recursive_t *slr)
{
    int id = gettid();

    if (slr->user != id) {
        if (cne_spinlock_trylock(&slr->sl) == 0)
            return 0;
        slr->user = id;
    }
    slr->count++;
    return 1;
}

static inline int
cne_try_tm(volatile int *lock)
{
    int i, retries;

    if (!cne_cpu_rtm_is_supported())
        return 0;

    retries = CNE_RTM_MAX_RETRIES;

    while (likely(retries--)) {

        unsigned int status = cne_xbegin();

        if (likely(CNE_XBEGIN_STARTED == status)) {
            if (unlikely(*lock))
                cne_xabort(CNE_XABORT_LOCK_BUSY);
            else
                return 1;
        }
        while (*lock)
            cne_pause();

        if ((status & CNE_XABORT_CONFLICT) ||
            ((status & CNE_XABORT_EXPLICIT) && (CNE_XABORT_CODE(status) == CNE_XABORT_LOCK_BUSY))) {
            /* add a small delay before retrying, basing the
             * delay on the number of times we've already tried,
             * to give a back-off type of behaviour. We
             * randomize trycount by taking bits from the tsc count
             */
            int try_count   = CNE_RTM_MAX_RETRIES - retries;
            int pause_count = (cne_rdtsc() & 0x7) | 1;
            pause_count <<= try_count;
            for (i = 0; i < pause_count; i++)
                cne_pause();
            continue;
        }

        if ((status & CNE_XABORT_RETRY) == 0) /* do not retry */
            break;
    }
    return 0;
}

static inline void
cne_spinlock_lock_tm(cne_spinlock_t *sl)
{
    if (likely(cne_try_tm(&sl->locked)))
        return;

    cne_spinlock_lock(sl); /* fall-back */
}

static inline int
cne_spinlock_trylock_tm(cne_spinlock_t *sl)
{
    if (likely(cne_try_tm(&sl->locked)))
        return 1;

    return cne_spinlock_trylock(sl);
}

static inline void
cne_spinlock_unlock_tm(cne_spinlock_t *sl)
{
    if (unlikely(sl->locked))
        cne_spinlock_unlock(sl);
    else
        cne_xend();
}

static inline void
cne_spinlock_recursive_lock_tm(cne_spinlock_recursive_t *slr)
{
    if (likely(cne_try_tm(&slr->sl.locked)))
        return;

    cne_spinlock_recursive_lock(slr); /* fall-back */
}

static inline void
cne_spinlock_recursive_unlock_tm(cne_spinlock_recursive_t *slr)
{
    if (unlikely(slr->sl.locked))
        cne_spinlock_recursive_unlock(slr);
    else
        cne_xend();
}

static inline int
cne_spinlock_recursive_trylock_tm(cne_spinlock_recursive_t *slr)
{
    if (likely(cne_try_tm(&slr->sl.locked)))
        return 1;

    return cne_spinlock_recursive_trylock(slr);
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_SPINLOCK_H_ */
