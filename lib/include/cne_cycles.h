/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 * Copyright (c) 2013 6WIND S.A.
 */

#ifndef _CNE_CYCLES_H_
#define _CNE_CYCLES_H_

/**
 * @file
 */

#include <cne_atomic.h>

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MS_PER_S 1000
#define US_PER_S 1000000
#define NS_PER_S 1000000000

/**
 * Read and return the timestamp counter value
 *
 * @return
 *   Returns the 64bit timesample counter value.
 */
static inline uint64_t
cne_rdtsc(void)
{
    union {
        uint64_t tsc_64;
        CNE_STD_C11
        struct {
            uint32_t lo_32;
            uint32_t hi_32;
        };
    } tsc;

    // clang-format off
    asm volatile("rdtsc" :
             "=a" (tsc.lo_32),
             "=d" (tsc.hi_32));
    // clang-format on
    return tsc.tsc_64;
}

/**
 * Read and return the timestamp precise counter value
 *
 * @return
 *   Returns the 64bit timesample counter value.
 */
static inline uint64_t
cne_rdtsc_precise(void)
{
    atomic_thread_fence(CNE_MEMORY_ORDER(release));
    return cne_rdtsc();
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_CYCLES_H_ */
