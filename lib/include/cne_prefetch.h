/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CNE_PREFETCH_H_
#define _CNE_PREFETCH_H_

/**
 * @file
 *
 * Set of cacheline control APIs
 */

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Prefetch a single cacheline at the given address into all caches levels
 *
 * @param p
 *    Pointer to cacheline to prefetch
 */
static inline void
cne_prefetch0(const volatile void *p)
{
    asm volatile("prefetcht0 %[p]" : : [p] "m"(*(const volatile char *)p));
}

/**
 * Prefetch the cacheline at the given address into all caches except L1
 *
 * @param p
 *    Pointer to cacheline to prefetch
 */
static inline void
cne_prefetch1(const volatile void *p)
{
    asm volatile("prefetcht1 %[p]" : : [p] "m"(*(const volatile char *)p));
}

/**
 * Prefetch the cacheline at the given address into all caches except L1 and L2
 *
 * @param p
 *    Pointer to cacheline to prefetch
 */
static inline void
cne_prefetch2(const volatile void *p)
{
    asm volatile("prefetcht2 %[p]" : : [p] "m"(*(const volatile char *)p));
}

/**
 * Prefetch the cacheline at the given address into non-temporal cache structure, minimizing cache
 * pollution.
 *
 * @param p
 *    Pointer to cacheline to prefetch
 */
static inline void
cne_prefetch_non_temporal(const volatile void *p)
{
    asm volatile("prefetchnta %[p]" : : [p] "m"(*(const volatile char *)p));
}

/**
 * Prefetch a cache line into all cache levels, with intention to write. This
 * prefetch variant hints to the CPU that the program is expecting to write to
 * the cache line being prefetched.
 *
 * @param p Address to prefetch
 */
static inline void
cne_prefetch0_write(const void *p)
{
    /* 1 indicates intention to write, 3 sets target cache level to L1. See
     * GCC docs where these integer constants are described in more detail:
     *  https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
     */
    __builtin_prefetch(p, 1, 3);
}

/**
 * Prefetch a cache line into all cache levels, except the 0th, with intention
 * to write. This prefetch variant hints to the CPU that the program is
 * expecting to write to the cache line being prefetched.
 *
 * @param p Address to prefetch
 */
static inline void
cne_prefetch1_write(const void *p)
{
    /* 1 indicates intention to write, 2 sets target cache level to L2. See
     * GCC docs where these integer constants are described in more detail:
     *  https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
     */
    __builtin_prefetch(p, 1, 2);
}

/**
 * Prefetch a cache line into all cache levels, except the 0th and 1st, with
 * intention to write. This prefetch variant hints to the CPU that the program
 * is expecting to write to the cache line being prefetched.
 *
 * @param p Address to prefetch
 */
static inline void
cne_prefetch2_write(const void *p)
{
    /* 1 indicates intention to write, 1 sets target cache level to L3. See
     * GCC docs where these integer constants are described in more detail:
     *  https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
     */
    __builtin_prefetch(p, 1, 1);
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_PREFETCH_H_ */
