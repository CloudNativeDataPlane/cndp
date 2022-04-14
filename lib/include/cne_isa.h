/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <sys/syscall.h>
#include <stdint.h>        // for uint64_t

#ifndef _CNE_ISA_H_
#define _CNE_ISA_H_

#include <cne_common.h>        // for CNDP_API

/**
 * @file
 *
 * APIs for ISA instructions
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set the address for UMONITOR instruction.
 *
 * For more information about usage of these instructions, please refer to
 * Intel(R) 64 and IA-32 Architectures Software Developer's Manual.
 *
 * @param addr
 *   Address to use for umonitor.
 * @return
 *   None.
 */
static __cne_always_inline void
cne_umonitor(volatile void *addr)
{
    /* UMONITOR */
    asm volatile(".byte 0xf3, 0x0f, 0xae, 0xf7;" : : "D"(addr));
}

/**
 * Execute UMWAIT given the timestamp value.
 *
 * This function will enter C0.2 state.
 *
 * For more information about usage of these instructions, please refer to
 * Intel(R) 64 and IA-32 Architectures Software Developer's Manual.
 *
 * @param timestamp
 *   The number of cycles to wait.
 * @return
 *   None.
 */
static __cne_always_inline void
cne_umwait(const uint64_t timestamp)
{
    const uint32_t l = (uint32_t)timestamp;
    const uint32_t h = (uint32_t)(timestamp >> 32);

    /* UMWAIT */
    asm volatile(".byte 0xf2, 0x0f, 0xae, 0xf7;"
                 :         /* ignore rflags */
                 : "D"(0), /* enter C0.2 */
                   "a"(l), "d"(h));
}

/**
 * Execute TPAUSE given the timestamp value.
 *
 * This function uses TPAUSE instruction  and will enter C0.2 state. For more
 * information about usage of this instruction, please refer to Intel(R) 64 and
 * IA-32 Architectures Software Developer's Manual.
 *
 * @param  timestamp
 *   The number of cycles to wait.
 * @return
 *   None.
 */
static __cne_always_inline void
cne_tpause(const uint64_t timestamp)
{
    const uint32_t l = (uint32_t)timestamp;
    const uint32_t h = (uint32_t)(timestamp >> 32);

    /* TPAUSE */
    asm volatile(".byte 0x66, 0x0f, 0xae, 0xf7;"
                 :         /* ignore rflags */
                 : "D"(0), /* enter C0.2 */
                   "a"(l), "d"(h));
}

/**
 * MOVDIRI instruction.
 *
 * @param addr
 *   The address to put the value.
 * @param value
 *   The value to move to the given address.
 * @return
 *   None.
 */
static __cne_always_inline void
cne_movdiri(volatile void *addr, uint32_t value)
{
    /* MOVDIRI */
    asm volatile(".byte 0x40, 0x0f, 0x38, 0xf9, 0x02" : : "a"(value), "d"(addr));
}

/**
 * Use movdir64b instruction to move data from source to destination
 *
 * @param dst
 *   The destination address to put the source data
 * @param src
 *   The source address to get the data from.
 * @return
 *   None.
 */
static __cne_always_inline void
cne_movdir64b(volatile void *dst, const void *src)
{
    /* MOVDIR64B */
    asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02" : : "a"(dst), "d"(src) : "memory");
}

/**
 * Demote a cacheline entry
 *
 * @param p
 *   The address of the cacheline to demote.
 * @return
 *   None.
 */
static __cne_always_inline void
cne_cldemote(const volatile void *p)
{
    /* CLDEMOTE */
    asm volatile(".byte 0x0f, 0x1c, 0x06" ::"S"(p));
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_ISA_H_ */
