/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2025 Intel Corporation
 */

#ifndef _CNE_CPUID_H_
#define _CNE_CPUID_H_

/**
 * @file
 *
 * Define the CPUID index registers and array to hold these values.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** EAX register define for indexing into cpuid_registers */
enum cpu_register_t {
    CNE_REG_EAX = 0,
    CNE_REG_EBX,
    CNE_REG_ECX,
    CNE_REG_EDX,
};

typedef uint32_t cpuid_registers_t[4]; /**< defined typedef for CPUID registers */

#ifdef __cplusplus
}
#endif

#endif /* _CNE_CPUID_H_ */
