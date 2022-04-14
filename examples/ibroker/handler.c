/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */
#include <ibroker.h>

#include "main.h"

/*
 * UINTR handlers and all functions called by UINTR handlers must be compiled
 * separately with “-mgeneral-regs-only -minline-all-stringops” compiler options.
 *
 * -mgeneral-regs-only
 *     Generate code that uses only the integer registers.
 * -minline-all-stringops
 *     Inline memcpy, memmove, memset and memcmp to avoid vector register usage in library
 * functions.
 */
__attribute__((target("general-regs-only", "inline-all-stringops"))) int
srv_func(int vector, void *arg)
{
    /* Need to use the args to eliminate compiler warnings */
    (void)vector;
    (void)arg;

    total_interrupts++;

    return 0;
}
