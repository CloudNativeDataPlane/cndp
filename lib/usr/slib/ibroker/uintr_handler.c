/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2025 Intel Corporation
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/queue.h>
#include <stdatomic.h>
#include <bsd/string.h>
#include <pthread.h>

#include "ibroker.h"
#include "ibroker_private.h"
#include "ibroker_uintr.h"

/*
 * This file is split out as the UIPI docs suggest we put the ui handler
 * function into its own file and apply special build options.
 *
 * UINTR handlers and all functions called by UINTR handlers must be compiled
 * separately with “-muintr -mgeneral-regs-only -minline-all-stringops” compiler options.
 * The -muintr is enabled in the top level meson.build and not required here.
 *
 * -mgeneral-regs-only
 *     Generate code that uses only the integer registers.
 * -minline-all-stringops
 *     Inline memcpy, memmove, memset and memcmp to avoid vector register usage in library
 * functions. The ui handler function must also be defined as an interrupt handler.
 */
__attribute__((interrupt, target("general-regs-only", "inline-all-stringops"))) void
uintr_handler(struct __uintr_frame *ui_frame __ibroker_unused, unsigned long vector)
{
    struct ibroker *ibroker = this_ibroker;

    if (ibroker && vector < IBROKER_MAX_SERVICES) {
        struct ibroker_srv *srv = &ibroker->services[vector];

        ibroker->intrs++;
        if (srv && srv->enabled && srv->func) {
            srv->call_cnt++;
            if (srv->func(vector, srv->arg) != 0)
                srv->err_cnt++;
        } else
            ibroker->invalid_service++;
    }
}
