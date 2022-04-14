/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CTHREAD_TIMER_H_
#define _CTHREAD_TIMER_H_

#include <cne.h>
#include <cne_system.h>
#include <cne_timer.h>
#include "cthread_int.h"
#include "cthread_sched.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline uint64_t
_ns_to_clks(uint64_t ns)
{
    uint64_t clkns = cne_get_timer_hz();

    clkns *= ns;
    clkns /= 1000000000ULL;

    return clkns;
}

static inline uint64_t
_clks_to_ns(uint64_t clks)
{
    uint64_t ns = cne_get_timer_hz();

    if (ns) {
        ns = 1000000000ULL / ns; /* nsecs per clk */
        ns *= clks;              /* nsec per clk times clks */
    }

    return ns;
}

static inline void
_timer_start(struct cthread *ct, uint64_t clks)
{
    if (clks > 0)
        cne_timer_reset_sync(&ct->tim, clks, SINGLE, cne_id(), _sched_timer_cb, (void *)ct);
}

static inline void
_timer_stop(struct cthread *ct)
{
    if (ct != NULL)
        cne_timer_stop_sync(&ct->tim);
}

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_TIMER_H_ */
