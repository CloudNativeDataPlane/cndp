/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017 Cavium, Inc
 */

#ifndef _CNE_PAUSE_H_
#define _CNE_PAUSE_H_

#include <emmintrin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Pause the core for a few cycles.
 */
static inline void
cne_pause(void)
{
    _mm_pause();
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_PAUSE_H_ */
