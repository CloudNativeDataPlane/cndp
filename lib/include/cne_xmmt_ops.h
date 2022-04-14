/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation
 */

#ifndef _XMMT_OPS_H_
#define _XMMT_OPS_H_

/**
 * @file
 *
 * This header defines a few AVX support routines
 */

#include <cne_vect.h>

/* vect_* abstraction implementation using SSE */

/** loads the xmm_t value from address p(does not need to be 16-byte aligned)*/
#define vect_loadu_sil128(p) _mm_loadu_si128(p)

/** sets the 4 signed 32-bit integer values and returns the xmm_t variable */
#define vect_set_epi32(i3, i2, i1, i0) _mm_set_epi32(i3, i2, i1, i0)

#endif /* _XMMT_OPS_H_ */
