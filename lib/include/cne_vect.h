/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CNE_VECT_X86_H_
#define _CNE_VECT_X86_H_

/**
 * @file
 *
 * CNE SSE/AVX related header.
 */

#include <stdint.h>
#include <cne_vect_generic.h>

#if (defined(__ICC) || (__GNUC__ == 4 && __GNUC_MINOR__ < 4))

#include <smmintrin.h> /* SSE4 */

#if defined(__AVX__)
#include <immintrin.h>
#endif

#else

#include <x86intrin.h>

#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CNE_VECT_DEFAULT_SIMD_BITWIDTH CNE_VECT_SIMD_256

typedef __m128i xmm_t;

/*
 * Some people use Klocwork for static code analysis. Klocwork is unable to
 * determine the proper size of the intrinsic types, and produces hundreds of
 * ABV.GENERAL false-positives when code using the cne_[xyz]mm_t types assign
 * to the embedded arrays. To avoid false-positives, we hardcode the expected
 * sizes and verify they are the same as the actual sizes using a compile time
 * check.
 */
#define XMM_SIZE 16
#define XMM_MASK (XMM_SIZE - 1)

typedef union cne_xmm {
    xmm_t x;
    uint8_t u8[XMM_SIZE / sizeof(uint8_t)];
    uint16_t u16[XMM_SIZE / sizeof(uint16_t)];
    uint32_t u32[XMM_SIZE / sizeof(uint32_t)];
    uint64_t u64[XMM_SIZE / sizeof(uint64_t)];
    double pd[XMM_SIZE / sizeof(double)];
} cne_xmm_t;

/**
 * @internal Compile time check of XMM_SIZE.
 */
static inline void
__cne_vec_xmm_size_check(void)
{
    CNE_BUILD_BUG_ON(XMM_SIZE != sizeof(xmm_t));
}

#ifdef __AVX__

typedef __m256i ymm_t;

#define YMM_SIZE 32
#define YMM_MASK (YMM_SIZE - 1)

typedef union cne_ymm {
    ymm_t y;
    xmm_t x[YMM_SIZE / sizeof(xmm_t)];
    uint8_t u8[YMM_SIZE / sizeof(uint8_t)];
    uint16_t u16[YMM_SIZE / sizeof(uint16_t)];
    uint32_t u32[YMM_SIZE / sizeof(uint32_t)];
    uint64_t u64[YMM_SIZE / sizeof(uint64_t)];
    double pd[YMM_SIZE / sizeof(double)];
} cne_ymm_t;

/**
 * @internal Compile time check of YMM_SIZE.
 */
static inline void
__cne_vec_ymm_size_check(void)
{
    CNE_BUILD_BUG_ON(YMM_SIZE != sizeof(ymm_t));
}

#endif /* __AVX__ */

#ifdef __AVX512F__

#define CNE_X86_ZMM_SIZE 64
#define CNE_X86_ZMM_MASK (CNE_X86_ZMM_SIZE - 1)

typedef union __cne_x86_zmm {
    __m512i z;
    ymm_t y[CNE_X86_ZMM_SIZE / sizeof(ymm_t)];
    xmm_t x[CNE_X86_ZMM_SIZE / sizeof(xmm_t)];
    uint8_t u8[CNE_X86_ZMM_SIZE / sizeof(uint8_t)];
    uint16_t u16[CNE_X86_ZMM_SIZE / sizeof(uint16_t)];
    uint32_t u32[CNE_X86_ZMM_SIZE / sizeof(uint32_t)];
    uint64_t u64[CNE_X86_ZMM_SIZE / sizeof(uint64_t)];
    double pd[CNE_X86_ZMM_SIZE / sizeof(double)];
} __cne_aligned(CNE_X86_ZMM_SIZE) __cne_x86_zmm_t;

/**
 * @internal Compile time check of CNE_X86_ZMM_SIZE.
 */
static inline void
__cne_vec_cne_x86_zmm_size_check(void)
{
    CNE_BUILD_BUG_ON(CNE_X86_ZMM_SIZE != sizeof(__m512i));
}

#endif /* __AVX512F__ */

#ifdef __cplusplus
}
#endif

#endif /* _CNE_VECT_X86_H_ */
