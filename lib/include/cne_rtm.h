/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2012,2013,2021 Intel Corporation
 */

#ifndef _CNE_RTM_H_
#define _CNE_RTM_H_ 1

/* Official RTM intrinsics interface matching gcc/icc, but works
   on older gcc compatible compilers and binutils. */

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CNE_XBEGIN_STARTED  (~0u)
#define CNE_XABORT_EXPLICIT (1 << 0)
#define CNE_XABORT_RETRY    (1 << 1)
#define CNE_XABORT_CONFLICT (1 << 2)
#define CNE_XABORT_CAPACITY (1 << 3)
#define CNE_XABORT_DEBUG    (1 << 4)
#define CNE_XABORT_NESTED   (1 << 5)
#define CNE_XABORT_CODE(x)  (((x) >> 24) & 0xff)

static __cne_always_inline unsigned int
cne_xbegin(void)
{
    unsigned int ret = CNE_XBEGIN_STARTED;

    asm volatile(".byte 0xc7,0xf8 ; .long 0" : "+a"(ret)::"memory");
    return ret;
}

static __cne_always_inline void
cne_xend(void)
{
    asm volatile(".byte 0x0f,0x01,0xd5" ::: "memory");
}

/* not an inline function to workaround a clang bug with -O0 */
#define cne_xabort(status)                                            \
    do {                                                              \
        asm volatile(".byte 0xc6,0xf8,%P0" ::"i"(status) : "memory"); \
    } while (0)

static __cne_always_inline int
cne_xtest(void)
{
    unsigned char out;

    asm volatile(".byte 0x0f,0x01,0xd6 ; setnz %0" : "=r"(out)::"memory");
    return out;
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_RTM_H_ */
