/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2023 Intel Corporation
 */

#ifndef _CNE_GETTID_H_
#define _CNE_GETTID_H_

/**
 * @file
 *
 * A gettid() wrapper is introduced in glibc 2.30. To support earlier versions
 * of glibc, this file provides a syscall wrapper.
 */

#ifdef __GLIBC_PREREQ
#if !__GLIBC_PREREQ(2, 30)

#include <sys/syscall.h>

#define gettid() syscall(SYS_gettid)

#endif /* !__GLIBC_PREREQ(2, 30) */
#endif /* __GLIBC_PREREQ */
#endif /* _CNE_GETTID_H_ */
