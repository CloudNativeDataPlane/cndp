/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _CNE_PER_THREAD_H_
#define _CNE_PER_THREAD_H_

/**
 * @file
 *
 * Per-thread variables in CNE
 *
 * This file defines an API for instantiating per-thread "global
 * variables" that are environment-specific. Note that in all
 * environments, a "shared variable" is the default when you use a
 * global variable.
 *
 * Parts of this are execution environment specific.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Macro to define a per thread variable "var" of type "type", don't
 * use keywords like "static" or "volatile" in type, just prefix the
 * whole macro.
 */
#define CNE_DEFINE_PER_THREAD(type, name) __thread __typeof__(type) per_thread_##name

/**
 * Macro to declare an extern per thread variable "var" of type "type"
 */
#define CNE_DECLARE_PER_THREAD(type, name) extern __thread __typeof__(type) per_thread_##name

/**
 * Read/write the per-thread variable value
 */
#define CNE_PER_THREAD(name) (per_thread_##name)

#ifdef __cplusplus
}
#endif

#endif /* _CNE_PER_THREAD_H_ */
