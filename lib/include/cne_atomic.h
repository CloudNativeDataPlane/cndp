/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation.
 */

#ifndef _CNE_ATOMIC_H_
#define _CNE_ATOMIC_H_

/**
 * @file
 */

#ifndef __cplusplus
#include <stdatomic.h>
#define CNE_ATOMIC(X)       atomic_##X
#define CNE_MEMORY_ORDER(X) memory_order_##X
#else
#include <atomic>
#define CNE_ATOMIC(X)       std::atomic<X>
#define CNE_MEMORY_ORDER(X) std::memory_order_##X
#endif

#endif /* _CNE_ATOMIC_H_ */
