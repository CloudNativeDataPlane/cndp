/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _RING_PROFILE_H_
#define _RING_PROFILE_H_

/**
 * @file
 * CNE Ring measure enqueue/dequeue performance for various esize values
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

int ring_profile(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* _RING_PROFILE_H_ */
