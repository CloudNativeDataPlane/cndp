/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _FIB_TEST_H_
#define _FIB_TEST_H_

/**
 * @file
 * CNE FIB Test
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

int fib_main(int argc, char **argv);
int fib6_main(int argc, char **argv);
int fib_perf_main(int argc, char **argv);
int fib6_perf_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* _FIB_TEST_H_ */
