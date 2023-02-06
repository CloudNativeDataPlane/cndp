/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#ifndef _TIMER_TEST_H_
#define _TIMER_TEST_H_

/**
 * @file
 * CNE timer Test
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

int timer_main(int argc, char **argv);
int test_timer(int nb_timers);
int test_timer_perf(void);

#ifdef __cplusplus
}
#endif

#endif /* _TIMER_TEST_H_ */
