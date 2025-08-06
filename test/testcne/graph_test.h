/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _GRAPH_TEST_H_
#define _GRAPH_TEST_H_

/**
 * @file
 * CNE Graph Test
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#define GRAPH_VERBOSE_FLAG (1 << 0)
#define GRAPH_PRINT_FLAG   (1 << 1)

int graph_main(int argc, char **argv);
int graph_perf_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* _GRAPH_TEST_H_ */
