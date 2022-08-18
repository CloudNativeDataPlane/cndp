/*-
 * Copyright(c) <2016-2022>, Intel Corporation. All rights reserved.
 * Copyright (c) 2022 Red Hat, Inc.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Created 2016 by Keith Wiles @ intel.com */

#ifndef _LATENCY_H_
#define _LATENCY_H_

#include <cne_timer.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_JITTER_THRESHOLD (50) /**< usec */

void txgen_page_latency(void);

#ifdef __cplusplus
}
#endif

#endif /* _LATENCY_H_ */
