/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2025 Intel Corporation
 */

#ifndef _CNE_ACL_OSDEP_H_
#define _CNE_ACL_OSDEP_H_

/**
 * @file
 *
 * CNE ACL CNDP/OS dependent file.
 */

#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/queue.h>

/*
 * Common defines.
 */

#define DIM(x) CNE_DIM(x)

#include <cne_common.h>
#include <cne_vect.h>
#include <cne_log.h>
#include <cne_prefetch.h>
#include <cne_byteorder.h>
#include <cne_branch_prediction.h>
#include <cne_per_thread.h>
#include <cne_strings.h>
#include <cne_cpuflags.h>

#endif /* _CNE_ACL_OSDEP_H_ */
