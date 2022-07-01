/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2019-2022 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _CNE_RING_H_
#define _CNE_RING_H_

/**
 * @file
 * CNE Ring
 *
 * The Ring Manager is a fixed-size queue, implemented as a table of
 * pointers. Head and tail pointers are modified atomically, allowing
 * concurrent access to it. It has the following features:
 *
 * - FIFO (First In First Out)
 * - Maximum size is fixed; the pointers are stored in a table.
 * - Lockless implementation.
 * - Multi- or single-consumer dequeue (default is single-consumer).
 * - Multi- or single-producer enqueue (default is single-producer).
 * - Bulk dequeue.
 * - Bulk enqueue.
 *
 * Note: the ring implementation is not preemptible. Refer to Programmer's
 * guide/Cloud Native Environment/Multiple pthread/Known Issues/cne_ring
 * for more information.
 *
 */

#include <cne_common.h>        // for CNE_NAME_LEN
#include <cne_ring_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The maximum length of a ring name. */
#define CNE_RING_NAMESIZE CNE_NAME_LEN

#ifdef __cplusplus
}
#endif

#endif /* _CNE_RING_H_ */
