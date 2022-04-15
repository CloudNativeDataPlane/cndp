/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_META_H
#define __CNET_META_H

/**
 * @file
 * CNET Metadata information.
 */

#include <cnet_ip_common.h>
#include <cne_inet.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cnet_metadata {
    struct in_caddr faddr;
    struct in_caddr laddr;

    CNE_MARKER end_metadata;
} __cne_cache_aligned; /**< cnet_metadata should be <= 64 bytes */

#ifdef __cplusplus
}
#endif

#endif /* __CNET_META_H */
