/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef __CHNL_OPEN_PRIV_H
#define __CHNL_OPEN_PRIV_H

/**
 * @file
 * Channel open private data to create a channel with socat list strings.
 */

#include <stdint.h>

#include <cne_common.h>
#include "cnet_const.h"

#ifdef __cplusplus
extern "C" {
#endif

// clang-format off
enum {
    UDP4_LISTEN,    /**< UDP4 Listen */
    UDP4_CONNECT,   /**< UDP4 Connect */
    UDP6_LISTEN,    /**< UDP4 Listen */
    UDP6_CONNECT,   /**< UDP4 Connect */
    TCP4_LISTEN,    /**< TCP4 Listen */
    TCP4_CONNECT,   /**< TCP4 Connect */
    TCP6_LISTEN,    /**< TCP4 Listen */
    TCP6_CONNECT,   /**< TCP4 Connect */
    MAX_OPEN_TYPES  /**< Max number of open types */
};
// clang-format on

#ifdef __cplusplus
}
#endif

#endif /* __CHNL_OPEN_PRIV_H */
