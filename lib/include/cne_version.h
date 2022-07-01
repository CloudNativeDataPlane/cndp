/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

/**
 * @file
 *
 * Definitions of CNDP version numbers
 */

#ifndef _CNE_VERSION_H_
#define _CNE_VERSION_H_

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Macro to compute a version number usable for comparisons
 */
#define CNE_VERSION_NUM(a, b, c, d) ((a) << 24 | (b) << 16 | (c) << 8 | (d))

/**
 * All version numbers in one define to compare with CNE_VERSION_NUM()
 */
// clang-format off
#define CNE_VERSION CNE_VERSION_NUM( \
            CNE_VER_YEAR, \
            CNE_VER_MONTH, \
            CNE_VER_MINOR, \
            CNE_VER_RELEASE)
// clang-format on

/**
 * Function returning version string
 *
 * @return
 *     string
 */
static inline const char *
cne_version(void)
{
    static char version[32];
    if (version[0] != 0)
        return version;
    // clang-format off
    if (strlen(CNE_VER_SUFFIX) == 0)
        snprintf(version, sizeof(version), "%s %d.%02d.%d",
            CNE_VER_PREFIX,
            CNE_VER_YEAR,
            CNE_VER_MONTH,
            CNE_VER_MINOR);
    else
        snprintf(version, sizeof(version), "%s %d.%02d.%d%s%d",
            CNE_VER_PREFIX,
            CNE_VER_YEAR,
            CNE_VER_MONTH,
            CNE_VER_MINOR,
            CNE_VER_SUFFIX,
            CNE_VER_RELEASE);
    // clang-format on
    return version;
}

#ifdef __cplusplus
}
#endif

#endif /* CNE_VERSION_H */
