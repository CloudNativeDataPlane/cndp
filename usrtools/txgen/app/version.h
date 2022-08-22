/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_VERSION_H_
#define _TXGEN_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

#define TXGEN_VER_PREFIX     "TX-Gen"
#define TXGEN_VER_CREATED_BY "Keith Wiles"

#define STRINGIFY(x) #x
#define TOSTRING(x)  STRINGIFY(x)

#define TXGEN_VERSION txgen_version_str()

static inline const char *
txgen_version_str(void)
{
    static char version[64];

    if (version[0] != 0)
        return version;
    if (strlen(CNE_VER_SUFFIX) == 0)
        snprintf(version, sizeof(version), "%s %d.%02d.%d", TXGEN_VER_PREFIX, CNE_VER_YEAR,
                 CNE_VER_MONTH, CNE_VER_MINOR);
    else
        snprintf(version, sizeof(version), "%s %d.%02d.%d%s%d", TXGEN_VER_PREFIX, CNE_VER_YEAR,
                 CNE_VER_MONTH, CNE_VER_MINOR,
                 (strlen(CNE_VER_SUFFIX) != 0) ? "-rc" : TOSTRING(CNE_VER_SUFFIX), CNE_VER_RELEASE);
    return version;
}

#ifdef __cplusplus
}
#endif

#endif /* TXGEN_VERSION_H_ */
