/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2025 Intel Corporation
 */

#include <cne_common.h>
#include <mempool.h>

/* Prototype required to fix "no previous prototype for function" error */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* When launching the mempool_create fuzz test, the -rss_limit_mb=N parameter
 * needs to be passed. Otherwise, an out of memory error will happen.
 */
extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct mempool_cfg cinfo = {0};
    mempool_t *mp            = NULL;

    if (size > sizeof(mempool_cfg))
        size = sizeof(mempool_cfg);
    memcpy(&cinfo, data, size);
    cinfo.mp_init  = NULL;
    cinfo.obj_init = NULL;
    if (cinfo.objsz == 0)
        cinfo.objsz = 2048;
    if (cinfo.objcnt == 0)
        cinfo.objcnt = 4096;
    cinfo.addr = NULL;
    cinfo.cache_sz %= MEMPOOL_CACHE_MAX_SIZE;
    mp = mempool_create(&cinfo);
    if (mp)
        mempool_destroy(mp);
    return 0;
}
