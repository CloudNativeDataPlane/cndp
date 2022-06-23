/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

#include <cne_mmap.h>
#include <string.h>
#include <assert.h>
/* Prototype required to fix "no previous prototype for function" error */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* When launching the mmap_alloc fuzz test, the -rss_limit_mb=N parameter
 * needs to be passed. Otherwise, an out of memory error will happen.
 */
extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *offset = NULL;
    mmap_t *mm   = NULL;

    struct {
        uint32_t bufcnt      = 0;
        uint32_t bufsz       = 0;
        mmap_type_t hugepage = MMAP_HUGEPAGE_DEFAULT;
    } args;

    if (size < sizeof(args))
        return 0;
    memcpy(&args.bufcnt, data, sizeof(uint32_t));
    memcpy(&args.bufsz, data + sizeof(args.bufcnt), sizeof(uint32_t));
    memcpy(&args.hugepage, data + sizeof(uint64_t), sizeof(int));
    if (args.bufcnt > 4 * 1024 || args.bufcnt == 0)
        args.bufcnt = 4 * 1024;

    if (args.bufsz > 4 * 1024 || args.bufsz == 0)
        args.bufsz = 4 * 1024;

    mm = mmap_alloc(args.bufcnt, args.bufsz, args.hugepage);
    assert(mm);
    offset = (char *)mmap_addr_at_offset(mm, args.bufcnt * args.bufsz / 2);
    assert(offset == (char *)mmap_addr(mm) + args.bufcnt * args.bufsz / 2);
    if (mm)
        mmap_free(mm);
    return 0;
}
