/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

// IWYU pragma: no_include <bits/mman-map-flags-generic.h>

#include <signal.h>            // for sigaction, SIGBUS, sigaddset, sigemptyset
#include <stdbool.h>           // for bool, false, true
#include <string.h>            // for strerror, memset
#include <sys/mman.h>          // for munmap, MAP_FAILED, mmap, MAP_ANONYMOUS
#include <setjmp.h>            // for siglongjmp, sigjmp_buf, sigsetjmp
#include <cne_common.h>        // for cne_log2_u64, cne_countof, CNE_ALIGN_CEIL
#include <cne_log.h>           // for CNE_LOG_ERR, CNE_LOG_WARNING, CNE_WARN
#include <errno.h>             // for errno
#include <strings.h>           // for strcasecmp
#include <unistd.h>            // for getpagesize
#include <stdint.h>            // for uint64_t, uint32_t
#include <stdlib.h>            // for free, calloc
#include <cne_mmap.h>

#include "mmap_private.h"        // for mmap_data
#include "cne_mmap.h"            // for mmap_sizes_t, MMAP_HUGEPAGE_4KB, MMAP_HUGE...

#ifdef __clang__
/* clang doesn't have -Wclobbered */
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wclobbered"
#endif

static mmap_stats_t mmap_stats;
static mmap_type_t mmap_default_type = MMAP_HUGEPAGE_4KB;

static sigjmp_buf huge_jmpenv;
static struct sigaction old_sigbus_action;
static bool restore_old_sigbus;

/*
 * The following SIGBUS signal handling is used when a mapping to a 1GB or 2MB page succeeds but
 * access to the page is denied. When a SIGBUS occurs, an attempt is made to fallback to a
 * smaller page size.
 */
static void
sigbus_handler(int signum __cne_unused)
{
    siglongjmp(huge_jmpenv, -1);
}

static void
start_sigbus_handler(void)
{
    struct sigaction act;
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, SIGBUS);

    memset(&act, 0, sizeof(act));
    act.sa_handler = sigbus_handler;
    act.sa_mask    = mask;
    act.sa_flags   = 0;

    if (sigaction(SIGBUS, &act, &old_sigbus_action))
        CNE_WARN("Failed to set SIGBUS action: %s\n", strerror(errno));
    else
        restore_old_sigbus = true;
}

static void
stop_sigbus_handler(void)
{
    if (restore_old_sigbus) {
        restore_old_sigbus = false;
        if (sigaction(SIGBUS, &old_sigbus_action, NULL))
            CNE_WARN("Failed to restore old SIGBUS action: %s\n", strerror(errno));
    }
}

static struct {
    const char *name;
    mmap_type_t typ;
} mmap_types[] = {
    // clang-format off
    { "4KB", MMAP_HUGEPAGE_4KB },
    { "2MB", MMAP_HUGEPAGE_2MB },
    { "1GB", MMAP_HUGEPAGE_1GB }
    // clang-format on
};

static int
pagesz_flags(uint64_t page_sz)
{
    /* as per mmap() manpage, all page sizes are log2 of page size
     * shifted by MAP_HUGE_SHIFT
     */
    int log2 = cne_log2_u64(page_sz);

    /* Do not set use huge pages for default page size */
    if (page_sz == (uint64_t)getpagesize())
        return 0;
    return (log2 << MAP_HUGE_SHIFT) | MAP_HUGETLB;
}

mmap_type_t
mmap_type_by_name(const char *htype)
{
    if (htype && htype[0] != '\0') {
        if (!strcasecmp(htype, "default"))
            return mmap_default_type;

        for (int i = 0; i < cne_countof(mmap_types); i++) {
            if (!strcasecmp(htype, mmap_types[i].name))
                return mmap_types[i].typ;
        }
    }

    return mmap_default_type;
}

const char *
mmap_name_by_type(mmap_type_t typ)
{
    if (typ < cne_countof(mmap_types))
        return mmap_types[typ].name;

    return mmap_types[mmap_default_type].name;
}

void
mmap_set_default(mmap_type_t htype)
{
    mmap_default_type = htype;
}

void
mmap_set_default_by_name(const char *name)
{
    mmap_set_default(mmap_type_by_name(name));
}

static void *
__alloc_mem(struct mmap_data *mm, mmap_type_t typ)
{
    int flags = MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE;
    uint64_t len;

    mm->typ   = typ;
    mm->align = mmap_stats.sizes[typ].page_sz;

    len    = (uint64_t)mm->bufcnt * (uint64_t)mm->bufsz;
    mm->sz = CNE_ALIGN_CEIL(len, mm->align);

    flags |= pagesz_flags(mmap_stats.sizes[typ].page_sz);

    /* map the segment, and populate page tables, the kernel fills
     * this segment with zeros if it's a new page.
     */
    return mmap(NULL, mm->sz, PROT_READ | PROT_WRITE, flags, -1, 0);
}

mmap_t *
mmap_alloc(uint32_t bufcnt, uint32_t bufsz, mmap_type_t typ)
{
    struct mmap_data *mm;
    void *va;

    if (mmap_stats.inited == 0) {
        mmap_stats.inited = 1;

        mmap_stats.sizes[MMAP_HUGEPAGE_4KB].page_sz = getpagesize();
        mmap_stats.sizes[MMAP_HUGEPAGE_2MB].page_sz = (2 * 1024 * 1024);
        mmap_stats.sizes[MMAP_HUGEPAGE_1GB].page_sz = (1024 * 1024 * 1024);
    }

    if (typ < MMAP_HUGEPAGE_4KB || typ >= MMAP_HUGEPAGE_CNT)
        typ = MMAP_HUGEPAGE_4KB;

    mm = calloc(1, sizeof(struct mmap_data));
    if (!mm)
        CNE_NULL_RET("Failed to allocate mmap_data structure\n");

    if (!bufcnt || !bufsz)
        CNE_ERR_GOTO(leave, "bufcnt %u * bufsz %u is zero\n", bufcnt, bufsz);

    mm->bufcnt = bufcnt;
    mm->bufsz  = bufsz;

retry:
    /* Try the requested size and if not available, degrade to the next available size */
    switch (typ) {
    case MMAP_HUGEPAGE_1GB:
        va = __alloc_mem(mm, MMAP_HUGEPAGE_1GB);
        if (va != MAP_FAILED)
            break;
        CNE_WARN("Failed to allocate %s hugepages, trying %s pages\n",
                 mmap_types[MMAP_HUGEPAGE_1GB].name, mmap_types[MMAP_HUGEPAGE_2MB].name);
        /* fall through */

    case MMAP_HUGEPAGE_2MB:
        va = __alloc_mem(mm, MMAP_HUGEPAGE_2MB);
        if (va != MAP_FAILED)
            break;
        CNE_WARN("Failed to allocate %s hugepages, trying %s pages\n",
                 mmap_types[MMAP_HUGEPAGE_2MB].name, mmap_types[MMAP_HUGEPAGE_4KB].name);
        /* fall through */

    default:
    case MMAP_HUGEPAGE_4KB:
        va = __alloc_mem(mm, MMAP_HUGEPAGE_4KB);
        if (va == MAP_FAILED)
            CNE_ERR_GOTO(leave, "Failed to allocate %s pages for %'ld bytes:\n    Error: %s\n",
                         mmap_types[MMAP_HUGEPAGE_4KB].name,
                         ((uint64_t)mm->bufcnt * (uint64_t)mm->bufsz), strerror(errno));
        break;
    }

    mm->addr = va;

    /* In linux, hugetlb limitations, like cgroup, are
     * enforced at fault time instead of mmap(), even
     * with the option of MAP_POPULATE. Kernel will send
     * a SIGBUS signal. To avoid to be killed, save stack
     * environment here, if SIGBUS happens, we can jump
     * back here.
     */
    if (sigsetjmp(huge_jmpenv, 1)) {
        stop_sigbus_handler();

        /* Unmap previous failing region before trying a new one */
        if (munmap(mm->addr, mm->sz))
            CNE_ERR_GOTO(leave, "munmap(%p, %ld) failed: %s\n", mm->addr, mm->sz, strerror(errno));

        mm->addr = NULL;

        switch (mm->typ) {
        case MMAP_HUGEPAGE_1GB:
            CNE_WARN("Failed to allocate %s hugepages, trying %s pages\n",
                     mmap_types[MMAP_HUGEPAGE_1GB].name, mmap_types[MMAP_HUGEPAGE_2MB].name);
            typ = MMAP_HUGEPAGE_2MB;
            break;
        case MMAP_HUGEPAGE_2MB:
            CNE_WARN("Failed to allocate %s hugepages, trying %s pages\n",
                     mmap_types[MMAP_HUGEPAGE_2MB].name, mmap_types[MMAP_HUGEPAGE_4KB].name);
            typ = MMAP_HUGEPAGE_4KB;
            break;
        case MMAP_HUGEPAGE_4KB:
        default:
            CNE_ERR_GOTO(leave, "Failed to allocate %s pages for %'ld bytes\n",
                         mmap_types[MMAP_HUGEPAGE_4KB].name,
                         (uint64_t)mm->bufcnt * (uint64_t)mm->bufsz);
        }

        goto retry;
    }

    /* we need to trigger a write to the page to enforce page fault and
     * ensure that page is accessible to us, but we can't overwrite value
     * that is already there, so read the old value, and write it back.
     * kernel populates the page with zeroes initially.
     */
    start_sigbus_handler();
    *(volatile int *)va = *(volatile int *)va;
    stop_sigbus_handler();

    mmap_stats.sizes[typ].allocated += mm->sz;
    mmap_stats.sizes[typ].num_allocated++;

    return (mmap_t *)mm;

leave:
    free(mm);
    return NULL;
}

int
mmap_free(mmap_t *_mm)
{
    struct mmap_data *mm = _mm;

    if (!mm)
        return 0;

    if (mm->typ < MMAP_HUGEPAGE_4KB || mm->typ >= MMAP_HUGEPAGE_CNT)
        CNE_ERR_RET("mmap type is invalid %d\n", mm->typ);

    if (mm->addr && mm->sz) {
        if (munmap(mm->addr, mm->sz))
            /* Do not free mm if munmap fails so application can handle it */
            CNE_ERR_RET("munmap(%p, %ld) failed: %s\n", mm->addr, mm->sz, strerror(errno));
        else {
            mmap_sizes_t *ss;

            ss = &mmap_stats.sizes[mm->typ];
            ss->freed += mm->sz;
            ss->num_freed++;
        }
    }

    free(mm);
    return 0;
}

void *
mmap_addr_at_offset(mmap_t *_mm, size_t offset)
{
    struct mmap_data *mm = _mm;

    if (mm && offset <= mmap_size(mm, NULL, NULL))
        return CNE_PTR_ADD(mm->addr, offset);
    else
        return NULL;
}

void *
mmap_addr(mmap_t *_mm)
{
    return mmap_addr_at_offset(_mm, 0);
}

size_t
mmap_size(mmap_t *_mm, uint32_t *bufcnt, uint32_t *bufsz)
{
    struct mmap_data *mm = _mm;

    if (mm) {
        if (bufcnt)
            *bufcnt = mm->bufcnt;
        if (bufsz)
            *bufsz = mm->bufsz;
        return mm->sz;
    }

    return 0;
}

#ifdef __clang__
/* clang doesn't have -Wclobbered */
#else
#pragma GCC diagnostic pop
#endif
