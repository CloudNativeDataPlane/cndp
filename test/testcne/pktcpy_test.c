/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for EOF, NULL, size_t
#include <stdint.h>            // for uint64_t
#include <getopt.h>            // for getopt_long, option
#include <tst_info.h>          // for tst_ok, tst_end, tst_start, tst_info_t
#include <cne_common.h>        // for CNE_SET_USED
#include <cne_pktcpy.h>        // for cne_pktcpy
#include <cne_mmap.h>          // for mmap_addr, mmap_alloc, mmap_free, MMAP...
#include <cne_cycles.h>        // for cne_rdtsc_precise
#include <cne_system.h>        // for cne_get_timer_hz
#include <string.h>            // for memcpy

#include "pktcpy_test.h"

#define _1K 1024L
#define _1M (_1K * _1K)
#define _1G (_1M * _1M)

struct pktcpy_tests {
    int overlap;
    int sec;
    uint64_t bufsz;
    mmap_type_t mtype;
} tests[] = {{0, 1, 8},           {0, 1, 16},          {0, 1, 64},
             {0, 1, 128},         {0, 1, 512},         {0, 1, _1K},
             {0, 1, (2 * _1K)},   {0, 1, (4 * _1K)},   {0, 1, (8 * _1K)},
             {0, 1, (16 * _1K)},  {0, 1, (32 * _1K)},  {0, 1, (64 * _1K)},
             {0, 1, (128 * _1K)}, {0, 1, (512 * _1K)}, {0, 1, _1M},
             {0, 1, (2 * _1M)},   {0, 1, (4 * _1M)},   {0, 1}};

static uint64_t
runcpy(struct pktcpy_tests *tst, void *(*fn)(void *d, const void *s, size_t len), uint64_t *_iter)
{
    mmap_t *mm = mmap_alloc(2, tst->bufsz, MMAP_HUGEPAGE_2MB);
    uint64_t begin, stop, iter;
    uint64_t cycles;

    if (!mm)
        return 0;

    char *s = mmap_addr(mm);
    char *d = s + tst->bufsz;

    iter  = 0;
    begin = cne_rdtsc_precise();
    stop  = begin + (cne_get_timer_hz() * tst->sec);
    while (cne_rdtsc_precise() < stop) {
        fn(d, s, tst->bufsz);
        iter++;
    }
    if (iter)
        cycles = (cne_get_timer_hz() * tst->sec) / iter;
    else
        /* iter should never be zero unless time is stopped. The check silences klocwork */
        cycles = (uint64_t)-1;

    mmap_free(mm);

    *_iter = iter;

    return cycles;
}

int
pktcpy_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};
    uint64_t pktcpy_cycles, memcpy_cycles;
    uint64_t pktcpy_iter, memcpy_iter;

    argvopt = argv;

    optind = 0;
    while ((opt = getopt_long(argc, argvopt, "V", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("pktcpy test/profile");

    memcpy_iter   = 0;
    memcpy_cycles = 0;
    pktcpy_cycles = 0;
    pktcpy_iter   = 0;
    tst_ok("%10s|%10s|%10s|%10s|\n", " ", "pktcpy", " ", "memcpy");
    tst_ok("%10s|%10s|%10s|%10s|%10s\n", "bytes", "cycles", "iter", "cycles", "iter");
    for (int i = 0; tests[i].bufsz; i++) {
        pktcpy_cycles = runcpy(&tests[i], cne_pktcpy, &pktcpy_iter);
        memcpy_cycles = runcpy(&tests[i], memcpy, &memcpy_iter);

        tst_ok("%10ld|%10ld|%10ld|%10ld|%10ld\n", tests[i].bufsz, pktcpy_cycles, pktcpy_iter,
               memcpy_cycles, memcpy_iter);
    }

    tst_end(tst, TST_PASSED);

    return 0;
}
