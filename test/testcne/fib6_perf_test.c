/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#include <stdio.h>               // for NULL, EOF
#include <stdint.h>              // for uint64_t, uint8_t, uint32_t, int64_t
#include <stdlib.h>              // for srand
#include <string.h>              // for memcpy
#include <getopt.h>              // for getopt_long, option
#include <cne_cycles.h>          // for cne_rdtsc
#include <private_fib6.h>        // for CNE_FIB6_TRIE
#include <cne_fib6.h>            // for cne_fib6_conf, cne_fib6_conf::(anonymous...
#include <tst_info.h>            // for tst_end, tst_start, TST_FAILED, TST_PASSED

#include "lpm6_data_test.h"        // for rules_tbl_entry, NUM_ROUTE_ENTRIES, NUM_...
#include "fib_test.h"              // for fib6_perf_main
#include "cne_common.h"            // for CNE_MIN
#include "cne_stdio.h"             // for cne_printf

#define TEST_FIB_ASSERT(cond)                            \
    do {                                                 \
        if (!(cond)) {                                   \
            cne_printf("Error at line %d:\n", __LINE__); \
            return -1;                                   \
        }                                                \
    } while (0)

#define ITERATIONS   (1 << 10)
#define BATCH_SIZE   100000
#define NUMBER_TBL8S (1 << 16)

static void
print_route_distribution(const struct rules_tbl_entry *table, uint32_t n)
{
    unsigned int i, j;

    cne_printf("Route distribution per prefix width:\n");
    cne_printf("DEPTH    QUANTITY (PERCENT)\n");
    cne_printf("---------------------------\n");

    /* Count depths. */
    for (i = 1; i <= 128; i++) {
        unsigned int depth_counter = 0;
        double percent_hits;

        for (j = 0; j < n; j++)
            if (table[j].depth == (uint8_t)i)
                depth_counter++;

        percent_hits = ((double)depth_counter) / ((double)n) * 100;
        cne_printf("%.2u%15u (%.2f)\n", i, depth_counter, percent_hits);
    }
    cne_printf("\n");
}

static inline uint8_t
bits_in_nh(uint8_t nh_sz)
{
    return 8 * (1 << nh_sz);
}

static inline uint64_t
get_max_nh(uint8_t nh_sz)
{
    return ((1ULL << (bits_in_nh(nh_sz) - 1)) - 1);
}

static int
test_fib6_perf(void)
{
    struct cne_fib6 *fib = NULL;
    struct cne_fib6_conf conf;
    uint64_t begin, total_time;
    unsigned int i, j;
    uint64_t next_hop_add;
    int status    = 0;
    int64_t count = 0;
    uint8_t ip_batch[NUM_IPS_ENTRIES][16];
    uint64_t next_hops[NUM_IPS_ENTRIES];

    conf.type          = CNE_FIB6_TRIE;
    conf.default_nh    = 0;
    conf.max_routes    = 1000000;
    conf.trie.nh_sz    = CNE_FIB6_TRIE_4B;
    conf.trie.num_tbl8 = CNE_MIN(get_max_nh(conf.trie.nh_sz), 1000000U);

    srand(cne_rdtsc());

    cne_printf("No. routes = %u\n", (unsigned int)NUM_ROUTE_ENTRIES);

    print_route_distribution(large_route_table, (uint32_t)NUM_ROUTE_ENTRIES);

    /* Only generate IPv6 address of each item in large IPS table,
     * here next_hop is not needed.
     */
    generate_large_ips_table(0);

    fib = cne_fib6_create(__func__, &conf);
    TEST_FIB_ASSERT(fib != NULL);

    /* Measure add. */
    begin = cne_rdtsc();

    for (i = 0; i < NUM_ROUTE_ENTRIES; i++) {
        next_hop_add = (i & ((1 << 14) - 1)) + 1;
        if (cne_fib6_add(fib, large_route_table[i].ip, large_route_table[i].depth, next_hop_add) ==
            0)
            status++;
    }
    /* End Timer. */
    total_time = cne_rdtsc() - begin;
    cne_printf("The fib6_perf result is as follows:\n");
    cne_printf("Unique added entries = %d\n", status);
    cne_printf("Average FIB Add: %g cycles\n", (double)total_time / NUM_ROUTE_ENTRIES);

    /* Measure bulk Lookup */
    total_time = 0;
    count      = 0;

    for (i = 0; i < NUM_IPS_ENTRIES; i++)
        memcpy(ip_batch[i], large_ips_table[i].ip, 16);

    for (i = 0; i < ITERATIONS; i++) {

        /* Lookup per batch */
        begin = cne_rdtsc();
        cne_fib6_lookup_bulk(fib, ip_batch, next_hops, NUM_IPS_ENTRIES);
        total_time += cne_rdtsc() - begin;

        for (j = 0; j < NUM_IPS_ENTRIES; j++)
            if (next_hops[j] == 0)
                count++;
    }
    cne_printf("BULK FIB Lookup: %.1f cycles (fails = %.1f%%)\n",
               (double)total_time / ((double)ITERATIONS * BATCH_SIZE),
               (count * 100.0) / (double)(ITERATIONS * BATCH_SIZE));

    /* Delete */
    status = 0;
    begin  = cne_rdtsc();

    for (i = 0; i < NUM_ROUTE_ENTRIES; i++) {
        /* cne_fib_delete(fib, ip, depth) */
        status += cne_fib6_delete(fib, large_route_table[i].ip, large_route_table[i].depth);
    }

    total_time = cne_rdtsc() - begin;

    cne_printf("Average FIB Delete: %g cycles\n", (double)total_time / NUM_ROUTE_ENTRIES);

    cne_fib6_free(fib);

    return 0;
}

int
fib6_perf_main(int argc, char **argv)
{
    tst_info_t *tst;
    int opt, flags = 0;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "v", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'v':
            break;
        default:
            break;
        }
    }
    (void)flags;

    tst = tst_start("FIB6 Perf");

    if (test_fib6_perf() < 0)
        goto leave;

    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_end(tst, TST_FAILED);
    return -1;
}
