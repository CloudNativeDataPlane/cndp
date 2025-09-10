/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, snprintf
#include <stdlib.h>            // for random, free
#include <getopt.h>            // for getopt_long, option
#include <txbuff.h>            // for txbuff_t, txbuff_*
#include <pktmbuf.h>           // for pktmbuf_t, pktmbuf_*
#include <mempool.h>           // for mempool_t
#include <tst_info.h>          // for tst_start, tst_end, TST_*
#include <cne_common.h>        // for CNE_USED, cne_countof
#include <cne_mmap.h>          // for mmap_alloc, mmap_free
#include <cne_stdio.h>         // for cne_printf
#include <stdint.h>            // for uint16_t, uint32_t, uint64_t
#include <string.h>            // for memset
#include <unistd.h>            // for usleep

#include "txbuff_test.h"

#define MAX_PKTS         1024
#define TXBUFF_SIZE_TEST 64
#define PERF_ITERATIONS  100000
#define PERF_BURST_SIZE  32
#define TEST_MBUF_COUNT  2048
#define TEST_MBUF_SIZE   CNE_MBUF_DEFAULT_BUF_SIZE

static mempool_t *mbuf_pool = NULL;
static pktmbuf_info_t *pi   = NULL;

// Test statistics
static uint64_t error_count = 0;
static uint64_t sent_count  = 0;

// Error callback for counting dropped packets
static void
test_error_callback(txbuff_t *buffer, uint16_t sent, uint16_t unsent)
{
    CNE_SET_USED(buffer);
    error_count += unsent;
    sent_count += sent;
}

// Basic functionality tests
static int
test_txbuff_create_free(void)
{
    tst_info_t *tst;
    txbuff_t *buffer;
    int ret = 0;

    tst = tst_start("TXBUFF Create/Free");

    // Test creating buffer for pktdev
    buffer = txbuff_pktdev_create(TXBUFF_SIZE_TEST, NULL, NULL, 0);
    if (!buffer) {
        tst_end(tst, TST_FAILED);
        return -1;
    }

    // Verify buffer properties
    if (buffer->size != TXBUFF_SIZE_TEST) {
        tst_error("Buffer size mismatch: expected %d, got %d\n", TXBUFF_SIZE_TEST, buffer->size);
        ret = -1;
    }

    if (buffer->length != 0) {
        tst_error("Buffer should be empty on creation\n");
        ret = -1;
    }

    if (buffer->txtype != TXBUFF_PKTDEV_FLAG) {
        tst_error("Buffer txtype should be PKTDEV_FLAG\n");
        ret = -1;
    }

    txbuff_free(buffer);

    // Test creating buffer for xskdev with custom error callback
    buffer = txbuff_xskdev_create(TXBUFF_SIZE_TEST, test_error_callback, NULL, NULL);
    if (!buffer) {
        tst_error("Failed to create xskdev buffer\n");
        ret = -1;
    } else {
        if (buffer->txtype != TXBUFF_XSKDEV_FLAG) {
            tst_error("Buffer txtype should be XSKDEV_FLAG\n");
            ret = -1;
        }
        if (buffer->error_cb != test_error_callback) {
            tst_error("Error callback not set correctly\n");
            ret = -1;
        }
        txbuff_free(buffer);
    }

    // Test edge cases - creating buffer with size 0 should still work
    buffer = txbuff_pktdev_create(0, NULL, NULL, 0);
    if (!buffer) {
        tst_error("txbuff with size 0 should be allowed\n");
        ret = -1;
    } else {
        if (buffer->size != 0) {
            tst_error("Buffer size should be 0\n");
            ret = -1;
        }
        txbuff_free(buffer);
    }

    tst_end(tst, ret ? TST_FAILED : TST_PASSED);
    return ret;
}

static int
test_txbuff_count(void)
{
    tst_info_t *tst;
    txbuff_t *buffer;
    int ret = 0;

    tst = tst_start("TXBUFF Count");

    // Test count on NULL buffer
    if (txbuff_count(NULL) != -1) {
        tst_error("txbuff_count(NULL) should return -1\n");
        ret = -1;
    }

    // Test count on empty buffer
    buffer = txbuff_pktdev_create(TXBUFF_SIZE_TEST, NULL, NULL, 0);
    if (!buffer) {
        tst_end(tst, TST_FAILED);
        return -1;
    }

    if (txbuff_count(buffer) != 0) {
        tst_error("Empty buffer should have count 0\n");
        ret = -1;
    }

    txbuff_free(buffer);
    tst_end(tst, ret ? TST_FAILED : TST_PASSED);
    return ret;
}

static int
test_txbuff_error_callback(void)
{
    tst_info_t *tst;
    txbuff_t *buffer;
    int ret = 0;

    tst = tst_start("TXBUFF Error Callback");

    buffer = txbuff_pktdev_create(TXBUFF_SIZE_TEST, NULL, NULL, 0);
    if (!buffer) {
        tst_end(tst, TST_FAILED);
        return -1;
    }

    // Test setting error callback
    ret = txbuff_set_err_callback(buffer, test_error_callback, NULL);
    if (ret != 0) {
        tst_error("Failed to set error callback\n");
        ret = -1;
        goto cleanup;
    }

    if (buffer->error_cb != test_error_callback) {
        tst_error("Error callback not set correctly\n");
        ret = -1;
        goto cleanup;
    }

    // Test setting callback on NULL buffer
    ret = txbuff_set_err_callback(NULL, test_error_callback, NULL);
    if (ret != -1) {
        tst_error("Setting callback on NULL buffer should fail\n");
        ret = -1;
        goto cleanup;
    }

    ret = 0;

cleanup:
    txbuff_free(buffer);
    tst_end(tst, ret ? TST_FAILED : TST_PASSED);
    return ret;
}

static int
test_txbuff_add_flush(void)
{
    tst_info_t *tst;
    txbuff_t *buffer;
    pktmbuf_t *pkts[MAX_PKTS];
    int ret = 0;
    uint16_t i, sent;

    tst = tst_start("TXBUFF Add/Flush");

    if (!mbuf_pool) {
        tst_error("Mempool not initialized\n");
        tst_end(tst, TST_FAILED);
        return -1;
    }

    buffer = txbuff_pktdev_create(TXBUFF_SIZE_TEST, test_error_callback, NULL, 0);
    if (!buffer) {
        tst_end(tst, TST_FAILED);
        return -1;
    }

    // Allocate test packets
    if (pktmbuf_alloc_bulk(pi, pkts, TXBUFF_SIZE_TEST) < 0) {
        tst_error("Failed to allocate packets\n");
        ret = -1;
        goto cleanup;
    }

    // Test adding packets one by one (not filling the buffer completely)
    for (i = 0; i < TXBUFF_SIZE_TEST / 2; i++) {
        sent = txbuff_add(buffer, pkts[i]);
        if (sent != 0) {
            tst_error("txbuff_add should return 0 when not flushing\n");
            ret = -1;
            goto cleanup_pkts;
        }

        if (txbuff_count(buffer) != (i + 1)) {
            tst_error("Buffer count mismatch at iteration %d: expected %d, got %d\n", i, i + 1,
                      txbuff_count(buffer));
            ret = -1;
            goto cleanup_pkts;
        }
    }

    // Test manual flush - this will call the error callback since no real device is configured
    error_count = 0;
    sent_count  = 0;
    sent        = txbuff_flush(buffer);

    // Buffer should be empty after flush regardless of transmission result
    if (txbuff_count(buffer) != 0) {
        tst_error("Buffer should be empty after flush\n");
        ret = -1;
        goto cleanup_pkts;
    }

    // Test automatic flush by filling buffer to capacity
    for (i = 0; i < TXBUFF_SIZE_TEST; i++) {
        if (pktmbuf_alloc_bulk(pi, &pkts[i], 1) < 0) {
            tst_error("Failed to allocate packet %d\n", i);
            ret = -1;
            goto cleanup_pkts;
        }

        sent = txbuff_add(buffer, pkts[i]);

        // When buffer reaches capacity, it should auto-flush
        if (i == TXBUFF_SIZE_TEST - 1) {
            // Buffer should be empty after auto-flush
            if (txbuff_count(buffer) != 0) {
                tst_error("Buffer should be empty after auto-flush\n");
                ret = -1;
                goto cleanup_pkts;
            }
        } else {
            if (sent != 0) {
                tst_error("txbuff_add should return 0 when not auto-flushing at position %d\n", i);
                ret = -1;
                goto cleanup_pkts;
            }
            if (txbuff_count(buffer) != (i + 1)) {
                tst_error("Buffer count mismatch at position %d\n", i);
                ret = -1;
                goto cleanup_pkts;
            }
        }
    }

cleanup_pkts:
    // Note: pkts may have been freed by txbuff operations, so we don't explicitly free them

cleanup:
    txbuff_free(buffer);
    tst_end(tst, ret ? TST_FAILED : TST_PASSED);
    return ret;
}

// Performance test for txbuff operations
static int
test_txbuff_performance(void)
{
    tst_info_t *tst;
    txbuff_t *buffer;
    pktmbuf_t *pkts[PERF_BURST_SIZE];
    uint64_t start_tsc, end_tsc, total_cycles;
    uint32_t i, j;
    int ret = 0;

    tst = tst_start("TXBUFF Performance");

    if (!mbuf_pool) {
        tst_error("Mempool not initialized\n");
        tst_end(tst, TST_FAILED);
        return -1;
    }

    buffer = txbuff_pktdev_create(PERF_BURST_SIZE, txbuff_drop_callback, NULL, 0);
    if (!buffer) {
        tst_end(tst, TST_FAILED);
        return -1;
    }

    // Pre-allocate packets for performance test
    if (pktmbuf_alloc_bulk(pi, pkts, PERF_BURST_SIZE) < 0) {
        tst_error("Failed to allocate packets for performance test\n");
        ret = -1;
        goto cleanup;
    }

    // Warm up
    for (i = 0; i < 1000; i++) {
        for (j = 0; j < PERF_BURST_SIZE; j++) {
            txbuff_add(buffer, pkts[j]);
        }
        txbuff_flush(buffer);
    }

    // Measure txbuff_add performance
    start_tsc = __builtin_ia32_rdtsc();

    for (i = 0; i < PERF_ITERATIONS; i++) {
        for (j = 0; j < PERF_BURST_SIZE; j++) {
            txbuff_add(buffer, pkts[j]);
        }
        txbuff_flush(buffer);
    }

    end_tsc      = __builtin_ia32_rdtsc();
    total_cycles = end_tsc - start_tsc;

    cne_printf("  TXBUFF Add+Flush Performance:\n");
    cne_printf("    Iterations: %u\n", PERF_ITERATIONS);
    cne_printf("    Burst size: %u\n", PERF_BURST_SIZE);
    cne_printf("    Total cycles: %lu\n", total_cycles);
    cne_printf("    Cycles per operation: %.2f\n",
               (double)total_cycles / (PERF_ITERATIONS * PERF_BURST_SIZE));
    cne_printf("    Operations per second: %.2f M\n",
               (double)(PERF_ITERATIONS * PERF_BURST_SIZE) * 2400.0 / total_cycles);

    // Free packets
    for (j = 0; j < PERF_BURST_SIZE; j++) {
        pktmbuf_free(pkts[j]);
    }

cleanup:
    txbuff_free(buffer);
    tst_end(tst, ret ? TST_FAILED : TST_PASSED);
    return ret;
}

// Initialize test environment
static int
setup_test_env(void)
{
    struct mempool_cfg mp_cfg = {0};
    mmap_t *mm;

    // Create memory map
    mm = mmap_alloc(TEST_MBUF_COUNT, TEST_MBUF_SIZE, MMAP_HUGEPAGE_4KB);
    if (!mm) {
        cne_printf("Failed to allocate memory map\n");
        return -1;
    }

    // Setup mempool configuration
    mp_cfg.addr     = mmap_addr(mm);
    mp_cfg.objcnt   = TEST_MBUF_COUNT;
    mp_cfg.objsz    = TEST_MBUF_SIZE;
    mp_cfg.cache_sz = MEMPOOL_CACHE_MAX_SIZE;

    // Create mempool
    mbuf_pool = mempool_create(&mp_cfg);
    if (!mbuf_pool) {
        cne_printf("Failed to create mempool\n");
        mmap_free(mm);
        return -1;
    }

    // Create pktmbuf info
    pi = pktmbuf_pool_create(mmap_addr(mm), TEST_MBUF_COUNT, TEST_MBUF_SIZE, MEMPOOL_CACHE_MAX_SIZE,
                             NULL);
    if (!pi) {
        cne_printf("Failed to create pktmbuf info\n");
        mempool_destroy(mbuf_pool);
        mmap_free(mm);
        return -1;
    }

    return 0;
}

// Cleanup test environment
static void
cleanup_test_env(void)
{
    if (pi) {
        pktmbuf_destroy(pi);
        pi = NULL;
    }

    if (mbuf_pool) {
        mempool_destroy(mbuf_pool);
        mbuf_pool = NULL;
    }
}

int
txbuff_main(int argc, char **argv)
{
    int ret = 0;

    CNE_SET_USED(argc);
    CNE_SET_USED(argv);

    // Setup test environment
    if (setup_test_env() < 0) {
        cne_printf("Failed to setup test environment\n");
        return -1;
    }

    cne_printf("Running TXBUFF (Packet Transmission Buffer) Tests\n");

    // Run all tests
    ret |= test_txbuff_create_free();
    ret |= test_txbuff_count();
    ret |= test_txbuff_error_callback();
    ret |= test_txbuff_add_flush();
    ret |= test_txbuff_performance();

    // Cleanup
    cleanup_test_env();

    return ret;
}
