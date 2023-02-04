/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#include <errno.h>
#include <stdlib.h>

#include <cne_common.h>
#include <cne_dsa.h>
#include <cne_mmap.h>
#include <pktmbuf.h>
#include <tst_info.h>

#include "dsa_test.h"

#define COPY_LEN 1024

/* all tests use the same pktmbuf pool */
static pktmbuf_info_t *pi;
static mmap_t *mm;

static int
alloc_pool(void)
{
    if (pi || mm) {
        tst_error("pktmbuf pool is already allocated\n");
        return -1;
    }

    mm = mmap_alloc(DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, MMAP_HUGEPAGE_DEFAULT);
    if (!mm) {
        tst_error("mmap_alloc() failed\n");
        return -1;
    }

    pi = pktmbuf_pool_create(mmap_addr(mm), DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, 0, NULL);
    if (!pi) {
        tst_error("pktmbuf_pool_create() failed\n");
        mmap_free(mm);
        return -1;
    }

    return 0;
}

static void
free_pool(void)
{
    if (pi)
        pktmbuf_destroy(pi);
    pi = NULL;

    if (mm)
        mmap_free(mm);
    mm = NULL;
}

static int
test_single_copy(uint16_t dev)
{
    pktmbuf_t *completed[2] = {0};
    char *src_data, *dst_data;
    pktmbuf_t *src, *dst;
    int i, ret = -1;

    src = pktmbuf_alloc(pi);
    dst = pktmbuf_alloc(pi);
    if (!src || !dst) {
        tst_error("pktmbuf_alloc() failed\n");
        goto leave;
    }

    src_data = pktmbuf_mtod(src, char *);
    dst_data = pktmbuf_mtod(dst, char *);

    for (i = 0; i < COPY_LEN; i++)
        src_data[i] = rand() & 0xFF;

    if (dsa_enqueue_copy(dev, (uintptr_t)src_data, (uintptr_t)dst_data, COPY_LEN, (uintptr_t)src,
                         (uintptr_t)dst) != 1) {
        tst_error("dsa_enqueue_copy() failed\n");
        goto leave;
    }

    if (dsa_perform_ops(dev)) {
        tst_error("dsa_perform_ops() failed\n");
        goto leave;
    }
    usleep(10);

    if (dsa_completed_ops(dev, 1, NULL, NULL, (void *)&completed[0], (void *)&completed[1]) != 1) {
        tst_error("dsa_completed_ops() failed\n");
        goto leave;
    }

    if (completed[0] != src || completed[1] != dst) {
        tst_error("completions: got (%p, %p), not (%p,%p)\n", completed[0], completed[1], src, dst);
        goto leave;
    }

    for (i = 0; i < COPY_LEN; i++) {
        if (dst_data[i] != src_data[i]) {
            tst_error("Data mismatch at char %u: got %02x not %02x\n", i, dst_data[i], src_data[i]);
            goto leave;
        }
    }

    /* check ring is now empty */
    if (dsa_completed_ops(dev, 1, NULL, NULL, (void *)&completed[0], (void *)&completed[1]) != 0) {
        tst_error("unexpected return handles from dsa_completed_ops()\n");
        goto leave;
    }

    ret = 0;
leave:
    pktmbuf_free(src);
    pktmbuf_free(dst);
    return ret;
}

static int
test_single_copy_4(uint16_t dev)
{
    const uint16_t max_completions = 16;
    pktmbuf_t *completed[32]       = {0};
    const uint16_t max_ops         = 4;
    char *src_data, *dst_data;
    pktmbuf_t *src, *dst;
    int i, ret = -1;

    src = pktmbuf_alloc(pi);
    dst = pktmbuf_alloc(pi);
    if (!src || !dst) {
        tst_error("pktmbuf_alloc() failed\n");
        goto leave;
    }

    src_data = pktmbuf_mtod(src, char *);
    dst_data = pktmbuf_mtod(dst, char *);

    for (i = 0; i < COPY_LEN; i++)
        src_data[i] = rand() & 0xFF;

    for (i = 0; i < max_ops; i++) {
        if (dsa_enqueue_copy(dev, (uintptr_t)src_data, (uintptr_t)dst_data, COPY_LEN,
                             (uintptr_t)src, (uintptr_t)dst) != 1) {
            tst_error("dsa_enqueue_copy() failed\n");
            goto leave;
        }
        if (dsa_perform_ops(dev)) {
            tst_error("dsa_perform_ops() failed\n");
            goto leave;
        }
    }

    usleep(10);

    if (dsa_completed_ops(dev, max_completions, NULL, NULL, (void *)&completed[0],
                          (void *)&completed[max_completions]) != max_ops) {
        tst_error("dsa_completed_ops() failed\n");
        goto leave;
    }

    if (completed[0] != src || completed[max_completions] != dst) {
        tst_error("completions: got (%p, %p), not (%p,%p)\n", completed[0],
                  completed[max_completions], src, dst);
        goto leave;
    }

    for (i = 0; i < COPY_LEN; i++) {
        if (dst_data[i] != src_data[i]) {
            tst_error("Data mismatch at char %u: got %02x not %02x\n", i, dst_data[i], src_data[i]);
            goto leave;
        }
    }

    /* check ring is now empty */
    if (dsa_completed_ops(dev, 1, NULL, NULL, (void *)&completed[0], (void *)&completed[1]) != 0) {
        tst_error("unexpected return handles from dsa_completed_ops()\n");
        goto leave;
    }

    ret = 0;
leave:
    pktmbuf_free(src);
    pktmbuf_free(dst);
    return ret;
}

static int
do_multi_copies(uint16_t dev, int split_batches, int split_completions)
{
    pktmbuf_t *srcs[32], *dsts[32];
    pktmbuf_t *completed_src[64];
    pktmbuf_t *completed_dst[64];
    uint32_t i, j;
    int ret = -1;

    memset(srcs, 0, sizeof(srcs));
    memset(dsts, 0, sizeof(dsts));

    for (i = 0; i < cne_countof(srcs); i++) {
        char *src_data;

        if (split_batches && i == cne_countof(srcs) / 2)
            dsa_perform_ops(dev);

        srcs[i] = pktmbuf_alloc(pi);
        dsts[i] = pktmbuf_alloc(pi);
        if (!srcs[i] || !dsts[i]) {
            tst_error("pktmbuf_alloc() failed\n");
            goto leave;
        }

        src_data = pktmbuf_mtod(srcs[i], char *);

        for (j = 0; j < COPY_LEN; j++)
            src_data[j] = rand() & 0xFF;

        if (dsa_enqueue_copy(dev, pktmbuf_mtod(srcs[i], uint64_t), pktmbuf_mtod(dsts[i], uint64_t),
                             COPY_LEN, (uintptr_t)srcs[i], (uintptr_t)dsts[i]) != 1) {
            tst_error("dsa_enqueue_copy() failed for index %d\n", i);
            goto leave;
        }
    }

    if (dsa_perform_ops(dev)) {
        tst_error("dsa_perform_ops() failed\n");
        goto leave;
    }

    usleep(10);

    if (split_completions) {
        /* gather completions in two halves */
        uint16_t half_len = cne_countof(srcs) / 2;

        if (dsa_completed_ops(dev, half_len, NULL, NULL, (void *)completed_src,
                              (void *)completed_dst) != half_len) {
            tst_error("dsa_completed_ops() failed - first half\n");
            goto leave;
        }

        if (dsa_completed_ops(dev, half_len, NULL, NULL, (void *)&completed_src[half_len],
                              (void *)&completed_dst[half_len]) != half_len) {
            tst_error("dsa_completed_ops() failed - second half\n");
            goto leave;
        }
    } else {
        /* gather all completions in one go */
        if (dsa_completed_ops(dev, cne_countof(completed_src), NULL, NULL, (void *)completed_src,
                              (void *)completed_dst) != cne_countof(srcs)) {
            tst_error("dsa_completed_ops() failed\n");
            goto leave;
        }
    }

    for (i = 0; i < cne_countof(srcs); i++) {
        char *src_data, *dst_data;

        if (completed_src[i] != srcs[i]) {
            tst_error("Error with source pointer %u\n", i);
            goto leave;
        }
        if (completed_dst[i] != dsts[i]) {
            tst_error("Error with dest pointer %u\n", i);
            goto leave;
        }

        src_data = pktmbuf_mtod(srcs[i], char *);
        dst_data = pktmbuf_mtod(dsts[i], char *);
        for (j = 0; j < COPY_LEN; j++) {
            if (src_data[j] != dst_data[j]) {
                tst_error("Error with copy of packet %u, byte %u\n", i, j);
                goto leave;
            }
        }
    }

    ret = 0;
leave:
    for (i = 0; i < cne_countof(srcs); i++) {
        pktmbuf_free(srcs[i]);
        pktmbuf_free(dsts[i]);
    }
    return ret;
}

static int
test_multi_copies(uint16_t dev)
{
    if (do_multi_copies(dev, 0, 0)) /* enqueue and complete one batch at a time */
        return -1;
    if (do_multi_copies(dev, 1, 0)) /* enqueue two batches then complete both */
        return -1;
    if (do_multi_copies(dev, 0, 1)) /* enqueue one batch then complete in two halves */
        return -1;
    return 0;
}

static int
test_enqueue_fill(uint16_t dev)
{
    const uint32_t lengths[] = {8, 64, 1024, 50, 100, 89};
    uint64_t pattern         = 0xfedcba9876543210;
    pktmbuf_t *completed[2]  = {0};
    pktmbuf_t *dst;
    char *dst_data;
    uint32_t i, j;
    int ret = -1;

    dst = pktmbuf_alloc(pi);
    if (!dst) {
        tst_error("pktmbuf_alloc() failed\n");
        goto leave;
    }

    dst_data = pktmbuf_mtod(dst, char *);

    for (i = 0; i < cne_countof(lengths); i++) {
        /* reset dst_data */
        memset(dst_data, 0, lengths[i]);

        /* perform the fill operation */
        if (dsa_enqueue_fill(dev, pattern, (uintptr_t)dst_data, lengths[i], (uintptr_t)dst) != 1) {
            tst_error("dsa_enqueue_fill() failed\n");
            goto leave;
        }

        dsa_perform_ops(dev);
        usleep(10);

        if (dsa_completed_ops(dev, 1, NULL, NULL, (void *)&completed[0], (void *)&completed[1]) !=
            1) {
            tst_error("dsa_completed_ops() failed\n");
            goto leave;
        }

        /* check the result */
        for (j = 0; j < lengths[i]; j++) {
            char pat_byte = ((char *)&pattern)[j % 8];

            if (dst_data[j] != pat_byte) {
                tst_error("Error with fill operation (lengths = %u): got (%x), not (%x)\n",
                          lengths[i], dst_data[j], pat_byte);
                goto leave;
            }
        }
    }

    ret = 0;
leave:
    pktmbuf_free(dst);
    return ret;
}

static int
test_burst_capacity(uint16_t dev)
{
#define BURST_SIZE 64
    const uint32_t ring_space = dsa_burst_capacity(dev);
    uint32_t i, j, iter, old_cap, cap, length = 1024;
    uintptr_t completions[BURST_SIZE];
    pktmbuf_t *src, *dst;
    int ret = -1;

    src = pktmbuf_alloc(pi);
    dst = pktmbuf_alloc(pi);
    if (!src || !dst) {
        tst_error("pktmbuf_alloc() failed\n");
        goto leave;
    }

    old_cap = ring_space;
    /* to test capacity, we enqueue elements and check capacity is reduced
     * by one each time - rebaselining the expected value after each burst
     * as the capacity is only for a burst. We enqueue multiple bursts to
     * fill up half the ring, before emptying it again. We do this twice to
     * ensure that we get to test scenarios where we get ring wrap-around
     */
    for (iter = 0; iter < 2; iter++) {
        for (i = 0; i < ring_space / (2 * BURST_SIZE); i++) {
            cap = dsa_burst_capacity(dev);
            if (cap > old_cap) {
                tst_error("Error, avail ring capacity has gone up, not down\n");
                goto leave;
            }
            old_cap = cap;

            for (j = 0; j < BURST_SIZE; j++) {
                if (dsa_enqueue_copy(dev, pktmbuf_mtod(src, uintptr_t),
                                     pktmbuf_mtod(dst, uintptr_t), length, 0, 0) != 1) {
                    tst_error("Error with dsa_enqueue_copy\n");
                    goto leave;
                }
                if (cap - dsa_burst_capacity(dev) != j + 1) {
                    tst_error("Error, ring capacity did not change as expected\n");
                    goto leave;
                }
            }
            dsa_perform_ops(dev);
        }
        usleep(10);
        for (i = 0; i < ring_space / (2 * BURST_SIZE); i++) {
            if (dsa_completed_ops(dev, BURST_SIZE, NULL, NULL, completions, completions) !=
                BURST_SIZE) {
                tst_error("Error with completions\n");
                goto leave;
            }
        }
        if (dsa_burst_capacity(dev) != ring_space) {
            tst_error("Error, ring capacity has not reset to original value\n");
            goto leave;
        }
        old_cap = ring_space;
    }

    ret = 0;
leave:
    pktmbuf_free(src);
    pktmbuf_free(dst);
    return ret;
}

static int
test_completion_status(uint16_t dev)
{
#define COMP_BURST_SZ 16
    pktmbuf_t *srcs[COMP_BURST_SZ], *dsts[COMP_BURST_SZ];
    pktmbuf_t *completed_src[COMP_BURST_SZ * 2];
    pktmbuf_t *completed_dst[COMP_BURST_SZ * 2];
    const uint32_t fail_copy[] = {0, 7, 15};
    uint32_t i, length = 1024;
    uint8_t not_ok = 0;
    int ret        = -1;

    memset(srcs, 0, sizeof(srcs));
    memset(dsts, 0, sizeof(dsts));

    /* Test single full batch statuses */
    for (i = 0; i < cne_countof(fail_copy); i++) {
        uint32_t status[COMP_BURST_SZ] = {0};
        uint32_t j;

        for (j = 0; j < COMP_BURST_SZ; j++) {
            srcs[j] = pktmbuf_alloc(pi);
            dsts[j] = pktmbuf_alloc(pi);
            if (!srcs[j] || !dsts[j]) {
                tst_error("pktmbuf_alloc() failed\n");
                goto leave;
            }

            if (dsa_enqueue_copy(
                    dev, (j == fail_copy[i] ? (uintptr_t)NULL : pktmbuf_mtod(srcs[j], uintptr_t)),
                    pktmbuf_mtod(dsts[j], uintptr_t), length, (uintptr_t)srcs[j],
                    (uintptr_t)dsts[j]) != 1) {
                tst_error("Error with dsa_enqueue_copy for buffer %u\n", j);
                goto leave;
            }
        }
        dsa_perform_ops(dev);
        usleep(100);

        if (dsa_completed_ops(dev, COMP_BURST_SZ, status, &not_ok, (void *)completed_src,
                              (void *)completed_dst) != COMP_BURST_SZ) {
            tst_error("Error with dsa_completed_ops\n");
            goto leave;
        }
        if (not_ok != 1 || status[fail_copy[i]] == DSA_OP_SUCCESS) {
            tst_error("Error, missing expected failed copy, %u\n", fail_copy[i]);
            for (j = 0; j < COMP_BURST_SZ; j++)
                cne_printf("%u ", status[j]);
            cne_printf("<-- Statuses\n");
            goto leave;
        }
        for (j = 0; j < COMP_BURST_SZ; j++) {
            pktmbuf_free(completed_src[j]);
            pktmbuf_free(completed_dst[j]);
        }
    }

    memset(srcs, 0, sizeof(srcs));
    memset(dsts, 0, sizeof(dsts));

    /* Test gathering status for two batches at once */
    for (i = 0; i < cne_countof(fail_copy); i++) {
        uint32_t status[COMP_BURST_SZ] = {0};
        uint32_t batch, j;
        uint32_t expected_failures = 0;

        for (batch = 0; batch < 2; batch++) {
            for (j = 0; j < COMP_BURST_SZ / 2; j++) {
                srcs[j] = pktmbuf_alloc(pi);
                dsts[j] = pktmbuf_alloc(pi);
                if (!srcs[j] || !dsts[j]) {
                    tst_error("pktmbuf_alloc() failed\n");
                    goto leave;
                }

                if (j == fail_copy[i])
                    expected_failures++;
                if (dsa_enqueue_copy(
                        dev,
                        (j == fail_copy[i] ? (uintptr_t)NULL : pktmbuf_mtod(srcs[j], uintptr_t)),
                        pktmbuf_mtod(dsts[j], uintptr_t), length, (uintptr_t)srcs[j],
                        (uintptr_t)dsts[j]) != 1) {
                    tst_error("Error with dsa_enqueue_copy for buffer %u\n", j);
                    goto leave;
                }
            }
            dsa_perform_ops(dev);
        }
        usleep(100);

        if (dsa_completed_ops(dev, COMP_BURST_SZ, status, &not_ok, (void *)completed_src,
                              (void *)completed_dst) != COMP_BURST_SZ) {
            tst_error("Error with dsa_completed_ops\n");
            goto leave;
        }
        if (not_ok != expected_failures) {
            tst_error("Error, missing expected failed copy, got %u, not %u\n", not_ok,
                      expected_failures);
            for (j = 0; j < COMP_BURST_SZ; j++)
                cne_printf("%u ", status[j]);
            cne_printf("<-- Statuses\n");
            goto leave;
        }
        for (j = 0; j < COMP_BURST_SZ; j++) {
            pktmbuf_free(completed_src[j]);
            pktmbuf_free(completed_dst[j]);
        }
    }

    memset(srcs, 0, sizeof(srcs));
    memset(dsts, 0, sizeof(dsts));

    /* Test gathering status for half batch at a time */
    for (i = 0; i < cne_countof(fail_copy); i++) {
        uint32_t status[COMP_BURST_SZ] = {0};
        uint32_t j;

        for (j = 0; j < COMP_BURST_SZ; j++) {
            srcs[j] = pktmbuf_alloc(pi);
            dsts[j] = pktmbuf_alloc(pi);
            if (!srcs[j] || !dsts[j]) {
                tst_error("pktmbuf_alloc() failed\n");
                goto leave;
            }

            if (dsa_enqueue_copy(
                    dev, (j == fail_copy[i] ? (uintptr_t)NULL : pktmbuf_mtod(srcs[j], uintptr_t)),
                    pktmbuf_mtod(dsts[j], uintptr_t), length, (uintptr_t)srcs[j],
                    (uintptr_t)dsts[j]) != 1) {
                tst_error("Error with dsa_enqueue_copy for buffer %u\n", j);
                goto leave;
            }
        }
        dsa_perform_ops(dev);
        usleep(100);

        if (dsa_completed_ops(dev, COMP_BURST_SZ / 2, status, &not_ok, (void *)completed_src,
                              (void *)completed_dst) != (COMP_BURST_SZ / 2)) {
            tst_error("Error with dsa_completed_ops\n");
            goto leave;
        }
        if (fail_copy[i] < COMP_BURST_SZ / 2 &&
            (not_ok != 1 || status[fail_copy[i]] == DSA_OP_SUCCESS)) {
            tst_error("Missing expected failure in first half-batch\n");
            goto leave;
        }
        if (dsa_completed_ops(dev, COMP_BURST_SZ / 2, status, &not_ok,
                              (void *)&completed_src[COMP_BURST_SZ / 2],
                              (void *)&completed_dst[COMP_BURST_SZ / 2]) != (COMP_BURST_SZ / 2)) {
            tst_error("Error with dsa_completed_ops\n");
            goto leave;
        }
        if (fail_copy[i] >= COMP_BURST_SZ / 2 &&
            (not_ok != 1 || status[fail_copy[i] - (COMP_BURST_SZ / 2)] == DSA_OP_SUCCESS)) {
            tst_error("Missing expected failure in second half-batch\n");
            goto leave;
        }

        for (j = 0; j < COMP_BURST_SZ; j++) {
            pktmbuf_free(completed_src[j]);
            pktmbuf_free(completed_dst[j]);
        }
    }

    memset(srcs, 0, sizeof(srcs));
    memset(dsts, 0, sizeof(dsts));

    /* Test gathering statuses with fence */
    for (i = 1; i < cne_countof(fail_copy); i++) {
        uint32_t status[COMP_BURST_SZ * 2] = {0};
        uint32_t j;
        uint16_t count;

        for (j = 0; j < COMP_BURST_SZ; j++) {
            srcs[j] = pktmbuf_alloc(pi);
            dsts[j] = pktmbuf_alloc(pi);
            if (!srcs[j] || !dsts[j]) {
                tst_error("pktmbuf_alloc() failed\n");
                goto leave;
            }

            /* always fail the first copy */
            if (dsa_enqueue_copy(dev, (j == 0 ? (uintptr_t)NULL : pktmbuf_mtod(srcs[j], uintptr_t)),
                                 pktmbuf_mtod(dsts[j], uintptr_t), length, (uintptr_t)srcs[j],
                                 (uintptr_t)dsts[j]) != 1) {
                tst_error("Error with dsa_enqueue_copy for buffer %u\n", j);
                goto leave;
            }
            /* put in a fence which will stop any further transactions
             * because we had a previous failure.
             */
            if (j == fail_copy[i])
                dsa_fence(dev);
        }
        dsa_perform_ops(dev);
        usleep(100);

        count = dsa_completed_ops(dev, COMP_BURST_SZ * 2, status, &not_ok, (void *)completed_src,
                                  (void *)completed_dst);
        if (count != COMP_BURST_SZ) {
            tst_error("Error with dsa_completed_ops, got %u not %u\n", count, COMP_BURST_SZ);
            for (j = 0; j < count; j++)
                cne_printf("%u ", status[j]);
            cne_printf("<-- Statuses\n");
            goto leave;
        }
        if (not_ok != COMP_BURST_SZ - fail_copy[i]) {
            tst_error("Unexpected failed copy count, got %u, expected %u\n", not_ok,
                      COMP_BURST_SZ - fail_copy[i]);
            for (j = 0; j < COMP_BURST_SZ; j++)
                cne_printf("%u ", status[j]);
            cne_printf("<-- Statuses\n");
            goto leave;
        }
        if (status[0] == DSA_OP_SUCCESS || status[0] == DSA_OP_SKIPPED) {
            tst_error("Error, op 0 unexpectedly did not fail.\n");
            goto leave;
        }
        for (j = 1; j <= fail_copy[i]; j++) {
            if (status[j] != DSA_OP_SUCCESS) {
                tst_error("Error, op %u unexpectedly failed\n", j);
                goto leave;
            }
        }
        for (j = fail_copy[i] + 1; j < COMP_BURST_SZ; j++) {
            if (status[j] != DSA_OP_SKIPPED) {
                tst_error("Error, all descriptors after fence should be invalid\n");
                goto leave;
            }
        }
        for (j = 0; j < COMP_BURST_SZ; j++) {
            pktmbuf_free(completed_src[j]);
            pktmbuf_free(completed_dst[j]);
        }
    }

    memset(srcs, 0, sizeof(srcs));
    memset(dsts, 0, sizeof(dsts));

    ret = 0;
leave:
    for (i = 0; i < COMP_BURST_SZ; i++) {
        pktmbuf_free(srcs[i]);
        pktmbuf_free(dsts[i]);
    }
    return ret;
}

static int
test_get_stats(uint16_t dev)
{
    struct dsa_stats stats = {0};
    int err;

    /* invalid dev, stats */
    err = dsa_get_stats(-1, NULL);
    if (!err) {
        tst_error("Expect dsa_get_stats(-1, NULL) to fail but it succeeded\n");
        return -1;
    }

    err = errno;
    if (err != ENODEV && err != EINVAL) {
        tst_error("Expect dsa_get_stats(-1, NULL) to set errno to ENODEV or EINVAL, not %d\n", err);
        return -1;
    }

    /* invalid dev */
    err = dsa_get_stats(-1, &stats);
    if (!err) {
        tst_error("Expect dsa_get_stats(-1, &stats) to fail but it succeeded\n");
        return -1;
    }

    err = errno;
    if (err != ENODEV) {
        tst_error("Expect dsa_get_stats(-1, NULL) to set errno to ENODEV, not %d\n", err);
        return -1;
    }

    /* invalid stats */
    err = dsa_get_stats(dev, NULL);
    if (!err) {
        tst_error("Expect dsa_get_stats(dev, NULL) to fail but it succeeded\n");
        return -1;
    }

    err = errno;
    if (err != EINVAL) {
        tst_error("Expect dsa_get_stats(dev, NULL) to set errno to EINVAL, not %d\n", err);
        return -1;
    }

    /* valid dev, stats */
    err = dsa_get_stats(dev, &stats);
    if (err) {
        tst_error("dsa_get_stats() failed: %s\n", strerror(errno));
        return -1;
    }

    tst_info("enqueue_failed: %lu\n", stats.enqueue_failed);
    tst_info("enqueued:       %lu\n", stats.enqueued);
    tst_info("started:        %lu\n", stats.started);
    tst_info("completed:      %lu\n", stats.completed);

    return 0;
}

static int
test_open_multiple(void)
{
    int16_t dev, i;
    int err = 0;

    /* try to open as many devices as possible */
    for (i = 0; i < 0x7FFF; i++) {
        dev = dsa_open(NULL);
        if (dev < 0)
            break;
        if (dev != i) {
            tst_error("Expected consecutive indices but got %d: %d\n", i, dev);
            (void)dsa_close(dev);
            err = -1;
            break;
        }
    }

    /* Loop through the devices, starting with the last one that was opened */
    for (--i; i >= 0; i--) {
        if (dsa_close(i)) {
            tst_error("Failed to close device %d: %s\n", i, strerror(errno));
            err = -1;
        }
    }

    return err;
}

int
dsa_main(int argc __cne_unused, char **argv __cne_unused)
{
    tst_info_t *tst;
    int16_t dev;
    int i;

    /* allocate the pktmbuf pool used by all tests */
    if (alloc_pool()) {
        /* dummy test, only used if pool alloc fails */
        tst = tst_start("DSA: alloc pool");
        tst_error("alloc_pool() failed\n");
        tst_end(tst, TST_FAILED);
        return -1;
    }

    /* Open Device */
    tst = tst_start("DSA: open");
    dev = dsa_open("wq0.0");
    if (dev < 0) {
        tst_error("dsa_open() failed: %s\n", strerror(errno));
        goto err;
    }
    tst_end(tst, TST_PASSED);

    /* Single Copy */
    tst = tst_start("DSA: single copy");
    for (i = 0; i < 100; i++)
        if (test_single_copy(dev))
            goto err;
    tst_end(tst, TST_PASSED);

    /* Single Copy, 4 times, retrieve all 4 completions */
    tst = tst_start("DSA: single copy 4 times");
    for (i = 0; i < 100; i++)
        if (test_single_copy_4(dev))
            goto err;
    tst_end(tst, TST_PASSED);

    /* Multiple copies */
    tst = tst_start("DSA: multiple copies");
    for (i = 0; i < 100; i++)
        if (test_multi_copies(dev))
            goto err;
    tst_end(tst, TST_PASSED);

    /* fill operation */
    tst = tst_start("DSA: fill operation");
    for (i = 0; i < 100; i++)
        if (test_enqueue_fill(dev))
            goto err;
    tst_end(tst, TST_PASSED);

    /* burst capacity */
    tst = tst_start("DSA: burst capacity");
    if (test_burst_capacity(dev))
        goto err;
    tst_end(tst, TST_PASSED);

    /* completion status */
    tst = tst_start("DSA: completion status");
    if (test_completion_status(dev))
        goto err;
    tst_end(tst, TST_PASSED);

    /* statistics */
    tst = tst_start("DSA: get stats");
    if (test_get_stats(dev))
        goto err;
    tst_end(tst, TST_PASSED);

    /* Close Device */
    tst = tst_start("DSA: close");
    if (dsa_close(dev)) {
        tst_error("dsa_close() failed: %s\n", strerror(errno));
        goto err;
    }
    tst_end(tst, TST_PASSED);

    tst = tst_start("DSA: open multiple");
    if (test_open_multiple())
        goto err;
    tst_end(tst, TST_PASSED);
    free_pool();
    return 0;

err:
    tst_end(tst, TST_FAILED);
    (void)dsa_close(dev);
    free_pool();
    return -1;
}
