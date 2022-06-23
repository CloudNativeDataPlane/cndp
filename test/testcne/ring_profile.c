/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <inttypes.h>        // for PRId64, PRId32
#include <stdio.h>           // for NULL, size_t, snprintf, EOF
#include <stdint.h>          // for uint64_t, uint32_t
#include <time.h>            // for clock_gettime, timespec, CLOCK_MONOTON...
#include <getopt.h>          // for no_argument, getopt_long, required_arg...
#include <cne_ring.h>        // for CNE_RING_NAMESIZE
#include <tst_info.h>        // for tst_error, tst_ok, tst_end, tst_start
#include <stdlib.h>          // for atoi
#include <limits.h>          // for INT_MAX

#include "ring_profile.h"
#include "cne_common.h"          // for cne_align32pow2, cne_countof
#include "cne_ring_api.h"        // for cne_ring_dequeue_elem, cne_ring_enqueu...
#include "cne_stdio.h"           // for cne_printf
#include "vt100_out.h"           // for vt_color, VT_NO_CHANGE, VT_OFF, VT_BLUE

static int verbose         = 0;
static int exact           = 0;
static int single_producer = 0;
static int single_consumer = 0;

int
ring_profile(int argc, char **argv)
{
    struct cne_ring *r;
    tst_info_t *tst;
    union {
        uint32_t e4;
        uint64_t e8;
        struct {
            uint64_t m[2];
        } e16;
        struct {
            uint32_t m[5];
        } e20;
        struct {
            uint64_t m[3];
        } e24;
        struct {
            uint64_t m[4];
        } e32;
    } val;
    double duration;
    size_t i;
    int opt;
    int size_arg  = 0;
    int count_arg = 0;
    char **argvopt;
    int option_index;
    struct timespec ts_start, ts_end;
    char tst_name[128];
    // clang-format off
    static struct option lgopts[] = {
        {"size", required_argument, NULL, 's'},               /**
                                                               * ring size in MB to be used
                                                               * esize * count shouldn't
                                                               * exceed that size
                                                               */
        {"count", required_argument, NULL, 'c'},              /**
                                                               * number of enqueue/dequeue
                                                               * rounds on ring.
                                                               * ring size will be esize *
                                                               * count.
                                                               */
        {"exact", no_argument, &exact, RING_F_EXACT_SZ},      /**
                                                               * use RING_F_EXACT_SZ when
                                                               * creating ring
                                                               */
        {"sp", no_argument, &single_producer, RING_F_SP_ENQ}, /**
                                                               * use signle producer ring
                                                               */
        {"sc", no_argument, &single_consumer, RING_F_SC_DEQ}, /**
                                                               * use single consumer ring
                                                               */
        {"verbose", no_argument, &verbose, 1},
        {NULL, 0, 0, 0}
    };
    // clang-format on
    size_t esize_i            = 0;
    unsigned int elem_sizes[] = {0, /* default */
                                 4, 8, 16, 32};

    /* reset flags to default before commandline parsing */
    verbose         = 0;
    exact           = 0;
    single_consumer = 0;
    single_producer = 0;

    argvopt = argv;

    optind = 0;
    while ((opt = getopt_long(argc, argvopt, "Vs:c:", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        case 's': {
            int size_opt = atoi(optarg);
            size_arg     = size_opt > 0 ? size_opt : size_arg;
            if (size_arg > INT_MAX) {
                /* size_arg won't be >INT_MAX, but the check silences klocwork */
                tst_error("size is too big\n");
                return -1;
            }
            break;
        }
        case 'c': {
            int count_opt = atoi(optarg);
            count_arg     = count_opt > 0 ? count_opt : count_arg;
            if (count_arg > INT_MAX) {
                /* count_arg won't be >INT_MAX, but the check silences klocwork */
                tst_error("count is too big\n");
                return -1;
            }
            break;
        }
        default:
            break;
        }
    }
    (void)verbose;

    if (size_arg != 0 && count_arg != 0)
        tst_error("size and count arg are mutually exclusive using count:%d\n", count_arg);
    else if (count_arg == 0)
        count_arg = 16 * 1024 * 1024;

    /* let's allocated 16MB of memory for ring.
     *
     * Depending on esize count will be changed so ring size is always the same
     */
    const size_t ring_size = size_arg * 1024 * 1024;
    tst_ok("input args size_arg=%d ring_size=%zu count_arg=%d flags=%x\n", size_arg, ring_size,
           count_arg, exact | single_consumer | single_producer);
    const size_t default_esize = sizeof(void *);

    for (esize_i = 0; esize_i < cne_countof(elem_sizes); esize_i++) {
        unsigned int esize        = elem_sizes[esize_i];
        unsigned int actual_esize = (esize ? esize : default_esize);
        unsigned int count        = 0;

        if (ring_size)
            count = ring_size / actual_esize;
        else
            count = count_arg;
        count                 = cne_align32pow2(count);
        unsigned int enqueued = count;
        int err_num           = 0;
        snprintf(tst_name, cne_countof(tst_name), "Ring esize=%d(%d) count=%u", esize, actual_esize,
                 count);
        tst_ok("%s\n", tst_name);
        tst = tst_start(tst_name);

        char ring_name[CNE_RING_NAMESIZE];
        snprintf(ring_name, cne_countof(ring_name), "R e=%d count=%d", esize, count);
        r = cne_ring_create(ring_name, esize, count, exact | single_consumer | single_producer);
        if (!r) {
            tst_error("Ring create failed\n");
            goto err;
        }
        tst_ok("Ring created e=%d count=%d\n", esize, count);

        if (verbose) {
            vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
            cne_ring_dump(NULL, r);
            cne_printf("\n");
            vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
        }

        clock_gettime(CLOCK_MONOTONIC_RAW, &ts_start);
        for (i = 0; i < count - 1; i++) {
            switch (actual_esize) {
            case 4: {
                val.e4  = i + 1;
                err_num = cne_ring_enqueue_elem(r, (void *)(&val.e4), actual_esize);
            } break;
            case 8: {
                val.e8  = i + 1;
                err_num = cne_ring_enqueue_elem(r, (void *)(&val.e8), actual_esize);
            } break;
            case 16: {
                val.e16.m[1] = i + 1;
                err_num      = cne_ring_enqueue_elem(r, (void *)(&val.e16), actual_esize);
            } break;
            case 20: {
                val.e20.m[1] = i + 1;
                err_num      = cne_ring_enqueue_elem(r, (void *)(&val.e20), actual_esize);
            } break;
            case 24: {
                val.e24.m[1] = i + 1;
                err_num      = cne_ring_enqueue_elem(r, (void *)(&val.e24), actual_esize);
            } break;
            case 32: {
                val.e32.m[1] = i + 1;
                err_num      = cne_ring_enqueue_elem(r, (void *)(&val.e32), actual_esize);
            } break;
            default:
                tst_error("Wrong value of actual_esize=%d\n", actual_esize);
                goto err;
            }
            if (0 > err_num) {
                tst_ok("enqueue failed i=%zu esize=%d\n", i, esize);
                goto err;
            }
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts_end);
        enqueued = i;
        duration = (ts_end.tv_sec - ts_start.tv_sec) * 1e9;
        duration = (duration + (ts_end.tv_nsec - ts_start.tv_nsec)) * 1e-9;
        tst_ok("enqueue esize=%d enqueued=%d size=%zu duration:%f\n", esize, enqueued,
               (size_t)enqueued * actual_esize, duration);

        if (verbose) {
            vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
            cne_ring_dump(NULL, r);
            cne_printf("\n");
            vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
        }

        clock_gettime(CLOCK_MONOTONIC_RAW, &ts_start);
        for (i = 0; i < enqueued; i++) {
            switch (actual_esize) {
            case 4: {
                err_num = cne_ring_dequeue_elem(r, (void *)(&val.e4), actual_esize);
                if (val.e4 != (uint32_t)(i + 1)) {
                    tst_error("Ring Dequeue failed e=%d val=%" PRId32 " err=%d\n", actual_esize,
                              val.e4, err_num);
                    goto err;
                }
            } break;
            case 8: {
                val.e8  = 0;
                err_num = cne_ring_dequeue_elem(r, (void *)(&val.e8), actual_esize);
                if (val.e8 != (uint64_t)(i + 1)) {
                    tst_error("Ring Dequeue failed e=%d val=%" PRId64 " i=%d err=%d\n",
                              actual_esize, val.e8, i, err_num);
                    goto err;
                }
            } break;
            case 16: {
                err_num = cne_ring_dequeue_elem(r, (void *)(&val.e16), actual_esize);
                if (val.e16.m[1] != (uint64_t)(i + 1)) {
                    tst_error("Ring Dequeue failed e=%d val={%" PRId64 ", %" PRId64 "} err=%d\n",
                              actual_esize, val.e16.m[1], err_num);
                    goto err;
                }
            } break;
            case 20: {
                err_num = cne_ring_dequeue_elem(r, (void *)(&val.e20), actual_esize);
                if (val.e20.m[1] != (uint64_t)(i + 1)) {
                    tst_error("Ring Dequeue failed e=%d val={%" PRIu32 ", %" PRIu32 "} err=%d\n",
                              actual_esize, val.e20.m[1], err_num);
                    goto err;
                }
            } break;
            case 24: {
                err_num = cne_ring_dequeue_elem(r, (void *)(&val.e24), actual_esize);
                if (val.e24.m[1] != (uint64_t)(i + 1)) {
                    tst_error("Ring Dequeue failed e=%d val={%" PRId64 ", %" PRId64 "} err=%d\n",
                              actual_esize, val.e24.m[1], err_num);
                    goto err;
                }
            } break;
            case 32: {
                err_num = cne_ring_dequeue_elem(r, (void *)(&val.e32), actual_esize);
                if (val.e32.m[1] != (uint64_t)(i + 1)) {
                    tst_error("Ring Dequeue failed e=%d val={%" PRId64 ", %" PRId64 "} err=%d\n",
                              actual_esize, val.e32.m[1], err_num);
                    goto err;
                }
            } break;
            default:
                tst_error("Wrong value of actual_esize=%d\n", actual_esize);
            }
            if (0 > err_num) {
                tst_ok("dequeue failed i=%d esize=%d err=%d\n", i, esize, err_num);
                break;
            }
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts_end);
        duration = (ts_end.tv_sec - ts_start.tv_sec) * 1e9;
        duration = (duration + (ts_end.tv_nsec - ts_start.tv_nsec)) * 1e-9;
        tst_ok("dequeue esize=%d enqueued=%d size=%zu duration:%f\n", esize, enqueued,
               (size_t)enqueued * actual_esize, duration);

        if (verbose) {
            vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
            cne_ring_dump(NULL, r);
            cne_printf("\n");
            vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
        }
        cne_ring_free(r);
        tst_end(tst, TST_PASSED);
    }
    return 0;

err:
    cne_ring_free(r);
    tst_end(tst, TST_FAILED);
    return -1;
}
