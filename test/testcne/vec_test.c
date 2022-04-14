/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2020 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, EOF
#include <stdlib.h>            // for rand
#include <stdint.h>            // for uint16_t, uint64_t, uint32_t
#include <getopt.h>            // for getopt_long, option
#include <uid.h>               // for uid_dump, uid_alloc, uid_free, uid_reg...
#include <tst_info.h>          // for tst_error, tst_cleanup, tst_end, tst_s...
#include <cne_common.h>        // for cne_countof, CNE_SET_USED
#include <cne_vec.h>

#include "vec_test.h"

#define ERR_OK  1
#define ERR_NOK 0

// clang-format off
static struct test_data {
    const char *name;
    uint16_t cnt;
    uint32_t err_ok;
} tdata[] = {
    {"Vec-0", 8, ERR_NOK},
    {"Vec-1", 16, ERR_NOK},
    {"Vec-2", 126, ERR_NOK},
    {"Vec-3", 128, ERR_NOK},
    {"Vec-4", 63, ERR_NOK},
    {"Vec-5", 256, ERR_NOK},
    {"Vec-6", 257, ERR_NOK}
};
// clang-format on

static int
test1(struct test_data *t)
{
    int d, *u = NULL;

    u = vec_alloc(u, t->cnt);
    if (!u)
        return -1;

    memset(u, 0, sizeof(u) * t->cnt);

    cne_printf("%s:\n", t->name);

    for (int j = 0; j < t->cnt; j++)
        vec_add_ptr(u, j + t->cnt);

    vec_dump(NULL, u);

    for (uint64_t j = (uint64_t)t->cnt; j > 0; j--) {
        d = vec_pop(u);
        if ((uint64_t)d != (j + (t->cnt - 1)))
            cne_printf("Oooops %d - %ld\n", d, (j + (t->cnt - 1)));
    }

    vec_dump(NULL, u);

    vec_free(u);

    return 0;
}

static int
test2(struct test_data *t)
{
    int **u = NULL;

    u = vec_alloc_ptr(u, t->cnt);
    if (!u)
        return -1;

    memset(u, 0, sizeof(void *) * t->cnt);

    cne_printf("%s:\n", t->name);

    for (uint64_t j = 0; j < (uint64_t)t->cnt + 1; j++) {
        void *v = (void *)(uintptr_t)(j + t->cnt);
        vec_add_ptr(u, v);
    }

    vec_dump(NULL, u);

    for (uint64_t j = (uint64_t)t->cnt; j > 0; j--) {
        void *v = vec_pop(u);
        if (v != (void *)(uintptr_t)(j + (t->cnt - 1)))
            cne_printf("Oooops %ld - %ld\n", (uint64_t)v, (j + (t->cnt - 1)));
    }

    vec_dump(NULL, u);

    vec_free(u);

    return 0;
}

int
vec_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

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

    tst = tst_start("Vec");

    for (int i = 0; i < cne_countof(tdata); i++)
        test1(&tdata[i]);
    for (int i = 0; i < cne_countof(tdata); i++)
        test2(&tdata[i]);

    tst_end(tst, TST_PASSED);

    return 0;
}
