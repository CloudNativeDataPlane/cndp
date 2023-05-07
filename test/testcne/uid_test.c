/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, EOF
#include <stdlib.h>            // for rand
#include <stdint.h>            // for uint16_t, uint32_t
#include <getopt.h>            // for getopt_long, option
#include <uid.h>               // for uid_dump, uid_unregister, uid_alloc
#include <tst_info.h>          // for tst_error, tst_end, tst_start, TST_FAILED
#include <cne_common.h>        // for cne_countof, CNE_SET_USED

#include "uid_test.h"
#include "cne_log.h"        // for CNE_ERR, CNE_LOG_ERR

#define ERR_OK  1
#define ERR_NOK 0

// clang-format off
static struct test_data {
    const char *name;
    uint16_t cnt;
    uint16_t alloc_cnt;
    uint32_t err_ok;
    u_id_t e;
} tdata[] = {
    {"UID-0", 8, 16, ERR_NOK},
    {"UID-1", 16, 32, ERR_NOK},
    {"UID-2", 126, 256, ERR_NOK},
    {"UID-3", 128, 256, ERR_NOK},
    {"UID-4", 63, 128, ERR_NOK},
    {"UID-5", 256, 512, ERR_NOK},
    {"UID-6", 257, 1024, ERR_NOK},
    {"UID-7", 65535, 65535, ERR_NOK}
};
// clang-format on

int
uid_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    struct test_data *t;
    char **argvopt;
    int option_index;
    uint16_t i, j;
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

    tst = tst_start("ID Allocator");

    for (j = 0; j < cne_countof(tdata); j++) {
        t    = &tdata[j];
        t->e = uid_register(t->name, t->cnt);
        if (!t->e) {
            tst_error("Failed to add a %s\n", t->name);
            goto err;
        }
    }
    uid_dump(NULL);

    for (j = 0; j < cne_countof(tdata); j++) {
        u_id_t e;

        t = &tdata[j];
        if (!t->name || t->name[0] == '\0') {
            tst_error("invalid name\n");
            goto err;
        }
        e = uid_find_by_name(t->name);
        if (!e) {
            tst_error("Failed to find name: %s\n", t->name);
            goto err;
        }
    }
    uid_dump(NULL);

    for (j = 0; j < cne_countof(tdata); j++) {
        t = &tdata[j];
        for (i = 0; i < t->alloc_cnt; i++) {
            int uid = uid_alloc(t->e);

            if (uid < 0) {
                if (i == t->cnt)        // expected failure
                    break;
                tst_error("Failed to allocate a UID for %s:%d max %d\n", t->name, i + 1, t->cnt);
                goto err;
            }

            if (uid_allocated(t->e) != i + 1) {
                tst_error("Failed to get number currently allocated of (%s)\n", t->name);
                goto err;
            }
        }
    }

    uid_dump(NULL);

    for (j = 0; j < cne_countof(tdata); j++) {
        t = &tdata[j];
        if (uid_max_ids(t->e) != t->cnt) {
            tst_error("Failed to get max ids of (%s)\n", t->name);
            goto err;
        }
    }
    uid_dump(NULL);

    for (j = 0; j < cne_countof(tdata); j++) {
        for (i = 0; i < t->alloc_cnt; i++) {
            int uid;

            uid = rand() % t->cnt;

            uid_free(t->e, uid);
        }
    }

    for (j = 0; j < cne_countof(tdata); j++) {
        t = &tdata[j];
        if (uid_unregister(t->e) < 0) {
            tst_error("Failed to delete a (%s)\n", t->name);
            goto err;
        }
    }
    uid_dump(NULL);

    tst_end(tst, TST_PASSED);

    return 0;
err:
    /* Only free if unsuccessful, as success case will have already done it. */
    for (j = 0; j < cne_countof(tdata); j++) {
        t = &tdata[j];
        if (t->e)
            if (uid_unregister(t->e) < 0)
                CNE_ERR("Failed to unregister uid %s\n", t->name);
    }
    tst_end(tst, TST_FAILED);
    return -1;
}
