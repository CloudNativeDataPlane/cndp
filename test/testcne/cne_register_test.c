/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, EOF
#include <stdint.h>            // for uint16_t, uint32_t
#include <cne.h>               // for cne_register, cne_unregister
#include <tst_info.h>          // for tst_error, tst_end, tst_start, TST_FAILED
#include <getopt.h>            // for getopt_long, option
#include <cne_common.h>        // for CNE_SET_USED

#include "cne_register_test.h"

static void
__on_exit(int sig __cne_unused, void *arg __cne_unused, int exit_type __cne_unused)
{
    return;
}

static int
cne_register_test(void)
{
    int tuid, cuid, tcnt, ret = 0;
    int v = 1234, vv = 0;
    void *setv  = &v;
    void *tempv = &vv;
    void **getv = &tempv;

    tuid = cne_register("TestCNERegister");
    if (tuid)
        tst_ok("PASS --- TEST: New thread registered, uid %d\n", tuid);

    cuid = cne_entry_uid();
    if (tuid != cuid) {
        tst_error("Invalid uid\n");
        goto err;
    } else
        tst_ok("PASS --- TEST: Current uid retrieved, %d\n", tuid);

    ret = cne_set_private(tuid, setv);
    if (ret < 0) {
        tst_error("Unable to set a private value for uid = %d\n", tuid);
        goto err;
    } else
        tst_ok("PASS --- TEST: Set private value, %d\n", *(int *)setv);

    ret = cne_get_private(tuid, getv);
    if (ret < 0) {
        tst_error("Unable to get the private value for uid = %d\n", tuid);
        goto err;
    } else
        tst_ok("PASS --- TEST: Retrieved private value, %d\n", *(int *)*getv);

    if (*(int *)setv != *(int *)*getv) {
        tst_error("Incorrect private value for uid = %d\n", tuid);
        goto err;
    } else
        tst_ok("PASS --- TEST: The set private value was retrieved\n");

    tcnt = cne_active_threads();
    if (tcnt < 0) {
        tst_error("Error retrieving total active threads\n");
        goto err;
    } else
        tst_ok("PASS --- TEST: Total number of active threads, %d\n", tcnt);

    if (tuid) {
        if (cne_unregister(tuid) < 0) {
            tst_error("cne_unregister(%d) failed\n", tuid);
            return -1;
        } else
            tst_ok("PASS --- TEST: uid %d unregistered\n", tuid);
    }

    ret = cne_on_exit(__on_exit, NULL, NULL, 0);
    if (ret < 0) {
        tst_error("Error on exit\n");
        goto err;
    } else
        tst_ok("PASS --- TEST: Exit CNE Registration test\n");

    return 0;

err:
    if (tuid)
        cne_unregister(tuid);
    return -1;
}

int
cne_register_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;
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

    tst = tst_start("CNE Registration");

    if (cne_register_test() < 0)
        goto err;

    tst_end(tst, TST_PASSED);
    return 0;
err:
    tst_end(tst, TST_FAILED);
    return -1;
}
