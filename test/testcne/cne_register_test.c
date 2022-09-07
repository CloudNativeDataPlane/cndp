/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>           // for NULL, EOF
#include <stdint.h>          // for uint16_t, uint32_t
#include <cne.h>             // for cne_register, cne_unregister
#include <tst_info.h>        // for tst_error, tst_end, tst_start, TST_FAILED
#include <getopt.h>          // for getopt_long, option
#include <pthread.h>
#include <cne_common.h>        // for CNE_SET_USED

#include "cne_register_test.h"

static void
__on_exit(int sig __cne_unused, void *arg __cne_unused, int exit_type __cne_unused)
{
    return;
}

static void *
cne_register_test(void *arg)
{
    int tuid = 0, cuid, tcnt, ret = 0;
    int v = 1234, vv = 0;
    void *setv  = &v;
    void *tempv = &vv;
    void **getv = &tempv;

    ret = cne_check_registration();
    if (ret > 0) {
        tst_error("Check registration returned success before registering thread with CNE");
        goto err;
    } else
        tst_ok("PASS --- TEST: Thread is not yet registered with CNE");

    tuid = cne_register("TestCNERegister");
    if (tuid)
        tst_ok("PASS --- TEST: New thread registered, uid %d", tuid);

    ret = cne_check_registration();
    if (!ret) {
        tst_error("Check registration failed after registering thread with CNE");
        goto err;
    } else
        tst_ok("PASS --- TEST: Thread is registered with CNE");

    cuid = cne_entry_uid();
    if (tuid != cuid) {
        tst_error("Invalid uid");
        goto err;
    } else
        tst_ok("PASS --- TEST: Current uid retrieved, %d", tuid);

    ret = cne_set_private(tuid, setv);
    if (ret < 0) {
        tst_error("Unable to set a private value for uid = %d", tuid);
        goto err;
    } else
        tst_ok("PASS --- TEST: Set private value, %d", *(int *)setv);

    ret = cne_get_private(tuid, getv);
    if (ret < 0) {
        tst_error("Unable to get the private value for uid = %d", tuid);
        goto err;
    } else
        tst_ok("PASS --- TEST: Retrieved private value, %d", *(int *)*getv);

    if (*(int *)setv != *(int *)*getv) {
        tst_error("Incorrect private value for uid = %d", tuid);
        goto err;
    } else
        tst_ok("PASS --- TEST: The set private value was retrieved");

    tcnt = cne_active_threads();
    if (tcnt < 0) {
        tst_error("Error retrieving total active threads");
        goto err;
    } else
        tst_ok("PASS --- TEST: Total number of active threads, %d", tcnt);

    if (cne_unregister(tuid) < 0) {
        tst_error("cne_unregister(%d) failed", tuid);
        *(int *)arg = -1;
        return NULL;
    } else
        tst_ok("PASS --- TEST: uid %d unregistered", tuid);

    ret = cne_on_exit(__on_exit, NULL, NULL, 0);
    if (ret < 0) {
        tst_error("Error on exit\n");
        goto err;
    } else
        tst_ok("PASS --- TEST: Exit CNE Registration test");

    *(int *)arg = 0;
    return NULL;

err:
    if (tuid)
        cne_unregister(tuid);

    *(int *)arg = -1;
    return NULL;
}

int
cne_register_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt;
    int option_index, ret, eno;
    pthread_t tid;
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

    ret = 0;
    if ((eno = pthread_create(&tid, NULL, cne_register_test, &ret)) != 0) {
        tst_error("pthread create failed: %s", strerror(eno));
        goto err;
    }
    if ((eno = pthread_join(tid, NULL)) != 0) {
        tst_error("pthread join failed: %s", strerror(eno));
        goto err;
    }
    if (ret < 0)
        goto err;

    tst_end(tst, TST_PASSED);
    return 0;
err:
    tst_end(tst, TST_FAILED);
    return -1;
}
