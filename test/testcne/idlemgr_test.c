/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>         // for NULL, EOF
#include <stdlib.h>        // for rand
#include <stdint.h>        // for uint16_t, uint32_t
#include <getopt.h>        // for getopt_long, option
#include <pthread.h>
#include <uid.h>               // for uid_dump, uid_unregister, uid_alloc
#include <tst_info.h>          // for tst_error, tst_end, tst_start, TST_FAILED
#include <cne_common.h>        // for cne_countof, CNE_SET_USED
#include <idlemgr.h>

#include "idlemgr_test.h"
#include "cne_log.h"        // for CNE_ERR, CNE_LOG_ERR

#define TST_FUNC(lb, name, f)              \
    do {                                   \
        tst_info_t *tst = tst_start(name); \
        int t;                             \
        if (tst == NULL)                   \
            return -1;                     \
        t = f;                             \
        tst_end(tst, t);                   \
        if (t == TST_FAILED)               \
            goto lb;                       \
    } while ((0))

static int
test1(void)
{
    idlemgr_t *imgr = NULL;

    imgr = idlemgr_create("test1", 0, 0, 0);
    if (imgr != NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() succeeded and should have failed\n");
    idlemgr_destroy(imgr);

    imgr = idlemgr_create("test1", 10, 0, 0);
    if (imgr == NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() failed and should have succeeded\n");
    idlemgr_destroy(imgr);

    imgr = idlemgr_create("test1", IDLE_MGR_MAX_FDS, 0, 0);
    if (imgr == NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() failed and should have succeeded with max FDs\n");
    idlemgr_destroy(imgr);

    imgr = idlemgr_create("test1", IDLE_MGR_MAX_FDS + 1, 0, 0);
    if (imgr != NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() succeeded with max FDs + 1\n");
    idlemgr_destroy(imgr);

    imgr = idlemgr_create("test1", 1, ((10 * 60) * 1000), 0);
    if (imgr != NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() succeeded with invalid idle_timeout\n");
    idlemgr_destroy(imgr);

    imgr = idlemgr_create("test1", 1, 10, ((10 * 60) * 1000));
    if (imgr != NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() succeeded with invalid intr_timeout\n");
    idlemgr_destroy(imgr);

    return TST_PASSED;
leave:
    idlemgr_destroy(imgr);
    return TST_FAILED;
}

static int
test2(void)
{
    idlemgr_stats_t stats;
    idlemgr_t *imgr = NULL;
    uint32_t idle = 0xFFFFFF, intr = 0xFFFFFF;

    imgr = idlemgr_create("test2", 2, 0, 0);
    if (imgr == NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() failed and should have succeeded\n");

    if (idlemgr_set_timeouts(imgr, 10, 2000) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_set_timeouts failed\n");

    if (idlemgr_get_timeouts(imgr, &idle, &intr) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_get_timeouts failed\n");

    if (idle != 10 || intr != 2000)
        CNE_ERR_GOTO(leave, "idlemgr_get_timeouts failed idle %u, intr %u\n", idle, intr);

    if (idlemgr_add(imgr, 100, 0) == 0)
        CNE_ERR_GOTO(leave, "idlemgr_add succeeded with bad file descriptor\n");

    if (idlemgr_add(imgr, 0, 0) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_add failed with duplicate file descriptor\n");

    if (idlemgr_add(imgr, 0, 0) == 0)
        CNE_ERR_GOTO(leave, "idlemgr_add failed with valid file descriptor\n");

    if (idlemgr_add(imgr, 1, 0) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_add failed second add\n");

    if (idlemgr_add(imgr, 3, 0) == 0)
        CNE_ERR_GOTO(leave, "idlemgr_add succeeded with too many fds\n");

    if (idlemgr_del(imgr, 0) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_del failed with valid file descriptor\n");

    if (idlemgr_get_events(imgr) == NULL)
        CNE_ERR_GOTO(leave, "idlemgr_get_events failed\n");

    if (idlemgr_stats(imgr, NULL) == 0)
        CNE_ERR_GOTO(leave, "idlemgr_stats succeeded with NULL pointer\n");

    idlemgr_destroy(imgr);
    imgr = NULL;

    cpu_set_t lcore_bitmap;
    CPU_ZERO(&lcore_bitmap);
    CPU_SET(10, &lcore_bitmap);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &lcore_bitmap);
    CNE_INFO("LCore ID %d\n", cne_lcore_id());

    imgr = idlemgr_create("test2", 2, 10, 1000);
    if (imgr == NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() failed and should have succeeded\n");

    if (idlemgr_add(imgr, 0, 0) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_add failed with valid file descriptor\n");

    if (idlemgr_process(imgr, 0) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_process failed\n");

    if (idlemgr_process(imgr, 1) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_process failed\n");

    if (idlemgr_process(imgr, 0) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_process failed\n");

    for (int i = 0; i < 10; i++) {
        usleep(1000);

        if (idlemgr_process(imgr, 0) < 0)
            CNE_ERR_GOTO(leave, "idlemgr_process failed\n");
    }
    CPU_ZERO(&lcore_bitmap);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &lcore_bitmap);

    idlemgr_dump(imgr);

    if (idlemgr_stats(imgr, &stats) < 0)
        CNE_ERR_GOTO(leave, "idlemgr_stats failed\n");
    if (stats.called_epoll == 0 || stats.intr_timedout == 0)
        CNE_ERR_GOTO(leave, "idlemgr did not call epoll_wait or timedout\n");

    idlemgr_destroy(imgr);
    imgr = NULL;

    if (idlemgr_add(imgr, 0, 0) == 0)
        CNE_ERR_GOTO(leave, "idlemgr_add succeeded with NULL pointer\n");

    return TST_PASSED;
leave:
    idlemgr_destroy(imgr);
    return TST_FAILED;
}

static int
test3(void)
{
    idlemgr_t *imgr = NULL, *imgr2 = NULL;

    imgr = idlemgr_create("test3", 10, 0, 0);
    if (imgr == NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() succeeded for test1 name\n");

    imgr2 = idlemgr_create("test1", 10, 0, 0);
    if (imgr2 != NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() should fail with duplicate name\n");

    idlemgr_destroy(imgr2);
    idlemgr_destroy(imgr);
    imgr = imgr2 = NULL;

    imgr = idlemgr_create("test3", 10, 10, 1000);
    if (imgr == NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() succeeded for test1 name\n");

    imgr2 = idlemgr_create("test3", 10, 20, 2000);
    if (imgr == NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() should succeed with name test2\n");
    idlemgr_destroy(imgr2);

    imgr2 = idlemgr_create("test3", 10, 30, 3000);
    if (imgr == NULL)
        CNE_ERR_GOTO(leave, "idlemgr_create() should succeed with name test2\n");
    idlemgr_list_dump();

    idlemgr_destroy(imgr2);
    idlemgr_destroy(imgr);

    return TST_PASSED;
leave:
    idlemgr_destroy(imgr2);
    idlemgr_destroy(imgr);
    return TST_FAILED;
}

int
idlemgr_main(int argc, char **argv)
{
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

    TST_FUNC(err, "1 - Idle Manager Create/Destroy", test1());
    TST_FUNC(err, "2 - Idle Manager misc APIs", test2());
    TST_FUNC(err, "3 - Idle Manager multiple instances", test3());

    return 0;
err:
    return -1;
}
