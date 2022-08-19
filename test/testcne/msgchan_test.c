/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

#include <stdio.h>         // for NULL, snprintf, EOF
#include <string.h>        // for strcmp, strncmp
#include <getopt.h>        // for getopt_long, option
#include <pthread.h>
#include <cne_common.h>        // for CNE_SET_USED, __cne_unused
#include <tst_info.h>          // for TST_ASSERT_EQUAL_AND_CLEANUP, tst_end, TST_A...
#include <msgchan.h>

#include "msgchan_test.h"

#define MSG_CHAN_SIZE 2048

static pthread_barrier_t barrier;
static volatile bool thread_done = false;
static volatile int serror, cerror;
static int verbose;

static inline void
set_object_values(void **objs, int count, int start_val)
{
    for (int i = 0; i < count; i++)
        objs[i] = (void *)(uintptr_t)start_val;
}

static inline int
tst_object_values(void **objs, int count, int start_val)
{
    for (int i = 0; i < count; i++) {
        if (objs[i] != (void *)(uintptr_t)start_val)
            return -1;
    }
    return 0;
}

static int
test1(void)
{
    int sizes[]                       = {64, 128, 256, 512, 1024, 2048, 4096, 8192};
    msgchan_t *mc[cne_countof(sizes)] = {0};
    char name[64]                     = {0};

    memset(mc, 0, sizeof(mc));

    for (int i = 0; i < cne_countof(mc); i++) {
        snprintf(name, sizeof(name), "test-%d", i);

        mc[i] = mc_create(name, sizes[i], 0);
        if (!mc[i])
            goto err;
    }

    for (int i = 0; i < cne_countof(mc); i++) {
        if (mc[i])
            mc_destroy(mc[i]);
    }
    return 0;
err:
    for (int i = 0; i < cne_countof(mc); i++) {
        if (mc[i])
            mc_destroy(mc[i]);
    }
    return -1;
}

static int
test2(void)
{
    msgchan_t *mc1 = NULL, *mc2 = NULL;
    int counts[] = {1, 4, 7, 8, 16, 32, 63, 64, 128, 256};
    void *objs[256], *robjs[256];

    mc1 = mc_create("test2", MSG_CHAN_SIZE, 0);
    if (!mc1)
        CNE_ERR_GOTO(err, "1 mc_create() failed\n");

    mc2 = mc_create("test2", MSG_CHAN_SIZE, 0);
    if (!mc2)
        CNE_ERR_GOTO(err, "2 mc_create() failed\n");

    if (verbose)
        mc_list();

    for (int i = 0; i < cne_countof(counts); i++) {
        int count = counts[i];
        int n;

        if (verbose)
            cne_printf("   [cyan]Test [green]%4d [cyan]object count[]\n", count);

        memset(objs, 0, (sizeof(void *) * count));

        set_object_values(objs, count, 0x1234);

        n = mc_send(mc1, objs, count);
        if (n < 0)
            CNE_ERR_GOTO(err, "mc_send() failed: %d\n", n);
        if (n != count)
            CNE_ERR_GOTO(err, "Send %d objs did not match expected %d\n", count, n);

        memset(robjs, 0, sizeof(robjs));
        n = mc_recv(mc2, robjs, count, 0);
        if (n < 0)
            CNE_ERR_GOTO(err, "mc_recv() failed: %d\n", n);
        if (n != count)
            CNE_ERR_GOTO(err, "Recv %d objs did not match expected %d\n", count, n);

        if (tst_object_values(robjs, n, 0x1234))
            CNE_ERR_GOTO(err, "Value returned is invalid\n");
    }

    if (verbose) {
        mc_dump(mc1);
        mc_dump(mc2);
    }

    mc_destroy(mc2);
    mc_destroy(mc1);

    return 0;
err:
    mc_destroy(mc2);
    mc_destroy(mc1);
    return -1;
}

static void *
server_func(void *arg)
{
    msgchan_t *mc = arg;
    uint64_t vals[128];
    int ret;

    cne_printf(
        "  [orange]>>> [magenta]Server started, waiting for client thread, msgchan: [cyan]%s[]\n",
        mc_name(mc));

    ret = pthread_barrier_wait(&barrier);
    if (ret > 0)
        CNE_ERR_GOTO(err, "barrier wait failed: %s\n", strerror(ret));

    thread_done = false;
    while (!thread_done) {
        int n;

        n = mc_recv(mc, (void **)vals, cne_countof(vals), 1);
        if (n < 0)
            CNE_ERR_GOTO(err, " [orange]Server[] [red]Received error[]\n");
        if (n) {
            int cnt = 0, nn;

            for (int i = 0; i < n; i++) {
                if (vals[i] == 0xdeadbeef) {
                    thread_done = true;
                    goto leave;
                }
                cnt++;
            }
            nn = mc_send(mc, (void **)vals, cnt);
            if (nn < 0)
                CNE_ERR_GOTO(err, "[orange]mc_send()[] returned error\n");
            if (nn != n)
                CNE_ERR_GOTO(err,
                             "[orange]mc_send()[] did not return [cyan]%d[], but got [cyan]%d[]\n",
                             n, nn);
        }
    }
leave:
    if (verbose)
        cne_printf("  [orange]<<< [magenta]Server exiting[]\n");

    return NULL;
err:
    thread_done = 1;
    serror      = -1;
    return NULL;
}

static void *
client_func(void *arg)
{
    msgchan_t *mc = arg;
    int counts[]  = {1, 4, 8, 16, 32, 64, 128, 256};
    void *vals[256], *rvals[256];
    int n, ret, k;

    cne_printf(
        "  [orange]>>> [magenta]Client started, waiting for server thread, msgchan: [cyan]%s[]\n",
        mc_name(mc));

    ret = pthread_barrier_wait(&barrier);
    if (ret > 0)
        CNE_ERR_GOTO(err, "barrier wait failed: %s\n", strerror(ret));

    for (int j = 0; j < cne_countof(counts) && !thread_done; j++) {
        int nb = 0, cnt = counts[j];

        for (int i = 0; i < 5000 && !thread_done; i++) {

            set_object_values(vals, cne_countof(vals), 0xfeedbeef);

            k = 0;
            while (!thread_done && cnt) {
                n = mc_send(mc, &vals[k], cnt);
                if (n < 0)
                    CNE_ERR_GOTO(err, "  [magenta]Client Send [green]%3d[] != [green]%d[]\n", n,
                                 cnt);
                cnt -= n;
                k += n;
            }

            memset(rvals, 0x55, sizeof(rvals));

            nb = mc_recv(mc, (void **)rvals, cne_countof(rvals), 0);
            if (nb < 0 || tst_object_values(rvals, nb, 0xfeedbeef))
                CNE_ERR_GOTO(err, "  [magenta]Client failed[]\n");
        }
    }

    if (verbose)
        cne_printf("  [orange]<<< [magenta]Client exiting[]\n");

    if (!thread_done) {
        vals[0] = (void *)(uintptr_t)0xdeadbeef;
        if (mc_send(mc, (void **)vals, 1) != 1)
            CNE_ERR_GOTO(err, "Closing send failed\n");
    }

    return NULL;
err:
    thread_done = 1;
    cerror      = -1;
    return NULL;
}

static int
test3(void)
{
    pthread_t s, c;
    msgchan_t *server = NULL, *client = NULL;
    int err, barrier_inited = 0, sthread_inited = 0, cthread_inited = 0;

    serror = cerror = 0;

    server = mc_create("test3", MSG_CHAN_SIZE, 0);
    if (!server)
        CNE_ERR_GOTO(err_exit, "Creating Server message channel failed\n");

    client = mc_create("test3", MSG_CHAN_SIZE, 0);
    if (!client)
        CNE_ERR_GOTO(err_exit, "Creating Client message channel failed\n");

    err = pthread_barrier_init(&barrier, NULL, 3);
    if (err)
        CNE_ERR_GOTO(err_exit, "barrier init failed: %s\n", strerror(err));
    barrier_inited = 1;

    err = pthread_create(&s, NULL, server_func, server);
    if (err)
        CNE_ERR_GOTO(err_exit, "Unable to start server thread: %s\n", strerror(err));
    sthread_inited = 1;

    err = pthread_create(&c, NULL, client_func, client);
    if (err)
        CNE_ERR_GOTO(err_exit, "Unable to start client thread: %s\n", strerror(err));
    cthread_inited = 1;

    err = pthread_barrier_wait(&barrier);
    if (err > 0)
        CNE_ERR_GOTO(err_exit, "barrier wait failed: %s\n", strerror(err));

    /*
     * Seems to be a race condition as pthread_join() will hang if test is run
     * multiple times in a row. We sleep to give the server/client threads a chance to run.
     */
    usleep(1000);

    err = pthread_join(s, NULL);
    if (err)
        CNE_ERR_GOTO(err_exit, "pthread_join(server) failed: %s\n", strerror(err));

    err = pthread_join(c, NULL);
    if (err)
        CNE_ERR_GOTO(err_exit, "pthread_join(client) failed: %s\n", strerror(err));

    err = pthread_barrier_destroy(&barrier);
    if (err)
        CNE_ERR_GOTO(err_exit, "barrier destroy failed: %s\n", strerror(err));

    if (verbose) {
        mc_dump(server);
        mc_dump(client);
    }

    mc_destroy(client);
    mc_destroy(server);

    return (serror || cerror) ? -1 : 0;

err_exit:
    thread_done = true;
    if (sthread_inited) {
        err = pthread_join(s, NULL);
        if (err)
            CNE_ERR("join(server) failed: %s\n", strerror(err));
    }
    if (cthread_inited) {
        err = pthread_join(c, NULL);
        if (err)
            CNE_ERR("join(client) failed: %s\n", strerror(err));
    }
    if (barrier_inited) {
        err = pthread_barrier_destroy(&barrier);
        if (err)
            CNE_ERR("barrier destroy failed: %s\n", strerror(err));
    }
    mc_destroy(client);
    mc_destroy(server);

    return -1;
}

int
msgchan_main(int argc, char **argv)
{
    tst_info_t *tst;
    int opt;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    verbose = 0;
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

    tst = tst_start("MsgChan Create/List/Destroy");
    if (test1() < 0)
        goto leave;
    tst_end(tst, TST_PASSED);

    tst = tst_start("MsgChan Server multiple sizes");
    if (test2() < 0)
        goto leave;
    tst_end(tst, TST_PASSED);

    tst = tst_start("MsgChan Server/Client");
    if (test3() < 0)
        goto leave;
    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_end(tst, TST_FAILED);

    return -1;
}
