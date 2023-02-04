/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation.
 */

#include <cne.h>        // for cne_init,
#include <cne_log.h>
#include <cne_thread.h>

#include <ibroker.h>

#include "main.h"

static struct app_info app_info = {0};
struct app_info *app            = &app_info;
static int tick;
uint64_t total_interrupts;

#define UIPI_BURST_COUNT 16 /**< Number of UIPI to send in a burst */

static int
walk_func(broker_id_t bid, void *arg __cne_unused)
{
    ibroker_info_t info = {0};

    if (ibroker_info(bid, &info) < 0)
        CNE_ERR_RET("ibroker_dump() failed: %s\n", strerror(errno));

    cne_printf("[yellow]%s[] ([magenta]%d[]): %8ld\n", info.name, info.tid, info.intrs);
    for (int i = 0; i < IBROKER_MAX_SERVICES; i++) {
        struct service_info *sinfo = &info.services[i];
        if (sinfo->valid)
            cne_printf("   [green]%-16s[] [magenta]%2d[]: [green]%8ld[] [red]%8ld[]\n", sinfo->name,
                       sinfo->uintr_fd, sinfo->call_cnt, sinfo->err_cnt);
    }

    return 0;
}

static void
page_stats(void)
{
    cne_printf_pos(1, 1, "[magenta]Running [green]%c[] [magenta]Total interrupts [green]%ld[]\n",
                   "|/-\\"[tick & 3], total_interrupts);
    tick++;

    if (ibroker_walk(walk_func, NULL) < 0)
        CNE_ERR("Failed: %s\n", strerror(errno));
}

static void
thread_func(void *arg)
{
    broker_id_t bid;
    pthread_t *pid = arg;
    char buff[128];
    const char *name;

    *pid = pthread_self();

    name = thread_name(-1);
    if (!name)
        CNE_RET("Not a value thread name\n");

    bid = ibroker_create(name);
    if (bid < 0)
        CNE_RET("Unable to register ibroker %s\n", thread_name(-1));

    for (int i = 0; i < app->num_services; i++) {
        snprintf(buff, sizeof(buff), "srv-%s-%d", thread_name(-1), i);
        if (ibroker_add_service(bid, buff, i, srv_func, NULL) < 0)
            CNE_RET("Unable to add service vector %2d to ibroker %-12s:%s\n", i, thread_name(-1),
                    buff);
    }

    if (pthread_barrier_wait(&app->barrier) > 0)
        CNE_RET("Barrier wait failed: %s\n", strerror(errno));

    while (app->quit == 0)
        usleep(100);
}

static void
sender_func(void *arg __cne_unused)
{
    int id_cnt;
    broker_id_t *ids = NULL;

    id_cnt = ibroker_id_list(NULL, 0);
    if (id_cnt <= 0)
        CNE_ERR_GOTO(leave, "Get id list failed\n");
    else {
        ids = calloc(id_cnt, sizeof(broker_id_t));

        if ((ids == NULL) || (ibroker_id_list(ids, id_cnt) < 0))
            CNE_ERR_GOTO(leave, "ibroker id list failed\n");
    }

    for (int i = 0; i < id_cnt; i++)
        for (int j = 0; j < app->num_services; j++)
            ibroker_register_sender(ids[i], j);

    for (;;) {
        usleep(1000);
        if (app->quit)
            break;
        for (int i = 0; i < UIPI_BURST_COUNT; i++) {
            broker_id_t id = ids[rand() % id_cnt];

            ibroker_send(id, rand() % app->num_services);
        }
    }

    for (int i = 0; i < id_cnt; i++) {
        int bid = ids[i];

        for (int j = 0; j < app->num_services; j++) {
            if (ibroker_del_service(ids[i], j) < 0)
                CNE_ERR_GOTO(leave, "Unable to delete service vector %2d to ibroker %-12s:%s\n", j,
                             thread_name(-1), ibroker_service_name(bid, j));
        }
    }

leave:
    free(ids);
}

static void
__on_exit(int val, void *arg, int exit_type)
{
    struct app_info *a = arg;

    switch (exit_type) {
    case CNE_CAUGHT_SIGNAL:
        /* Terminate the application if not USR1 signal, allows for GDB breakpoint setting */
        if (val == SIGUSR1)
            return;

        cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with signal [green]%d[]\n", val);

        if (a)
            a->quit = 1;

        break;

    case CNE_CALLED_EXIT:
        if (a)
            a->quit = 1;
        if (val)
            cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with status [green]%d[]\n", val);
        break;

    case CNE_USER_EXIT:
        cne_printf_pos(99, 1, "\n>>> [cyan]Terminating[]\n");
        break;

    default:
        break;
    }
    fflush(stdout);
}

int
main(int argc, char **argv)
{
    char buff[128];
    int tidx, signals[] = {SIGINT, SIGUSR1, SIGUSR2};

    // Setup the random number seed.
    srand(0x20250630 + (getpid() * 333));

    if ((tidx = cne_init()) < 0)
        CNE_ERR_GOTO(err, "Unable to parse the arguments\n");

    cne_on_exit(__on_exit, app, signals, cne_countof(signals));

    if (parse_args(argc, argv))
        CNE_ERR_GOTO(err, "Unable to parse the arguments\n");

    vt_cls();
    cne_printf_pos(99, 1,
                   "[yellow]*** [magenta]iBroker[], [magenta]PID[]: [red]%d[], [magenta]Number of "
                   "brokers[]: [green]%d[], [magenta]Number of Services[]: [green]%d[]\n",
                   getpid(), app->num_brokers, app->num_services);

    /* Make sure we account for this thread in the barrier by adding one */
    if (pthread_barrier_init(&app->barrier, NULL, app->num_brokers + 1))
        CNE_ERR_GOTO(err, "Barrier initialize failed: %s\n", strerror(errno));

    if (app->num_brokers >= MAX_THREADS)
        CNE_ERR_GOTO(leave, "Number of brokers exceeds %d\n", MAX_THREADS);

    for (int i = 0; i < app->num_brokers; i++) {
        snprintf(buff, sizeof(buff), "Broker-%d", i);

        if (thread_create(buff, thread_func, &app->thread_ids[i]) < 0)
            CNE_ERR_GOTO(leave, "Unable to create broker thread\n");
    }

    cne_printf("Wait until [red]Ctrl-C[] is pressed\n");
    sleep(1);

    if (pthread_barrier_wait(&app->barrier) > 0)
        CNE_ERR_GOTO(leave, "Barrier wait failed: %s", strerror(errno));

    if (thread_create("Sender", sender_func, &app->sender_id) < 0)
        CNE_ERR_GOTO(leave, "Unable to create sender thread\n");

    for (;;) {
        sleep(1);
        if (app->quit)
            break;
        page_stats();
    }
    sleep(1);

    pthread_barrier_destroy(&app->barrier);
    cne_unregister(tidx);
    return EXIT_SUCCESS;

leave:
    pthread_barrier_destroy(&app->barrier);
err:
    if (tidx >= 0)
        cne_unregister(tidx);
    return EXIT_FAILURE;
}
