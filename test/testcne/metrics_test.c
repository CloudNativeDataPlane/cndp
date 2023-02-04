/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2023 Intel Corporation
 */

#include <stdio.h>           // for NULL, EOF
#include <metrics.h>         // for metrics_register
#include <tst_info.h>        // for tst_error, tst_end, tst_start, TST_FAILED

#include "metrics_test.h"

static int
test_cb(metrics_client_t *client, const char *cmd __cne_unused, const char *params __cne_unused)
{
    cne_printf("Test Callback\n");
    metrics_append(client, "\"name\":\"Metrics Test\"");
    return 0;
}

static int
metrics_test(void)
{
    const char *c;
    int ret = 0;
    metrics_client_t *client;
    lport_stats_t stats = {0};
    char lpname[]       = "test_lport";

    client = calloc(1, sizeof(metrics_client_t));
    if (!client)
        return -1;

    client->cmd    = "/test";
    client->params = "params";

    ret = metrics_init(NULL);
    if (ret < 0) {
        ret = errno;
        tst_error("Unable to initialize metrics library, %s\n", strerror(errno));
        free(client);
        /* return errno if this test fails due to permission error */
        return (ret == EPERM) || (ret == EACCES) ? ret : -1;
    }

    tst_ok("PASS --- TEST: Metrics library initialized\n");

    ret = metrics_register(client->cmd, test_cb);
    if (ret < 0) {
        tst_error("Unable to register new metrics command, %s\n", strerror(errno));
        goto err;
    }

    tst_ok("PASS --- TEST: New metrics command, '%s' registered\n", client->cmd);

    c = metrics_cmd(client);
    if (c == NULL) {
        tst_error("Command pointer is NULL\n");
        goto err;
    }

    tst_ok("PASS --- TEST: command pointer retrieved\n");

    c = metrics_params(client);
    if (c == NULL) {
        tst_error("params pointer is NULL\n");
        goto err;
    }

    tst_ok("PASS --- TEST: params pointer retrieved\n");

    ret = metrics_port_stats(client, lpname, &stats);
    if (ret < 0) {
        tst_error("Unable to add lport stats, %s\n", strerror(errno));
        goto err;
    }

    tst_ok("PASS --- TEST: Added lport stats to metrics buffer\n");

    free(client->buffer);
    client->buffer = NULL;

    ret = metrics_destroy();
    if (ret < 0) {
        tst_error("Unable to remove registered metrics commands, %s\n", strerror(errno));
        goto err;
    }

    tst_ok("PASS --- TEST: Removed all registered metrics commands\n");

    free(client);
    return 0;
err:
    metrics_destroy();
    free(client);
    return -1;
}

int
metrics_main(int argc __cne_unused, char **argv __cne_unused)
{
    tst_info_t *tst;
    int err;

    tst = tst_start("Metrics");

    err = metrics_test();
    if (err < 0)
        tst_end(tst, TST_FAILED);
    else if (err == EPERM || err == EACCES)
        tst_end(tst, TST_SKIPPED);
    else
        tst_end(tst, TST_PASSED);

    return err < 0 ? -1 : 0;
}
