/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
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
        tst_error("Unable to initialize metrics library, %s\n", strerror(errno));
        free(client);
        return -1;
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

    tst = tst_start("Metrics");

    if (metrics_test() < 0)
        goto err;

    tst_end(tst, TST_PASSED);
    return 0;
err:
    tst_end(tst, TST_FAILED);
    return -1;
}
