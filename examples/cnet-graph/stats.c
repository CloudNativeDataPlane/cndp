/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation.
 */

#include <stdio.h>             // for snprintf, fflush, NULL, stdout
#include <cne_common.h>        // for __cne_unused
#include <cne_log.h>           // for CNE_ERR_RET, CNE_LOG_ERR
#include <metrics.h>           // for metrics_append, metrics_register, metrics_cl...
#include <stdint.h>            // for uint64_t
#include <pktmbuf.h>           // IWYU pragma: keep
#include <unistd.h>            // for gethostname

#include "cnet-graph.h"        // for fwd_info, fwd_port, FWD_DEBUG_STATS, enable_...
#include "cne_lport.h"         // for lport_stats_t
#include "jcfg.h"              // for jcfg_lport_t, jcfg_info_t, jcfg_lport_foreach
#include "pktdev_api.h"        // for pktdev_stats_get

extern struct cnet_info *cinfo;

static int
fwd_host(metrics_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    char hostname[256];

    if (gethostname(hostname, sizeof(hostname)) < 0)
        return -1;

    metrics_append(c, "\"hostname\":\"%s\"", hostname);

    return 0;
}

static int
fwd_app(metrics_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    metrics_append(c, "\"name\":\"cnet-graph\"");

    return 0;
}

static int
handle_stats(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_lport_t *lport = obj;
    struct fwd_port *pd = lport->priv_;
    lport_stats_t stats = {0};
    metrics_client_t *c = arg;

    pktdev_stats_get(pd->lport, &stats);

    if (lport->lpid > 0)
        metrics_append(c, ",");

    return metrics_port_stats(c, lport->name, &stats);
}

static int
fwd_stats(metrics_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    return jcfg_lport_foreach(cinfo->jinfo, handle_stats, c);
}

int
enable_metrics(void)
{
    if (metrics_init(NULL) < 0)
        CNE_ERR_RET("metrics failed to initialize: %s\n", strerror(errno));

    if (metrics_register("/host", fwd_host) < 0)
        CNE_ERR_RET("Failed to register the metrics host\n");

    if (metrics_register("/app", fwd_app) < 0)
        CNE_ERR_RET("Failed to register the metrics app\n");

    if (metrics_register("/stats", fwd_stats) < 0)
        CNE_ERR_RET("Failed to register the metric stats\n");

    return 0;
}
