/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdio.h>             // for snprintf, fflush, NULL, stdout
#include <cne_common.h>        // for __cne_unused
#include <cne_log.h>           // for CNE_ERR_RET, CNE_LOG_ERR
#include <metrics.h>           // for metrics_append, metrics_register, metrics_cl...
#include <stdint.h>            // for uint64_t
#include <unistd.h>            // for gethostname

#include <cne_lport.h>        // for lport_stats_t
#include <jcfg.h>             // for jcfg_lport_t, jcfg_info_t, jcfg_lport_foreach

#include "main.h"        // for fwd_info, fwd_port, FWD_DEBUG_STATS, enable_...

static uint64_t tick, print_stats_inited;

#define COLUMN_WIDTH     20
#define COLUMN_SEPARATOR "-------------------"

enum { YELLOW_TYPE = 1, MAGENTA_TYPE, CYAN_TYPE, RED_TYPE, GREEN_TYPE, BLUE_TYPE, ORANGE_TYPE };

static void
prt_cnt(int skip, int width, uint64_t cnt, int type)
{
    char buff[64];

    vt_cnright(skip);
    snprintf(buff, sizeof(buff), "%'lu", cnt);

    // clang-format off
    switch(type) {
    case YELLOW_TYPE:   cne_printf("[yellow]%*s [yellow]|\n", width, buff); break;
    case MAGENTA_TYPE:  cne_printf("[magenta]%*s [yellow]|\n", width, buff); break;
    case CYAN_TYPE:     cne_printf("[cyan]%*s [yellow]|\n", width, buff); break;
    case RED_TYPE:      cne_printf("[red]%*s [yellow]|\n", width, buff); break;
    case GREEN_TYPE:    cne_printf("[green]%*s [yellow]|\n", width, buff); break;
    case BLUE_TYPE:     cne_printf("[blue]%*s [yellow]|\n", width, buff); break;
    case ORANGE_TYPE:   cne_printf("[orange]%*s [yellow]|\n", width, buff); break;
    default:            cne_printf("[orange]%*s [yellow]|\n", width, buff); break;
    }
    // clang-format on
}

static void
print_port_stats(int lport_id, struct fwd_port *p, struct fwd_info *fwd)
{
    lport_stats_t stats = {0};
    uint64_t rx_pps, tx_pps;
    uint64_t acl_permit_pps, acl_deny_pps, acl_prefilter_pps;
    int skip, col;

    vt_restore();
    cne_printf("\n\n");

    col  = COLUMN_WIDTH;
    skip = (lport_id + 1) * (col + 2);
    vt_cnright(skip);

    cne_printf("[cyan]%*d[] [yellow]|[]\n", col, lport_id);

    switch (fwd->pkt_api) {
    case XSKDEV_PKT_API:
        (void)xskdev_stats_get(p->xsk, &stats);
        break;
    case PKTDEV_PKT_API:
        (void)pktdev_stats_get(p->lport, &stats);
        break;
    default:
        break;
    }

    rx_pps            = (stats.ipackets - p->ipackets);
    tx_pps            = (stats.opackets - p->opackets);
    acl_permit_pps    = (p->acl_stats.acl_permit - p->prev_acl_stats.acl_permit);
    acl_deny_pps      = (p->acl_stats.acl_deny - p->prev_acl_stats.acl_deny);
    acl_prefilter_pps = (p->acl_stats.acl_prefilter_drop - p->prev_acl_stats.acl_prefilter_drop);

    vt_cnright(skip);
    cne_printf("[yellow]%*s [yellow]+[]\n", col, COLUMN_SEPARATOR);

    prt_cnt(skip, col, rx_pps, YELLOW_TYPE);
    prt_cnt(skip, col, stats.ipackets, MAGENTA_TYPE);
    prt_cnt(skip, col, stats.ibytes / (1024 * 1024), CYAN_TYPE);
    prt_cnt(skip, col, stats.ierrors, RED_TYPE);
    prt_cnt(skip, col, stats.imissed, RED_TYPE);
    prt_cnt(skip, col, stats.rx_invalid, RED_TYPE);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    prt_cnt(skip, col, stats.rx_ring_full, CYAN_TYPE);
    prt_cnt(skip, col, stats.rx_fill_ring_empty, CYAN_TYPE);
#endif

    prt_cnt(skip, col, tx_pps, YELLOW_TYPE);
    prt_cnt(skip, col, stats.opackets, MAGENTA_TYPE);
    prt_cnt(skip, col, stats.obytes / (1024 * 1024), CYAN_TYPE);
    prt_cnt(skip, col, stats.oerrors, RED_TYPE);
    prt_cnt(skip, col, stats.odropped, CYAN_TYPE);
    prt_cnt(skip, col, stats.tx_invalid, RED_TYPE);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    prt_cnt(skip, col, stats.tx_ring_empty, CYAN_TYPE);
#endif

    if (fwd->flags & FWD_ACL_STATS) {
        prt_cnt(skip, col, acl_prefilter_pps, YELLOW_TYPE);
        prt_cnt(skip, col, p->acl_stats.acl_prefilter_drop, MAGENTA_TYPE);

        prt_cnt(skip, col, acl_permit_pps, YELLOW_TYPE);
        prt_cnt(skip, col, p->acl_stats.acl_permit, MAGENTA_TYPE);

        prt_cnt(skip, col, acl_deny_pps, YELLOW_TYPE);
        prt_cnt(skip, col, p->acl_stats.acl_deny, MAGENTA_TYPE);
    }

    if (fwd->flags & FWD_DEBUG_STATS) {
        vt_cnright(skip);
        cne_printf("[yellow]%*s [yellow]+[]\n", col, COLUMN_SEPARATOR);

        prt_cnt(skip, col, stats.rx_ring_empty, CYAN_TYPE);
        prt_cnt(skip, col, stats.rx_buf_alloc, MAGENTA_TYPE);
        prt_cnt(skip, col, stats.rx_busypoll_wakeup, CYAN_TYPE);
        prt_cnt(skip, col, stats.rx_poll_wakeup, CYAN_TYPE);
        prt_cnt(skip, col, stats.rx_rcvd_count, CYAN_TYPE);
        prt_cnt(skip, col, stats.rx_burst_called, CYAN_TYPE);

        prt_cnt(skip, col, stats.fq_add_count, CYAN_TYPE);
        prt_cnt(skip, col, stats.fq_alloc_failed, RED_TYPE);
        prt_cnt(skip, col, stats.fq_buf_freed, CYAN_TYPE);

        prt_cnt(skip, col, stats.tx_kicks, CYAN_TYPE);
        prt_cnt(skip, col, stats.tx_kick_failed, RED_TYPE);
        prt_cnt(skip, col, stats.tx_kick_again, RED_TYPE);
        prt_cnt(skip, col, p->tx_overrun, CYAN_TYPE);
        prt_cnt(skip, col, stats.tx_ring_full, CYAN_TYPE);
        prt_cnt(skip, col, stats.tx_copied, CYAN_TYPE);

        prt_cnt(skip, col, stats.cq_empty, MAGENTA_TYPE);
        prt_cnt(skip, col, stats.cq_buf_freed, MAGENTA_TYPE);
    }

    p->ipackets                          = stats.ipackets;
    p->opackets                          = stats.opackets;
    p->prev_acl_stats.acl_prefilter_drop = p->acl_stats.acl_prefilter_drop;
    p->prev_acl_stats.acl_permit         = p->acl_stats.acl_permit;
    p->prev_acl_stats.acl_deny           = p->acl_stats.acl_deny;
}

static int
_print_stats(jcfg_info_t *j __cne_unused, void *obj, void *arg, int idx __cne_unused)
{
    jcfg_lport_t *lport  = obj;
    struct fwd_port *pd  = lport->priv_;
    struct fwd_info *fwd = (struct fwd_info *)arg;

    print_port_stats(lport->lpid, pd, fwd);

    return 0;
}

enum {
    DFLT_LINE,
    TICK_LINE,
    COL_LINE,
    HDR_LINE,
    ACL_LINE  = 0x100,
    DBG_LINE  = 0x80,
    LINE_MASK = 0x7f
};

struct stats_line {
    int type;
    const char *fmt;
    const char *msg;
    const char *hdr;
} stat_lines[] = {
    {DFLT_LINE, "\n"},
    {TICK_LINE, "[cyan:-:italic]Running:  [yellow:-:bold]%c[]\n", ""},

    {COL_LINE, "[cyan:-:bold]%-*s [yellow:-:-]|[]\n", "lport ID"},
    {COL_LINE, "[yellow]%-*s [yellow]+[]\n", COLUMN_SEPARATOR},
    {HDR_LINE, "[yellow:-:italic]%-*s [green:-:-]%-*s [yellow]|[]\n", "Pkts/s", "RX"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Total Pkts"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Total MBs"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Errors"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Missed"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Invalid"},
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   ring full"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   ring empty"},
#endif
    {HDR_LINE, "[yellow:-:italic]%-*s [green:-:-]%-*s [yellow]|[]\n", "Pkts/s", "TX"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Total Pkts"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Total MBs"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Errors"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Dropped"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Invalid"},
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   ring empty"},
#endif

    {HDR_LINE | ACL_LINE, "[yellow:-:italic]%-*s [green:-:-]%-*s [yellow]|[]\n", "Pkts/s",
     "ACL Drop"},
    {COL_LINE | ACL_LINE, "[green]%-*s [yellow]|[]\n", "   Total Pkts", NULL},
    {HDR_LINE | ACL_LINE, "[yellow:-:italic]%-*s [green:-:-]%-*s [yellow]|[]\n", "Pkts/s",
     "ACL Permit"},
    {COL_LINE | ACL_LINE, "[green]%-*s [yellow]|[]\n", "   Total Pkts", NULL},
    {HDR_LINE | ACL_LINE, "[yellow:-:italic]%-*s [green:-:-]%-*s [yellow]|[]\n", "Pkts/s",
     "ACL Deny"},
    {COL_LINE | ACL_LINE, "[green]%-*s [yellow]|[]\n", "   Total Pkts", NULL},

    {COL_LINE | DBG_LINE, "[magenta:-:italic]%-*s [yellow:-:-]+ []\n", "Debug Stats"},
    {HDR_LINE | DBG_LINE, "[yellow:-:italic]%-*s [cyan:-:-]%-*s [yellow]|[]\n", "Ring Empty", "RX"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Buf Alloc"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Call Busypoll"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Call Poll"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Rcvd Count"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Burst Called"},

    {HDR_LINE | DBG_LINE, "[yellow:-:italic]%-*s [cyan:-:-]%-*s [yellow]|[]\n", "Added", "FQ"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Alloc Failed"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Buf Freed"},

    {HDR_LINE | DBG_LINE, "[yellow:-:italic]%-*s [cyan:-:-]%-*s [yellow]|[]\n", "Kicks", "TX"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Kicks Failed"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Kicks again"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Ring Full"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Overrun"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Copied"},
    {HDR_LINE | DBG_LINE, "[yellow:-:italic]%-*s [cyan:-:-]%-*s [yellow]|[]\n", "Empty", "CQ"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Buf Freed"},
    {DFLT_LINE, "[]\n"}};

static void
print_stats_init(struct fwd_info *fwd)
{
    int nlines = 0;

    print_stats_inited = 1;

    for (int i = 0; i < cne_countof(stat_lines); i++) {
        struct stats_line *st = &stat_lines[i];

        /* Skip the extra debug stats lines */
        if (!(fwd->flags & FWD_DEBUG_STATS) && (st->type & DBG_LINE))
            continue;

        /* Skip the extra ACL stats lines */
        if (!(fwd->flags & FWD_ACL_STATS) && (st->type & ACL_LINE))
            continue;

        nlines++;
    }

    vt_make_space(nlines);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

void
print_port_stats_all(struct fwd_info *fwd)
{
    int col = COLUMN_WIDTH;

    if (!print_stats_inited)
        print_stats_init(fwd);

    vt_save();
    for (int i = 0; i < cne_countof(stat_lines); i++) {
        struct stats_line *st = &stat_lines[i];
        unsigned int hdrlen;

        /* Skip the extra debug stats lines */
        if (!(fwd->flags & FWD_DEBUG_STATS) && (st->type & DBG_LINE))
            continue;

        /* skip ACL lines */
        if (!(fwd->flags & FWD_ACL_STATS) && (st->type & ACL_LINE))
            continue;

        switch (st->type & LINE_MASK) {
        case DFLT_LINE:
            cne_printf(st->fmt, st->msg);
            break;
        case TICK_LINE:
            cne_printf(st->fmt, "|/-\\"[tick % 4]);
            tick++;
            break;
        case COL_LINE:
            cne_printf(st->fmt, col, st->msg);
            break;
        case HDR_LINE:
            hdrlen = strlen(st->hdr);
            cne_printf(st->fmt, hdrlen, st->hdr, col - hdrlen - 1, st->msg);
            break;
        case DBG_LINE:
            break;
        default:
            break;
        }
    }
    jcfg_lport_foreach(fwd->jinfo, _print_stats, fwd);

    vt_restore();
}
#pragma GCC diagnostic pop

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
    metrics_append(c, "\"name\":\"cndpfwd\"");

    return 0;
}

static int
handle_stats(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_lport_t *lport  = obj;
    struct fwd_port *pd  = lport->priv_;
    lport_stats_t stats  = {0};
    metrics_client_t *c  = arg;
    struct fwd_info *fwd = (struct fwd_info *)(c->info->priv);

    switch (fwd->pkt_api) {
    case XSKDEV_PKT_API:
        xskdev_stats_get(pd->xsk, &stats);
        break;
    case PKTDEV_PKT_API:
        pktdev_stats_get(pd->lport, &stats);
        break;
    default:
        break;
    }

    if (lport->lpid > 0)
        metrics_append(c, ",");

    if (metrics_port_stats(c, lport->name, &stats) < 0)
        return -1;

    /* only publish ACL-related stats in one of the ACL modes */
    if (fwd->flags & FWD_ACL_STATS) {
        metrics_append(c, ",\"%s_n_acl_prefilter_drop_packets\":%ld", lport->name,
                       pd->acl_stats.acl_prefilter_drop);
        metrics_append(c, ",\"%s_n_acl_permit_packets\":%ld", lport->name,
                       pd->acl_stats.acl_permit);
        metrics_append(c, ",\"%s_n_acl_deny_packets\":%ld", lport->name, pd->acl_stats.acl_deny);
    }

    return 0;
}

static int
fwd_stats(metrics_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    struct fwd_info *fwd = (struct fwd_info *)(c->info->priv);
    return jcfg_lport_foreach(fwd->jinfo, handle_stats, c);
}

int
enable_metrics(struct fwd_info *fwd)
{
    print_stats_inited = 0;
    tick               = 0;
    if (metrics_init((void *)fwd) < 0)
        CNE_ERR_RET("metrics failed to initialize: %s\n", strerror(errno));

    if (metrics_register("/port_stats", fwd_stats) < 0)
        CNE_ERR_RET("Failed to register the metric stats\n");

    return 0;
}

static int
handle_thread(jcfg_info_t *j __cne_unused, void *obj, void *arg, int idx)
{
    jcfg_thd_t *thread = obj;
    uds_client_t *c    = arg;
    unsigned int i;

    if (idx > 0)
        metrics_append(c, ",");

    uds_append(c, "{");

    /* JSON is unsorted, so if we want order, we need to provide id's */
    uds_append(c, "\"id\":%d,", thread->idx);
    uds_append(c, "\"name\":\"%s\",", thread->name);
    uds_append(c, "\"group\":\"%s\",", thread->group_name);
    uds_append(c, "\"type\":\"%s\",", thread->thread_type);
    uds_append(c, "\"ports\":[");
    for (i = 0; i < thread->lport_cnt; i++) {
        if (i > 0)
            uds_append(c, ",");
        uds_append(c, "\"%s\"", thread->lport_names[i]);
    }
    uds_append(c, "]");
    uds_append(c, "}");

    return 0;
}

static int
handle_port(jcfg_info_t *j __cne_unused, void *obj, void *arg, int idx)
{
    jcfg_lport_t *lport = obj;
    uds_client_t *c     = arg;

    if (idx > 0)
        metrics_append(c, ",");

    uds_append(c, "{");

    /* JSON is unsorted, so if we want order, we need to provide id's */
    uds_append(c, "\"id\":%d,", lport->lpid);
    uds_append(c, "\"name\":\"%s\",", lport->name);
    uds_append(c, "\"netdev\":\"%s\",", lport->netdev);
    uds_append(c, "\"qid\":%d,", lport->qid);
    uds_append(c, "\"pmd_name\":\"%s\"", lport->pmd_name);

    uds_append(c, "}");

    return 0;
}

static int
fwd_threads(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    int ret;
    struct fwd_info *fwd = (struct fwd_info *)(c->info->priv);

    uds_append(c, "\"threads\":[");
    ret = jcfg_thread_foreach(fwd->jinfo, handle_thread, c);
    uds_append(c, "]");

    return ret;
}

static int
fwd_ports(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    int ret;
    struct fwd_info *fwd = (struct fwd_info *)(c->info->priv);

    uds_append(c, "\"ports\":[");
    ret = jcfg_lport_foreach(fwd->jinfo, handle_port, c);
    uds_append(c, "]");

    return ret;
}

struct thread_arg {
    uds_client_t *client;
    bool pause;
    bool first;
};
static int
pause_thread(jcfg_info_t *j __cne_unused, void *obj, void *arg, int idx __cne_unused)
{
    jcfg_thd_t *thd       = obj;
    struct thread_arg *ta = arg;

    /* don't try to pause main thread */
    if (strcasecmp(thd->thread_type, "main") == 0)
        return 0;

    thd->pause = ta->pause;

    if (!ta->first)
        uds_append(ta->client, ",");
    ta->first = false;

    uds_append(ta->client, "{\"name\":\"%s\",\"status\":\"%s\"}", thd->name,
               ta->pause ? "paused" : "running");

    return 0;
}

static int
fwd_thread_ctl(uds_client_t *c, const char *cmd, const char *params)
{
    struct thread_arg ta;
    int ret;
    struct fwd_info *fwd = (struct fwd_info *)(c->info->priv);

    ta.client = c;
    ta.first  = true;

    /* both commands require a parameter */
    if (params == NULL) {
        uds_append(c, "\"error\":\"Command requires thread name (or 'all') as a parameter\"");
        return 0;
    }

    if (strcasecmp(cmd, "/start") == 0) {
        ta.pause = false;
    } else if (strcasecmp(cmd, "/stop") == 0) {
        ta.pause = true;
    } else {
        /* should not ever happen */
        CNE_ASSERT(0);
        uds_append(c, "\"error\":\"Invalid command\"");
        return 0;
    }

    /* do we want to touch all threads or just a particular one? */
    if (strcasecmp(params, "all") == 0) {
        uds_append(c, "\"threads\":[");
        ret = jcfg_thread_foreach(fwd->jinfo, pause_thread, &ta);
        uds_append(c, "]");
    } else {
        /* find a thread with requested name */
        jcfg_thd_t *thd = jcfg_lookup_thread(fwd->jinfo, params);
        if (thd != NULL) {
            uds_append(c, "\"threads\":[");
            ret = pause_thread(fwd->jinfo, thd, &ta, 0);
            uds_append(c, "]");
        } else {
            ret = 0;
            uds_append(c, "\"error\":\"Thread '%s' not found\"", params);
        }
    }
    return ret;
}

int
enable_uds_info(struct fwd_info *fwd)
{
    uds_info_t *info = uds_get_default(fwd);
    const uds_group_t *app_grp;

    if (info == NULL)
        CNE_ERR_RET("UDS failed to initialize: %s\n", strerror(errno));

    app_grp = uds_create_group(info, "app", (void *)fwd);
    if (app_grp == NULL)
        CNE_ERR_RET("UDS 'app' group create failed: %s\n", strerror(errno));

    if (uds_register(app_grp, "/hostname", fwd_host) < 0)
        CNE_ERR_RET("Failed to register the metrics host\n");

    if (uds_register(app_grp, "/appname", fwd_app) < 0)
        CNE_ERR_RET("Failed to register the metrics app\n");

    if (uds_register(app_grp, "/threads", fwd_threads))
        CNE_ERR_RET("Failed to register threads command: %s\n", strerror(errno));

    if (uds_register(app_grp, "/ports", fwd_ports))
        CNE_ERR_RET("Failed to register ports command: %s\n", strerror(errno));

    if (uds_register(app_grp, "/stop", fwd_thread_ctl))
        CNE_ERR_RET("Failed to register stop command: %s\n", strerror(errno));

    if (uds_register(app_grp, "/start", fwd_thread_ctl))
        CNE_ERR_RET("Failed to register start command: %s\n", strerror(errno));

    if (fwd->test == ACL_STRICT_TEST || fwd->test == ACL_PERMISSIVE_TEST) {
        const uds_group_t *acl_grp;

        acl_grp = uds_create_group(info, "acl", NULL);
        if (acl_grp == NULL)
            CNE_ERR_RET("UDS 'acl' group create failed: %s\n", strerror(errno));

        if (uds_register(acl_grp, "/clear", fwd_acl_clear))
            CNE_ERR_RET("Failed to register ACL clear command: %s\n", strerror(errno));
        if (uds_register(acl_grp, "/add", fwd_acl_add_rule))
            CNE_ERR_RET("Failed to register ACL add rule command: %s\n", strerror(errno));
        if (uds_register(acl_grp, "/build", fwd_acl_build))
            CNE_ERR_RET("Failed to register ACL build command: %s\n", strerror(errno));
        if (uds_register(acl_grp, "/rules", fwd_acl_read))
            CNE_ERR_RET("Failed to register ACL rules command: %s\n", strerror(errno));
    }

    return 0;
}
