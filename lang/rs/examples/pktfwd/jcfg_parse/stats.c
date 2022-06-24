/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdio.h>             // for snprintf, fflush, NULL, stdout
#include <cne_common.h>        // for __cne_unused
#include <cne_log.h>           // for CNE_ERR_RET, CNE_LOG_ERR
#include <metrics.h>           // for metrics_append, metrics_register, metrics_cl...
#include <stdint.h>            // for uint64_t
#include <pktmbuf.h>           // IWYU pragma: keep
#include <unistd.h>            // for gethostname

#include "fwd.h"               // for fwd_info, fwd_port, FWD_DEBUG_STATS, enable_...
#include "cne_lport.h"         // for lport_stats_t
#include "jcfg.h"              // for jcfg_lport_t, jcfg_info_t, jcfg_lport_foreach
#include "pktdev_api.h"        // for pktdev_stats_get

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
    int skip, col;

    vt_restore();
    cne_printf("\n\n");

    col  = COLUMN_WIDTH;
    skip = (lport_id + 1) * (col + 2);
    vt_cnright(skip);

    cne_printf("[blue]%*d[] [yellow]|[]\n", col, lport_id);

    pktdev_stats_get(p->lport, &stats);

    rx_pps = (stats.ipackets - p->ipackets);
    tx_pps = (stats.opackets - p->opackets);

    vt_cnright(skip);
    cne_printf("[yellow]%*s [yellow]+[]\n", col, COLUMN_SEPARATOR);

    prt_cnt(skip, col, rx_pps, YELLOW_TYPE);
    prt_cnt(skip, col, stats.ipackets, MAGENTA_TYPE);
    prt_cnt(skip, col, stats.ibytes / (1024 * 1024), CYAN_TYPE);
    prt_cnt(skip, col, stats.ierrors, RED_TYPE);
    prt_cnt(skip, col, stats.imissed, RED_TYPE);
    prt_cnt(skip, col, stats.rx_invalid, RED_TYPE);

    prt_cnt(skip, col, tx_pps, YELLOW_TYPE);
    prt_cnt(skip, col, stats.opackets, MAGENTA_TYPE);
    prt_cnt(skip, col, stats.obytes / (1024 * 1024), CYAN_TYPE);
    prt_cnt(skip, col, stats.oerrors, RED_TYPE);
    prt_cnt(skip, col, stats.odropped, CYAN_TYPE);
    prt_cnt(skip, col, stats.tx_invalid, RED_TYPE);

    if (fwd->flags & FWD_DEBUG_STATS) {
        vt_cnright(skip);
        cne_printf("[yellow]%-*s [yellow]+[]\n", col, COLUMN_SEPARATOR);

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
        prt_cnt(skip, col, stats.tx_ring_full, CYAN_TYPE);
        prt_cnt(skip, col, stats.tx_copied, CYAN_TYPE);

        prt_cnt(skip, col, stats.cq_empty, MAGENTA_TYPE);
        prt_cnt(skip, col, stats.cq_buf_freed, MAGENTA_TYPE);
    }

    p->ipackets = stats.ipackets;
    p->opackets = stats.opackets;
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

enum { DFLT_LINE, TICK_LINE, COL_LINE, HDR_LINE, DBG_LINE = 0x80, LINE_MASK = 0x7f };

struct stats_line {
    int type;
    const char *fmt;
    const char *msg;
} stat_lines[] = {
    {DFLT_LINE, "\n"},
    {TICK_LINE, "[cyan:-:italic]Running:  [yellow:-:bold]%c[]\n", ""},

    {COL_LINE, "[blue:-:bold]%-*s [yellow:-:-]|[]\n", "lport ID"},
    {COL_LINE, "[yellow]%-*s [yellow]+[]\n", "---------------"},
    {HDR_LINE, "[yellow:-:italic]RX [green:-:-]%-*s [yellow]|[]\n", "Pkts/s"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Total Pkts"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Total MBs"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Errors"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Missed"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Invalid"},
    {HDR_LINE, "[yellow:-:italic]TX [green:-:-]%-*s [yellow]|[]\n", "Pkts/s"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Total Pkts"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Total MBs"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Errors"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Dropped"},
    {COL_LINE, "[green]%-*s [yellow]|[]\n", "   Invalid"},

    {COL_LINE | DBG_LINE, "[magenta:-:italic]%-*s [yellow:-:-]+ []\n", "Debug Stats"},
    {HDR_LINE | DBG_LINE, "[yellow:-:italic]RX [green:-:-]%-*s [yellow]|[]\n", "Peek Fail"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Polls"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Buf Alloc"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Buf Freed"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Ring Empty"},

    {HDR_LINE | DBG_LINE, "[yellow:-:italic]FQ [green:-:-]%-*s [yellow]|[]\n", "Reserved"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Alloc Failed"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Buf Freed"},

    {HDR_LINE | DBG_LINE, "[yellow:-:italic]TX [green:-:-]%-*s [yellow]|[]\n", "Kicks"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Kicks Failed"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Ring Full"},
    {HDR_LINE | DBG_LINE, "[yellow:-:italic]CQ [green:-:-]%-*s [yellow]|[]\n", "Empty"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Peek Fail"},
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

        /* Skip the extra debug stats lines */
        if (!(fwd->flags & FWD_DEBUG_STATS) && (st->type & DBG_LINE))
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
            cne_printf(st->fmt, col - 3, st->msg);
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
    metrics_append(c, "\"name\":\"pktfwd\"");

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

    if (metrics_port_stats(c, lport->name, &stats) < 0)
        return -1;

    return 0;
}

static int
fwd_stats(metrics_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    struct fwd_info *fwd = (struct fwd_info *)(c->info->priv);
    return jcfg_lport_foreach(fwd->jinfo, handle_stats, c);
}

int
enable_metrics(struct fwd_info *finfo)
{
    print_stats_inited = 0;
    tick               = 0;
    if (metrics_init((void *)finfo) < 0)
        CNE_ERR_RET("metrics failed to initialize: %s\n", strerror(errno));

    if (metrics_register("/host", fwd_host) < 0)
        CNE_ERR_RET("Failed to register the metrics host\n");

    if (metrics_register("/app", fwd_app) < 0)
        CNE_ERR_RET("Failed to register the metrics app\n");

    if (metrics_register("/stats", fwd_stats) < 0)
        CNE_ERR_RET("Failed to register the metric stats\n");

    return 0;
}
