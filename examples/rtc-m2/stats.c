/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation.
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

    if (fwd->flags & FWD_DEBUG_STATS) {
        vt_cnright(skip);
        cne_printf("[yellow]%*s [yellow]+[]\n", col, COLUMN_SEPARATOR);

        prt_cnt(skip, col, stats.rx_ring_empty, CYAN_TYPE);
        prt_cnt(skip, col, stats.rx_buf_alloc, MAGENTA_TYPE);
        prt_cnt(skip, col, stats.rx_busypoll_wakeup, CYAN_TYPE);
        prt_cnt(skip, col, stats.rx_poll_wakeup, CYAN_TYPE);
        prt_cnt(skip, col, stats.rx_rcvd_count, CYAN_TYPE);
        prt_cnt(skip, col, stats.rx_burst_called, CYAN_TYPE);

        prt_cnt(skip, col, stats.fq_add_called, CYAN_TYPE);
        prt_cnt(skip, col, stats.fq_add_count, CYAN_TYPE);
        prt_cnt(skip, col, stats.fq_full, CYAN_TYPE);
        prt_cnt(skip, col, stats.fq_alloc_zero, CYAN_TYPE);
        prt_cnt(skip, col, stats.fq_reserve_failed, CYAN_TYPE);

        prt_cnt(skip, col, stats.tx_kicks, CYAN_TYPE);
        prt_cnt(skip, col, stats.tx_kick_failed, RED_TYPE);
        prt_cnt(skip, col, stats.tx_kick_again, RED_TYPE);
        prt_cnt(skip, col, p->tx_overrun, CYAN_TYPE);
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

    {COL_LINE | DBG_LINE, "[magenta:-:italic]%-*s [yellow:-:-]+ []\n", "Debug Stats"},
    {HDR_LINE | DBG_LINE, "[yellow:-:italic]%-*s [cyan:-:-]%-*s [yellow]|[]\n", "Ring Empty", "RX"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Buf Alloc"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Call Busypoll"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Call Poll"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Rcvd Count"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Burst Called"},

    {HDR_LINE | DBG_LINE, "[yellow:-:italic]%-*s [cyan:-:-]%-*s [yellow]|[]\n", "Called", "FQ"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Added"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Full"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Alloc Zero"},
    {COL_LINE | DBG_LINE, "[green]%-*s [yellow]|[]\n", "   Rsvd Failed"},

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
