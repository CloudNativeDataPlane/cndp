/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdio.h>             // for snprintf, fflush, NULL, stdout
#include <stdlib.h>            // for atoi
#include <cne_common.h>        // for __cne_unused
#include <cne_log.h>           // for CNE_ERR_RET, CNE_LOG_ERR
#include <metrics.h>           // for metrics_append, metrics_params, metrics_regi...
#include <stdint.h>            // for uint64_t, uint16_t
#include <pktmbuf.h>           // IWYU pragma: keep

#include "dlb_test.h"          // for fwd_info, fwd_port, enable_m...
#include "cne_lport.h"         // for lport_stats_t
#include "jcfg.h"              // for jcfg_lport_foreach, jcfg_lport_t
#include "pktdev_api.h"        // for pktdev_stats_get

extern struct fwd_info *fwd;
static uint64_t tick, print_stats_inited;

#define COLUMN_WIDTH 12

void
print_dlb_stats(void)
{
    char buff[64];
    int skip, col, i;

    cne_printf("\n");

    col  = COLUMN_WIDTH;
    skip = (col + 2);

    vt_pos(18, 0);
    cne_printf("[green]DLB Stats: [blue]%ld[]\n", tick++);
    cne_printf("%*s [yellow]|", col, "");
    cne_printf("[green] Enq (mil/s) [yellow]|");
    cne_printf("[green] Deq (mil/s) [yellow]|\n");

    cne_printf("[yellow]%*s [yellow]|", col, "");
    cne_printf("[yellow]%*s [yellow]|", col, "-----------");
    cne_printf("[yellow]%*s [yellow]| \n", col, "-----------");

    cne_printf("[green]%-*s [yellow]|[]\n", col, "Producer");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "Consumer");
    for (i = 0; i < num_workers; i++)
        cne_printf("[green]%-*s %2d [yellow]|[]\n", col - 3, "Worker", i);

    vt_cup(2 + num_workers);
    vt_cnright(skip);

    snprintf(buff, sizeof(buff), "%f",
             (prod_args.curr_evt_stats.enq - prod_args.prev_evt_stats.enq) / 1000000.0);
    cne_printf("[magenta]%*s [yellow]|", col, buff);
    cne_printf("[magenta]%*s [yellow]|\n", col, " ");
    prod_args.prev_evt_stats.enq = prod_args.curr_evt_stats.enq;

    vt_cnright(skip);
    cne_printf("[magenta]%*s [yellow]|", col, " ");
    snprintf(buff, sizeof(buff), "%f",
             (cons_args.curr_evt_stats.deq - cons_args.prev_evt_stats.deq) / 1000000.0);
    cne_printf("[magenta]%*s [yellow]|\n", col, buff);

    cons_args.prev_evt_stats.deq = cons_args.curr_evt_stats.deq;

    for (i = 0; i < num_workers; i++) {
        vt_cnright(skip);
        snprintf(buff, sizeof(buff), "%f",
                 (work_args[i].curr_evt_stats.enq - work_args[i].prev_evt_stats.enq) / 1000000.0);
        cne_printf("[magenta]%*s [yellow]|", col, buff);
        work_args[i].prev_evt_stats.enq = work_args[i].curr_evt_stats.enq;

        snprintf(buff, sizeof(buff), "%f",
                 (work_args[i].curr_evt_stats.deq - work_args[i].prev_evt_stats.deq) / 1000000.0);
        cne_printf("[magenta]%*s [yellow]|\n", col, buff);
        work_args[i].prev_evt_stats.deq = work_args[i].curr_evt_stats.deq;
    }
    vt_restore();
}

static void
print_port_stats(int lport_id, struct fwd_port *p)
{
    lport_stats_t stats = {0};
    char buff[64];
    uint64_t rx_pps, tx_pps;
    int skip, col;

    vt_restore();
    cne_printf("\n\n");

    col  = COLUMN_WIDTH;
    skip = (lport_id + 1) * (col + 2);
    vt_cnright(skip);

    cne_printf("[blue]%*d[] [yellow]|[]\n", col, lport_id);

    pktdev_stats_get(p->lport, &stats);

    rx_pps = (stats.ipackets - p->ipackets) / 1024;
    tx_pps = (stats.opackets - p->opackets) / 1024;

    vt_cnright(skip);
    cne_printf("[yellow]%*s [yellow]+\n", col, " -------------");

    snprintf(buff, sizeof(buff), "%lu/%lu", stats.ipackets / 1024, rx_pps);
    vt_cnright(skip);
    cne_printf("[magenta]%*s [yellow]|\n", col, buff);
    snprintf(buff, sizeof(buff), "%lu/%lu", stats.opackets / 1024, tx_pps);
    vt_cnright(skip);
    cne_printf("[magenta]%*s [yellow]|\n", col, buff);

    snprintf(buff, sizeof(buff), "%lu", stats.ibytes / (1024 * 1024));
    vt_cnright(skip);
    cne_printf("[yellow]%*s [yellow]|\n", col, buff);
    snprintf(buff, sizeof(buff), "%lu", stats.obytes / (1024 * 1024));
    vt_cnright(skip);
    cne_printf("[yellow]%*s [yellow]|\n", col, buff);

    snprintf(buff, sizeof(buff), "%lu", stats.ierrors);
    vt_cnright(skip);
    cne_printf("[red]%*s [yellow]|\n", col, buff);
    snprintf(buff, sizeof(buff), "%lu", stats.oerrors);
    vt_cnright(skip);
    cne_printf("[red]%*s [yellow]|\n", col, buff);

    snprintf(buff, sizeof(buff), "%lu", stats.imissed);
    vt_cnright(skip);
    cne_printf("[red]%*s [yellow]|\n", col, buff);
    snprintf(buff, sizeof(buff), "%lu", stats.odropped);
    vt_cnright(skip);
    cne_printf("[cyan]%*s [yellow]|\n", col, buff);

    snprintf(buff, sizeof(buff), "%lu", stats.rx_invalid);
    vt_cnright(skip);
    cne_printf("[red]%*s [yellow]|\n", col, buff);
    snprintf(buff, sizeof(buff), "%lu", stats.tx_invalid);
    vt_cnright(skip);
    cne_printf("[red]%*s [yellow]|[]\n", col, buff);

    p->ipackets = stats.ipackets;
    p->opackets = stats.opackets;
}

static int
_print_stats(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_lport_t *lport = obj;
    struct fwd_port *pd = lport->priv_;

    print_port_stats(lport->lpid, pd);

    return 0;
}

static void
print_stats_init(void)
{
    print_stats_inited = 1;

    vt_make_space(12);
}

void
print_port_stats_all(void)
{
    int col = COLUMN_WIDTH;

    if (!print_stats_inited)
        print_stats_init();

    vt_cls();
    vt_pos(2, 0);
    vt_save();
    cne_printf("\n[green]LPort Stats: [blue]%ld[]\n", tick);

    cne_printf("[green]%-*s [yellow]|[]\n", col, "lport ID");
    cne_printf("[yellow]%-*s [yellow]+[]\n", col, "--------------");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "Rx KPkts/Kpps");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "TX KPkts/Kpps");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "RX MBytes");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "TX MBytes");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "Rx Errors");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "Tx Errors");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "Rx Missed");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "Tx Dropped");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "Rx Invalid");
    cne_printf("[green]%-*s [yellow]|[]\n", col, "Tx Invalid");

    cne_printf("[]\n");

    jcfg_lport_foreach(fwd->jinfo, _print_stats, fwd);

    fflush(stdout);
    vt_restore();
}
