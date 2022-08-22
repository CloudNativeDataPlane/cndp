/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdio.h>               // for snprintf, NULL
#include <pktdev.h>              // for PKTDEV_FOREACH
#include <pktdev_api.h>          // for pktdev_port_count, pktdev_stats_get
#include <inttypes.h>            // for PRIu64
#include <net/ethernet.h>        // for ETHER_CRC_LEN
#include <netinet/in.h>          // for htonl, in_addr
#include <stdint.h>              // for uint32_t
#include <string.h>              // for memset
#include <unistd.h>              // for usleep
#include <endian.h>

#include "cmds.h"                 // for txgen_flags_string, txgen_link_state, txge...
#include "display.h"              // for display_set_color, display_dashline
#include "txgen.h"                // for COLUMN_WIDTH_0, COLUMN_WIDTH_1, txgen, txg...
#include "cne_inet.h"             // for inet_ntop4
#include <net/cne_ether.h>        // for inet_mtoa
#include "cne_lport.h"            // for lport_stats_t
#include "cne_log.h"
#include "ether.h"               // for eth_stats_t
#include "jcfg.h"                // for jcfg_lport_t
#include "netdev_funcs.h"        // for netdev_link, netdev_get_link
#include "port-cfg.h"            // for port_info_t, port_sizes_t, ABC_FILL_PATTERN
#include "seq.h"                 // for pkt_seq_t
#include "stats.h"               // for pkt_stats_t, txgen_get_link_status, txgen_...

/**
 *
 * txgen_print_static_data - Display the static data on the screen.
 *
 * DESCRIPTION
 * Display a set of lport static data on the screen.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static void
txgen_print_static_data(void)
{
    port_info_t *info;
    pkt_seq_t *pkt;
    char buff[32], *b;
    uint32_t pid, ip_row;
    uint32_t col, row;
    struct in_addr mask = {.s_addr = 0xFFFFFFFF}, ip_dst, ip_src;

    display_set_color("default");
    display_set_color("top.page");
    display_topline("<Main Page>");

    display_set_color("top.lports");
    cne_printf_pos(1, 3, "Port Count %u", pktdev_port_count());

    row = PORT_STATE_ROW;
    display_set_color("stats.lport.label");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "  Flags:Port");

    /* Labels for dynamic fields (update every second) */
    display_set_color("stats.lport.linklbl");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Link State");

    display_set_color("stats.lport.ratelbl");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Pkts/s Max/Rx");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "       Max/Tx");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "MBits/s Rx/Tx");

    display_set_color("stats.lport.sizelbl");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Broadcast");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Multicast");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Sizes 64");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "      65-127");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "      128-255");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "      256-511");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "      512-1023");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "      1024-1518");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Runts/Jumbos");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "ARP/ICMP Pkts");
    display_set_color("stats.lport.errlbl");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Errors Rx/Tx");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Dropped Tx");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Invalid Rx/Tx");
    display_set_color("stats.lport.totlbl");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Total Rx Pkts");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "      Tx Pkts");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "      Rx MBs");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "      Tx MBs");

    ip_row = row;

    /* Labels for static fields */
    display_set_color("stats.stat.label");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Pattern Type");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Tx Count/% Rate");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Pkt Size/Tx Burst");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "TTL/Port Src/Dest");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Pkt Type");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "IP  Destination");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "    Source");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "MAC Destination");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "    Source");
    row++;

    /* Get the last location to use for the window starting row. */
    txgen.last_row = ++row;
    display_dashline(txgen.last_row);

    /* Display the colon after the row label. */
    display_set_color("stats.colon");
    for (row = PORT_STATE_ROW; row < (uint32_t)(txgen.last_row - 2); row++)
        cne_printf_pos(row, COLUMN_WIDTH_0 - 1, ":");

    for (pid = 0; txgen.info[pid].lport != NULL; pid++) {
        display_set_color("stats.stat.values");
        info = &txgen.info[pid];

        pkt = &info->pkt;

        /* Display Port information Src/Dest IP addr, Netmask, Src/Dst MAC addr */
        col = (COLUMN_WIDTH_1 * pid) + COLUMN_WIDTH_0;
        row = ip_row;

        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1,
                       (info->fill_pattern_type == ABC_FILL_PATTERN)    ? "abcd..."
                       : (info->fill_pattern_type == NO_FILL_PATTERN)   ? "None"
                       : (info->fill_pattern_type == ZERO_FILL_PATTERN) ? "Zero"
                                                                        : info->user_pattern);

        display_set_color("stats.rate.count");
        txgen_transmit_count_rate(pid, buff, sizeof(buff));
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        display_set_color("stats.stat.values");
        snprintf(buff, sizeof(buff), "%d /%5d", pkt->pktSize + ETHER_CRC_LEN, info->tx_burst);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);
        snprintf(buff, sizeof(buff), "%d/%5d/%5d", pkt->ttl, pkt->sport, pkt->dport);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);
        snprintf(buff, sizeof(buff), "%s / %s", "IPv4",
                 (pkt->ipProto == IPPROTO_TCP) ? "TCP" : "UDP");
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        display_set_color("stats.ip");
        memset(buff, 0, sizeof(buff));
        ip_dst.s_addr = be32toh(pkt->ip_dst_addr.s_addr);
        b             = inet_ntop4(buff, sizeof(buff), &ip_dst, &mask);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, (b) ? b : "InvalidIP");
        memset(buff, 0, sizeof(buff));
        ip_src.s_addr = be32toh(pkt->ip_src_addr.s_addr);
        b             = inet_ntop4(buff, sizeof(buff), &ip_src, (struct in_addr *)&pkt->ip_mask);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, (b) ? b : "InvalidIP");
        display_set_color("stats.mac");
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1,
                       inet_mtoa(buff, sizeof(buff), &pkt->eth_dst_addr));
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1,
                       inet_mtoa(buff, sizeof(buff), &pkt->eth_src_addr));
    }

    /* Display the string for total pkts/s rate of all lports */
    col = (COLUMN_WIDTH_1 * pid) + COLUMN_WIDTH_0;
    display_set_color("stats.total.label");
    cne_printf_pos(LINK_STATE_ROW, col, "%*s", COLUMN_WIDTH_3, "---Total Rate---");
    vt_eol();
    display_set_color(NULL);

    txgen.flags &= ~PRINT_LABELS_FLAG;
}

#define LINK_RETRY 8

/**
 *
 * txgen_get_link_status - Get the lport link status.
 *
 * DESCRIPTION
 * Try to get the link status of a lport. The <wait> flag if set tells the
 * routine to try and wait for the link status for 3 seconds. If the <wait> flag
 * is zero the try three times to get a link status if the link is not up.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_get_link_status(port_info_t *info, int wait)
{
    /* get link status */
    for (int i = 0; i < LINK_RETRY; i++) {
        netdev_get_link(info->lport->netdev, &info->link);

        if (info->link.link_status && info->link.link_speed) {
            txgen_packet_rate(info);
            break;
        }
        if (!wait)
            break;

        usleep(100 * 1000);
    }
}

/**
 *
 * txgen_page_stats - Display the statistics on the screen for all lports.
 *
 * DESCRIPTION
 * Display the lport statistics on the screen for all lports.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_page_stats(void)
{
    port_info_t *info;
    unsigned int col, row, total_ports;
    lport_stats_t *rate, *cumm, *prev;
    char buff[32];

    if (txgen.flags & PRINT_LABELS_FLAG)
        txgen_print_static_data();

    cumm = &txgen.cumm_rate_totals;
    memset(cumm, 0, sizeof(eth_stats_t));

    /* Calculate the total values */
    PKTDEV_FOREACH (pid) {
        info = &txgen.info[pid];

        rate = &info->rate_stats;

        cumm->ipackets += rate->ipackets;
        cumm->opackets += rate->opackets;
        cumm->ibytes += rate->ibytes;
        cumm->obytes += rate->obytes;
        cumm->ierrors += rate->ierrors;
        cumm->oerrors += rate->oerrors;
        cumm->odropped += rate->odropped;
        cumm->rx_invalid += rate->rx_invalid;
        cumm->tx_invalid += rate->tx_invalid;

        if (cumm->ipackets > txgen.max_total_ipackets)
            txgen.max_total_ipackets = cumm->ipackets;
        if (cumm->opackets > txgen.max_total_opackets)
            txgen.max_total_opackets = cumm->opackets;

        cumm->imissed += rate->imissed;
    }

    total_ports = 0;
    for (int pid = 0; txgen.info[pid].lport != NULL; pid++) {
        info = &txgen.info[pid];

        if (!info->link.link_status || !info->link.link_speed) {
            txgen_get_link_status(info, 0);
            if (info->link.link_status)
                txgen_packet_rate(info);
        }

        total_ports++;
        /* Display the disable string when lport is not enabled. */
        col = (COLUMN_WIDTH_1 * pid) + COLUMN_WIDTH_0;
        row = PORT_STATE_ROW;

        /* Display the lport number for the column */
        snprintf(buff, sizeof(buff), "%s:%d", txgen_flags_string(info), pid);
        display_set_color("stats.lport.flags");
        cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1, buff);
        display_set_color(NULL);

        row = LINK_STATE_ROW;

        /* Grab the link state of the lport and display Duplex/Speed and UP/Down */
        txgen_get_link_status(info, 0);

        txgen_link_state(pid, buff, sizeof(buff));
        display_set_color("stats.lport.status");
        cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1, buff);
        display_set_color(NULL);

        rate = &info->rate_stats;
        prev = &info->prev_stats;

        display_set_color("stats.lport.rate");

        /* Rx/Tx pkts/s rate */
        row = LINK_STATE_ROW + 1;
        snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, info->max_ipackets, rate->ipackets);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, info->max_opackets, rate->opackets);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, iBitsTotal(info->rate_stats) / Million,
                 oBitsTotal(info->rate_stats) / Million);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        /* Packets Sizes */
        row = PKT_SIZE_ROW;
        display_set_color("stats.lport.sizes");
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1, info->sizes.broadcast);
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1, info->sizes.multicast);
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1, info->sizes._64);
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1, info->sizes._65_127);
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1, info->sizes._128_255);
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1, info->sizes._256_511);
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1, info->sizes._512_1023);
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1, info->sizes._1024_1518);
        snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, info->sizes.runt, info->sizes.jumbo);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, info->stats.arp_pkts,
                 info->stats.echo_pkts);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        /* Rx/Tx Errors */
        row = PKT_TOTALS_ROW;
        display_set_color("stats.lport.errors");
        snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, prev->ierrors, prev->oerrors);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);
        snprintf(buff, sizeof(buff), "%" PRIu64, prev->odropped);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);
        snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, prev->rx_invalid, prev->tx_invalid);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        /* Total Rx/Tx */
        display_set_color("stats.lport.totals");
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1,
                       info->curr_stats.ipackets - info->base_stats.ipackets);
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1,
                       info->curr_stats.opackets - info->base_stats.opackets);

        /* Total Rx/Tx mbits */
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1,
                       (iBitsTotal(info->curr_stats) - iBitsTotal(info->base_stats)) / Million);
        cne_printf_pos(row++, col, "%*lu", COLUMN_WIDTH_1,
                       (oBitsTotal(info->curr_stats) - oBitsTotal(info->base_stats)) / Million);

        display_set_color(NULL);
    }

    display_set_color("stats.total.data");

    /* Display the total pkts/s for all lports */
    col = (COLUMN_WIDTH_1 * total_ports) + COLUMN_WIDTH_0;
    row = LINK_STATE_ROW + 1;
    snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, txgen.max_total_ipackets, cumm->ipackets);
    cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_3, buff);
    vt_eol();
    snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, txgen.max_total_opackets, cumm->opackets);
    cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_3, buff);
    vt_eol();
    snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64,
             iBitsTotal(txgen.cumm_rate_totals) / Million,
             oBitsTotal(txgen.cumm_rate_totals) / Million);
    cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_3, buff);
    vt_eol();
    display_set_color(NULL);
}

/**
 *
 * txgen_process_stats - Process statistics for all lports on timer1
 *
 * DESCRIPTION
 * When timer1 callback happens then process all of the lport statistics.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_process_stats(int pid)
{
    lport_stats_t *curr, *rate, *prev;
    port_info_t *info;

    info = &txgen.info[pid];

    curr = &info->curr_stats;
    if (pktdev_stats_get(pid, curr))
        return;

    rate = &info->rate_stats;
    prev = &info->prev_stats;

    rate->ipackets = curr->ipackets - prev->ipackets;
    rate->opackets = curr->opackets - prev->opackets;
    rate->ibytes   = curr->ibytes - prev->ibytes;
    rate->obytes   = curr->obytes - prev->obytes;
    rate->ierrors  = curr->ierrors - prev->ierrors;
    rate->oerrors  = curr->oerrors - prev->oerrors;
    rate->imissed  = curr->imissed - prev->imissed;

    /* Find the new max rate values */
    if (rate->ipackets > info->max_ipackets)
        info->max_ipackets = rate->ipackets;
    if (rate->opackets > info->max_opackets)
        info->max_opackets = rate->opackets;

    /* Use structure move to copy the data. */
    *prev = *curr;
}
