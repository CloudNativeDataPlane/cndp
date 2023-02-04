/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) <2016-2023>, Intel Corporation. All rights reserved.
 * Copyright (c) 2022 Red Hat, Inc.
 */

#include <stdio.h>

#include "txgen.h"
#include "display.h"        // for display_set_color, display_dashline
#include "cmds.h"           // for display_set_color, display_dashline
#include "latency.h"

/**
 *
 * txgen_print_latency - Display the static data on the screen.
 *
 * DESCRIPTION
 * Display a set of port static data on the screen.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
txgen_print_latency(void)
{
    port_info_t *info;
    uint32_t pid, col, row, ip_row;
    char buff[32], *b;
    pkt_seq_t *pkt;
    struct in_addr mask = {.s_addr = 0xFFFFFFFF}, ip_dst, ip_src;

    display_set_color("top.page");
    display_topline("<Latency Page>");

    display_set_color("top.ports");
    cne_printf_pos(1, 3, "Port Count %u", pktdev_port_count());

    row = PORT_STATE_ROW;
    display_set_color("stats.port.label");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "  Flags:Port");

    /* Labels for dynamic fields (update every second) */
    display_set_color("stats.dyn.label");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Link State");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Pkts/s Max/Rx");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "       Max/Tx");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "MBits/s Rx/Tx");

    row++;
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Lat avg/max");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Jitter Threshold");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Jitter count");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Total Rx pkts");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Jitter percent");

    /* Labels for static fields */
    display_set_color("stats.stat.label");
    ip_row = ++row;
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Pattern Type");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Tx Count/% Rate");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "PktSize/Rx:Tx Burst");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Src/Dest Port");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Pkt Type:VLAN ID");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Dst  IP Address");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Src  IP Address");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Dst MAC Address");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "Src MAC Address");
    cne_printf_pos(row++, 1, "%-*s", COLUMN_WIDTH_0, "VendID/PCI Addr");
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

        display_set_color("stats.stat.values");
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

    /* Display the string for total pkts/s rate of all ports */
    col = (COLUMN_WIDTH_1 * pid) + COLUMN_WIDTH_0;
    display_set_color("stats.total.label");
    cne_printf_pos(LINK_STATE_ROW, col, "%*s", COLUMN_WIDTH_3, "----TotalRate----");
    vt_eol();
    display_set_color(NULL);

    txgen.flags &= ~PRINT_LABELS_FLAG;
}

/**
 *
 * txgen_page_latency - Display the latency on the screen for all ports.
 *
 * DESCRIPTION
 * Display the port latency on the screen for all ports.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
txgen_page_latency(void)
{
    unsigned int col = 0, row = 0, total_ports;
    char buff[32];
    uint64_t avg_lat, ticks, max_lat;
    lport_stats_t *rate, *cumm;
    port_info_t *info;

    if (txgen.flags & PRINT_LABELS_FLAG)
        txgen_print_latency();

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
        /* Display the disable string when port is not enabled. */
        col = (COLUMN_WIDTH_1 * pid) + COLUMN_WIDTH_0;
        row = PORT_STATE_ROW;

        /* Display the port number for the column */
        snprintf(buff, sizeof(buff), "%s:%d", txgen_flags_string(info), pid);
        display_set_color("stats.lport.flags");
        cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1, buff);
        display_set_color(NULL);

        row = LINK_STATE_ROW;

        /* Grab the link state of the port and display Duplex/Speed and UP/Down */
        txgen_get_link_status(info, 0);

        txgen_link_state(pid, buff, sizeof(buff));
        display_set_color("stats.lport.status");
        cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1, buff);
        display_set_color(NULL);

        rate = &info->rate_stats;

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

        row++;

        ticks   = cne_get_timer_hz() / 1000000;
        avg_lat = 0;
        max_lat = 0;
        if (info->latency_nb_pkts) {
            avg_lat = (info->avg_latency / info->latency_nb_pkts) / ticks;
            if (avg_lat > info->max_avg_latency)
                info->max_avg_latency = avg_lat;
            if (info->min_avg_latency == 0)
                info->min_avg_latency = avg_lat;
            else if (avg_lat < info->min_avg_latency)
                info->min_avg_latency = avg_lat;
            max_lat               = info->max_latency / ticks;
            info->latency_nb_pkts = 0;
            info->avg_latency     = 0;
        }

        snprintf(buff, sizeof(buff), "%" PRIu64 "/%" PRIu64, avg_lat, max_lat);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        snprintf(buff, sizeof(buff), "%" PRIu64, info->jitter_threshold);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        snprintf(buff, sizeof(buff), "%" PRIu64, info->jitter_count);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        snprintf(buff, sizeof(buff), "%" PRIu64, info->prev_stats.ipackets);
        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        if (info->prev_stats.ipackets)
            snprintf(buff, sizeof(buff), "%" PRIu64,
                     (info->jitter_count * 100) / info->prev_stats.ipackets);
        else
            snprintf(buff, sizeof(buff), "%" PRIu64, avg_lat);

        cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_1, buff);

        display_set_color(NULL);
    }

    /* Display the total pkts/s for all ports */
    col = (COLUMN_WIDTH_1 * total_ports) + COLUMN_WIDTH_0;
    row = LINK_STATE_ROW + 1;
    snprintf(buff, sizeof(buff), "%lu/%lu", txgen.max_total_ipackets,
             txgen.cumm_rate_totals.ipackets);
    cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_3, buff);
    vt_eol();
    snprintf(buff, sizeof(buff), "%lu/%lu", txgen.max_total_opackets,
             txgen.cumm_rate_totals.opackets);
    cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_3, buff);
    vt_eol();
    snprintf(buff, sizeof(buff), "%lu/%lu", iBitsTotal(txgen.cumm_rate_totals) / Million,
             oBitsTotal(txgen.cumm_rate_totals) / Million);
    cne_printf_pos(row++, col, "%*s", COLUMN_WIDTH_3, buff);
    vt_eol();
    display_set_color(NULL);
}
