/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#include <pktmbuf.h>              // for DEFAULT_MBUF_SIZE, MBUF_INVALID_PORT
#include <net/cne_ether.h>        // for inet_mtoa, cne_ether_hdr, CNE_ETH...
#include <net/ethernet.h>         // for ETHERTYPE_IP, ETHERTYPE_IPV6
#include <netinet/in.h>           // for ntohs
#include <pthread.h>              // for pthread_mutex_lock, pthread_mutex...
#include <stdint.h>               // for uint16_t, uint32_t, uint8_t, uint...
#include <stdio.h>                // for snprintf, NULL
#include <string.h>               // for memcpy
#include <sys/types.h>            // for ssize_t

#include "txgen.h"          // for COLUMN_WIDTH_1, COLUMN_WIDTH_0
#include "display.h"        // for display_set_color, display_...
#include "pcap.h"
#include "cne_inet4.h"
#include "cne_inet.h"                     // for pkt_hdr_t, inet_ntop4, pkt_hdr_s:...
#include "_pcap.h"                        // for pcap_info_t, _pcap_read, _pcap_re...
#include "cne_branch_prediction.h"        // for unlikely
#include "cne_log.h"
#include "jcfg.h"               // for jcfg_lport_t
#include "net/cne_ip.h"         // for cne_ipv4_hdr
#include "net/cne_udp.h"        // for cne_udp_hdr
#include "pktdev_api.h"         // for pktdev_port_count
#include "port-cfg.h"           // for port_info_t, SEND_PCAP_PKTS
#include "net/cne_inet6.h"

#ifndef MBUF_INVALID_PORT
#define MBUF_INVALID_PORT UINT8_MAX
#endif

/**
 *
 * txgen_print_pcap - Display the pcap data page.
 *
 * DESCRIPTION
 * Display the pcap data page on the screen.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

static void
txgen_print_pcap(uint16_t pid)
{
    uint32_t i, row, col, max_pkts, len;
    uint16_t type, vlan, skip;
    uint8_t proto = 0;
    port_info_t *info;
    pkt_hdr_t *hdr;
    pcap_info_t *pcap;
    pcaprec_hdr_t pcap_hdr;
    char buff[64];
    char pkt_buff[DEFAULT_MBUF_SIZE];

    display_set_color("top.page");
    display_topline("<PCAP Page>");
    cne_printf_pos(1, 3, "Port Count %d", pktdev_port_count());

    info = &txgen.info[pid];
    pcap = info->pcap;

    row = PORT_STATE_ROW;
    col = 1;
    if (pcap == NULL) {
        cne_cprintf(10, tty_num_columns(), "** Port does not have a PCAP file assigned **");
        row = 28;
        goto leave;
    }

    display_set_color("stats.stat.label");
    vt_eol_pos(row, col);
    cne_printf_pos(row++, col, "Port: %d, PCAP Count: %d of %d", pid, pcap->pkt_idx,
                   pcap->pkt_count);
    cne_printf_pos(row++, col, "%*s %*s%*s%*s%*s%*s%*s%*s", 5, "Seq", COLUMN_WIDTH_0, "Dst MAC",
                   COLUMN_WIDTH_0, "Src MAC", COLUMN_WIDTH_0, "Dst IP", COLUMN_WIDTH_0 + 2,
                   "Src IP", 12, "Port S/D", 15, "Protocol:VLAN", 9, "Size-FCS");

    max_pkts = pcap->pkt_idx + PCAP_PAGE_SIZE;
    if (max_pkts > pcap->pkt_count)
        max_pkts = pcap->pkt_count;

    _pcap_skip(pcap, pcap->pkt_idx);

    display_set_color("stats.stat.values");
    for (i = pcap->pkt_idx; i < max_pkts; i++) {
        col  = 1;
        skip = 0;

        len = _pcap_read(pcap, &pcap_hdr, pkt_buff, sizeof(pkt_buff));
        if (len == 0)
            break;

        /* Skip any jumbo packets larger then buffer. */
        if (pcap_hdr.incl_len > sizeof(pkt_buff)) {
            i--;
            skip++;
        }
        /* Skip packets that are not normal IP packets. */
        type = ntohs(((uint16_t *)pkt_buff)[6]);
        if (unlikely(type == CNE_ETHER_TYPE_VLAN))
            type = ntohs(((uint16_t *)pkt_buff)[8]);

        if (unlikely(type < MAX_ETHER_TYPE_SIZE))
            skip++;

        hdr = (pkt_hdr_t *)&pkt_buff[0];

        vt_eol_pos(row, col);

        cne_printf_pos(row, col, "%5d:", i);
        col += 7;
        cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1,
                       inet_mtoa(buff, sizeof(buff), &hdr->eth.d_addr));
        col += COLUMN_WIDTH_1;
        cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1,
                       inet_mtoa(buff, sizeof(buff), &hdr->eth.s_addr));
        col += COLUMN_WIDTH_1;

        type  = ntohs(hdr->eth.ether_type);
        vlan  = 0;
        if (type == CNE_ETHER_TYPE_VLAN) {
            vlan  = ntohs(((uint16_t *)&hdr->eth.ether_type)[1]);
            type  = ntohs(((uint16_t *)&hdr->eth.ether_type)[2]);
#if CNET_ENABLE_IP6
            if (type == CNE_ETHER_TYPE_IPV6)
                /* Why offset 4, will it be different for ipv6 ? */
                proto = ((struct cne_ipv6_hdr *)((char *)&hdr->ipv6 + 4))->proto;
            else
#endif
                proto = ((struct cne_ipv4_hdr *)((char *)&hdr->ipv4 + 4))->next_proto_id;
        }

        if (type == CNE_ETHER_TYPE_IPV4) {
            struct in_addr mask = {.s_addr = 0xFFFFFFFF};
            char *b;

            proto = hdr->ipv4.next_proto_id;
            b = inet_ntop4(buff, sizeof(buff), (struct in_addr *)&hdr->ipv4.dst_addr, &mask);
            cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1, (b) ? b : "InvalidIP");
            col += COLUMN_WIDTH_1;
            b = inet_ntop4(buff, sizeof(buff), (struct in_addr *)&hdr->ipv4.src_addr, &mask);
            cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1 + 2, (b) ? b : "InvalidIP");
            col += COLUMN_WIDTH_1 + 2;

            snprintf(buff, sizeof(buff), "%d/%d", ntohs(hdr->uip.udp.src_port),
                     ntohs(hdr->uip.udp.dst_port));
            cne_printf_pos(row, col, "%*s", 12, buff);
            col += 12;
        }
#if CNET_ENABLE_IP6
        else if (type == CNE_ETHER_TYPE_IPV6) {
            struct in6_addr mask;
            char *b;

            proto = hdr->ipv6.proto;
            __size_to_mask6(128, &mask);
            b = inet_ntop6(buff, sizeof(buff), (struct in6_addr *)&hdr->ipv6.dst_addr, &mask);
            cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1, (b) ? b : "InvalidIP");
            col += COLUMN_WIDTH_1;
            b = inet_ntop6(buff, sizeof(buff), (struct in6_addr *)&hdr->ipv6.src_addr, &mask);
            cne_printf_pos(row, col, "%*s", COLUMN_WIDTH_1 + 2, (b) ? b : "InvalidIP");
            col += COLUMN_WIDTH_1 + 2;

            snprintf(buff, sizeof(buff), "%d/%d", ntohs(hdr->uip.udp.src_port),
                     ntohs(hdr->uip.udp.dst_port));
            cne_printf_pos(row, col, "%*s", 12, buff);
            col += 12;
        }
#endif
        else {
            skip++;
            col += ((2 * COLUMN_WIDTH_1) + 2 + 12);
        }
        snprintf(buff, sizeof(buff), "%s/%s:%4d",
                 (type == ETHERTYPE_IP)     ? "IPv4"
                 : (type == ETHERTYPE_IPV6) ? "IPv6"
                                            : "Other",
                 (type == IPPROTO_TCP)     ? "TCP"
                 : (proto == IPPROTO_ICMP) ? "ICMP"
                                           : "UDP",
                 (vlan & 0xFFF));
        cne_printf_pos(row, col, "%*s", 15, buff);
        col += 15;
        cne_printf_pos(row, col, "%5d", len);

        if (skip && (type < ETHERTYPE_IP))
            cne_printf_pos(row, col + 7, "<<< Skip %04x", type);
        else if (skip && (type != ETHERTYPE_IP))
            cne_printf_pos(row, col + 7, " EthType %04x", type);
        row++;
    }
leave:
    display_dashline(row + 2);
    display_set_color(NULL);

    txgen.flags &= ~PRINT_LABELS_FLAG;
}

void
txgen_page_pcap(port_info_t *info)
{
    jcfg_lport_t *lport = info->lport;

    if (txgen.flags & PRINT_LABELS_FLAG)
        txgen_print_pcap(lport->lpid);
}

void
txgen_pcap_mbuf_ctor(port_info_t *info, pktmbuf_t *m)
{
    pcaprec_hdr_t hdr;
    ssize_t len = -1;
    char buffer[DEFAULT_MBUF_SIZE];
    pcap_info_t *pcap = (pcap_info_t *)info->pcap;

    for (;;) {
        if (unlikely(_pcap_read(pcap, &hdr, buffer, sizeof(buffer)) <= 0)) {
            _pcap_rewind(pcap);
            continue;
        }

        len = hdr.incl_len;

        /* Adjust the packet length if not a valid size. */
        if (len < MIN_PKT_SIZE)
            len = MIN_PKT_SIZE;
        else if (len > MAX_PKT_SIZE)
            len = MAX_PKT_SIZE;

        m->data_len = len;
        memcpy(pktmbuf_mtod(m, uint8_t *), (uint8_t *)buffer, len);

        break;
    }
}

int
txgen_pcap_parse(pcap_info_t *pcap, port_info_t *info)
{
    pcaprec_hdr_t hdr;
    uint32_t elt_count, len, i;
    uint64_t pkt_sizes = 0;
    char buffer[DEFAULT_MBUF_SIZE];

    if ((pcap == NULL) || (info == NULL))
        return -1;

    _pcap_rewind(pcap); /* Rewind the file is needed */

    pkt_sizes = elt_count = i = 0;

    /* The pcap_open left the file pointer to the first packet. */
    while (_pcap_read(pcap, &hdr, buffer, sizeof(buffer)) > 0) {
        /* Skip any jumbo packets or packets that are too small */
        len = hdr.incl_len;

        if (len < (uint32_t)MIN_PKT_SIZE)
            len = MIN_PKT_SIZE;
        else if (len > (uint32_t)MAX_PKT_SIZE)
            len = MAX_PKT_SIZE;

        elt_count++;

        if ((elt_count & 0x3ff) == 0)
            cne_printf_pos(1, 1, "%c\b", "-\\|/"[i++ & 3]);

        pkt_sizes += len;
    }

    if (elt_count > 0) {
        if (pthread_mutex_lock(&info->port_lock))
            return -1;
        /* Create the average size packet */
        pcap->pkt_size  = (pkt_sizes / elt_count);
        pcap->pkt_count = elt_count;
        pcap->pkt_idx   = 0;
        _pcap_rewind(pcap);
        txgen_set_port_flags(info, SEND_PCAP_PKTS);
        if (pthread_mutex_unlock(&info->port_lock))
            return -1;
    }

    txgen_packet_rate(info);
    return 0;
}
