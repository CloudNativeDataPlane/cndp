/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdatomic.h>           // for atomic_load, atomic_exchange
#include <string.h>              // for memset, memcpy, strcmp, strncmp, strcpy, NULL
#include <sys/stat.h>            // for fchmod
#include <pcap/pcap.h>           // for pcap_close, pcap_compile, pcap_open_dead
#include <bsd/string.h>          // for strlcat
#include <inttypes.h>            // for PRIu64
#include <net/ethernet.h>        // for ETHER_CRC_LEN, ether_addr
#include <netinet/in.h>          // for in_addr, ntohl
#include <pcap/dlt.h>            // for DLT_EN10MB
#include <stdio.h>               // for fprintf, snprintf, fclose, fileno, fopen
#include <stdlib.h>              // for strtod
#include <unistd.h>              // for usleep
#include <endian.h>

#include "txgen.h"        // for txgen_packet_ctor, txgen, txgen_t, txgen_c...
#include "cmds.h"
#include "display.h"              // for display_resume, display_pause, ...
#include "cne_inet.h"             // for inet_ntop4
#include "_pcap.h"                // for pcap_info_t
#include "capture.h"              // for txgen_set_capture
#include "cli.h"                  // for cli_quit
#include "cne.h"                  // for copyright_msg, powered_by
#include "cne_common.h"           // for __cne_unused
#include <net/cne_ether.h>        // for inet_mtoa, CNE_ETHER_TYPE_IPV4
#include "cne_log.h"
#include "jcfg.h"                // for jcfg_lport_t, jcfg_info_t, jcfg_lport_foreach
#include "netdev_funcs.h"        // for netdev_link, ETH_LINK_FULL_DUPLEX
#include "pktdev_api.h"          // for pktdev_stats_get, pktdev_start, pktdev_stop
#include "pktmbuf.h"             // for DEFAULT_BURST_SIZE
#include "seq.h"                 // for pkt_seq_t

static char hash_line[] = "#######################################################################";

static int
_dump_lport(jcfg_info_t *j __cne_unused, void *obj, void *arg, int idx __cne_unused)
{
    jcfg_lport_t *lport = obj;
    uint64_t transmit_count;
    port_info_t *info;
    pkt_seq_t *pkt;
    char buff[64], *b;
    FILE *fd = arg;
    uint32_t flags;
    struct in_addr mask = {.s_addr = 0xFFFFFFFF}, ip_dst, ip_src;
    int pid;

    info = &txgen.info[lport->lpid];
    pkt  = &info->pkt;

    if (info->tx_burst == 0)
        return 0;

    pid = info->lport->lpid;

    fprintf(fd, "######################### Port %2d ##################################\n",
            lport->lpid);
    transmit_count = atomic_load(&info->transmit_count);
    if (transmit_count == 0)
        strcpy(buff, "Forever");
    else
        snprintf(buff, sizeof(buff), "%" PRIu64, transmit_count);
    fprintf(fd, "#\n");
    flags = atomic_load(&info->port_flags);
    fprintf(fd, "# Port: %2d, Burst:%3d, Rate:%g%%, Flags:%08x, TX Count:%s\n", pid, info->tx_burst,
            info->tx_rate, flags, buff);
    txgen_link_state(info->lport->lpid, buff, sizeof(buff));
    fprintf(fd, "# Link: %s\n", buff);

    fprintf(fd, "#\n# Set up the primary lport information:\n");
    fprintf(fd, "set %d count %" PRIu64 "\n", pid, transmit_count);
    fprintf(fd, "set %d size %d\n", pid, pkt->pktSize + ETHER_CRC_LEN);
    fprintf(fd, "set %d rate %g\n", pid, info->tx_rate);
    fprintf(fd, "set %d burst %d\n", pid, info->tx_burst);
    fprintf(fd, "set %d sport %d\n", pid, pkt->sport);
    fprintf(fd, "set %d dport %d\n", pid, pkt->dport);
    fprintf(fd, "set %d type %s\n", lport->lpid,
            (pkt->ethType == CNE_ETHER_TYPE_IPV4) ? "ipv4" : "unknown");
    fprintf(fd, "set %d proto %s\n", lport->lpid, (pkt->ipProto == IPPROTO_TCP) ? "tcp" : "udp");

    ip_dst.s_addr = be32toh(pkt->ip_dst_addr.s_addr);
    b             = inet_ntop4(buff, sizeof(buff), &ip_dst, &mask);
    fprintf(fd, "set %d dst ip %s\n", pid, (b) ? b : "InvalidIP");
    ip_dst.s_addr = be32toh(pkt->ip_src_addr.s_addr);
    b             = inet_ntop4(buff, sizeof(buff), &ip_src, (struct in_addr *)&pkt->ip_mask);
    fprintf(fd, "set %d src ip %s\n", pid, (b) ? b : "InvalidIP");
    fprintf(fd, "set %d dst mac %s\n", pid, inet_mtoa(buff, sizeof(buff), &pkt->eth_dst_addr));
    fprintf(fd, "set %d src mac %s\n", pid, inet_mtoa(buff, sizeof(buff), &pkt->eth_src_addr));

    fprintf(fd, "set %d pattern %s\n", lport->lpid,
            (info->fill_pattern_type == ABC_FILL_PATTERN)    ? "abc"
            : (info->fill_pattern_type == NO_FILL_PATTERN)   ? "none"
            : (info->fill_pattern_type == ZERO_FILL_PATTERN) ? "zero"
                                                             : "user");
    if ((info->fill_pattern_type == USER_FILL_PATTERN) && strlen(info->user_pattern)) {
        char buff[64];
        memset(buff, 0, sizeof(buff));
        snprintf(buff, sizeof(buff), "%s", info->user_pattern);
        fprintf(fd, "set %d user pattern %s\n", lport->lpid, buff);
    }
    fprintf(fd, "\n");

    fprintf(fd, "%sable %d capture\n", (flags & CAPTURE_PKTS) ? "en" : "dis", lport->lpid);
    return 0;
}

/**
 *
 * txgen_save - Save a configuration as a startup script
 *
 * DESCRIPTION
 * Save a configuration as a startup script
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static int
txgen_script_save(char *path)
{
    FILE *fd;

    fd = fopen(path, "w");
    if (fd == NULL)
        return -1;

    fprintf(fd, "#\n# %s\n", txgen_version());
    fprintf(fd, "# %s, %s\n", copyright_msg(), powered_by());

    fprintf(fd, "\n%s\n", hash_line);

    fprintf(fd, "# TXGen Configuration script information:\n");
    fprintf(fd, "#   Flags %08x\n", txgen.flags);
    fprintf(fd, "#   Promiscuous mode is %s\n\n",
            (txgen.flags & PROMISCUOUS_ON_FLAG) ? "Enabled" : "Disabled");

    jcfg_lport_foreach(txgen.jinfo, _dump_lport, (void *)fd);

    fprintf(fd, "################################ Done #################################\n");

    fchmod(fileno(fd), 0666);
    fclose(fd);
    return 0;
}

/**
 *
 * txgen_save - Save a configuration as a startup script
 *
 * DESCRIPTION
 * Save a configuration as a startup script
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
int
txgen_save(char *path)
{
    return txgen_script_save(path);
}

/**
 *
 * txgen_link_state - Get the ASCII string for the lport state.
 *
 * DESCRIPTION
 * Return the lport state string for a given lport.
 *
 * RETURNS: String pointer to link state
 *
 * SEE ALSO:
 */
char *
txgen_link_state(int lport, char *buff, int len)
{
    port_info_t *info = &txgen.info[lport];

    if (info->link.link_status)
        snprintf(buff, len, "<UP-%u-%s>", (uint32_t)info->link.link_speed,
                 (info->link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("FD") : ("HD"));
    else
        snprintf(buff, len, "<--Down-->");

    return buff;
}

/**
 *
 * txgen_transmit_count_rate - Get a string for the current transmit count and rate
 *
 * DESCRIPTION
 * Current value of the transmit count/%rate as a string.
 *
 * RETURNS: String pointer to transmit count/%rate.
 *
 * SEE ALSO:
 */
char *
txgen_transmit_count_rate(int lport, char *buff, int len)
{
    port_info_t *info = &txgen.info[lport];

    if (atomic_load(&info->transmit_count) == 0)
        snprintf(buff, len, "Forever /%g%%", info->tx_rate);
    else
        snprintf(buff, len, "%" PRIu64 " /%g%%", atomic_load(&info->transmit_count), info->tx_rate);

    return buff;
}

/**
 *
 * txgen_port_sizes - Current stats for all lport sizes
 *
 * DESCRIPTION
 * Structure returned with all of the counts for each lport size.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
int
txgen_port_sizes(int lport, port_sizes_t *psizes)
{
    port_info_t *info = &txgen.info[lport];

    *psizes = info->sizes;
    return 0;
}

/**
 *
 * txgen_pkt_stats - Get the packet stats structure.
 *
 * DESCRIPTION
 * Return the packet statistics values.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
int
txgen_pkt_stats(int lport, pkt_stats_t *pstats)
{
    port_info_t *info = &txgen.info[lport];

    *pstats = info->stats;
    return 0;
}

/**
 *
 * txgen_port_stats - Get the lport or rate stats for a given lport
 *
 * DESCRIPTION
 * Get the lports or rate stats from a given lport.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
int
txgen_port_stats(int lport, const char *name, eth_stats_t *pstats)
{
    port_info_t *info = &txgen.info[lport];

    if (strcmp(name, "lport") == 0)
        *pstats = info->prev_stats;
    else if (strcmp(name, "rate") == 0)
        *pstats = info->rate_stats;

    return 0;
}

/**
 *
 * txgen_flags_string - Return the flags string for display
 *
 * DESCRIPTION
 * Return the current flags string for display for a lport.
 *
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
char *
txgen_flags_string(port_info_t *info)
{
    static char buff[32];

    snprintf(buff, sizeof(buff), "%c:%s:%6s", (txgen.flags & PROMISCUOUS_ON_FLAG) ? 'P' : '-',
             (txgen_tst_port_flags(info, SEND_PCAP_PKTS)) ? "PCAP" : "-", "Single");

    return buff;
}

/**
 *
 * txgen_update_display - Update the display data and static data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_update_display(void)
{
    txgen.flags |= (PRINT_LABELS_FLAG | UPDATE_DISPLAY_FLAG);
}

/**
 *
 * txgen_clear_display - clear the screen.
 *
 * DESCRIPTION
 * clear the screen and redisplay data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_clear_display(void)
{
    if (!display_is_paused()) {
        display_pause();

        vt_cls();
        vt_pos(100, 1);

        txgen_update_display();

        display_resume();

        txgen_page_display();
    }
}

/**
 *
 * txgen_force_update - Force the screen to update data and static data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_force_update(void)
{
    txgen.flags |= UPDATE_DISPLAY_FLAG | PRINT_LABELS_FLAG;

    if (!display_is_paused())
        txgen_page_display();
}

/**
 *
 * txgen_screen - Enable or Disable screen updates.
 *
 * DESCRIPTION
 * Enable or disable screen updates.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
txgen_screen(int state)
{
    if (state == DISABLE_STATE) {
        if (!display_is_paused()) {
            display_pause();
            vt_cls();
            vt_setw(1);
            vt_pos(100, 1);
        }
    } else {
        vt_cls();
        vt_setw(txgen.last_row + 1);
        display_resume();
        vt_pos(100, 1);
        txgen_force_update();
    }
}

/**
 *
 * txgen_start_transmitting - Start a lport transmitting packets.
 *
 * DESCRIPTION
 * Start the given lports sending packets.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
txgen_start_transmitting(port_info_t *info)
{
    if (!txgen_tst_port_flags(info, SENDING_PACKETS)) {
        atomic_exchange(&info->current_tx_count, atomic_load(&info->transmit_count));

        if (atomic_load(&info->current_tx_count) == 0)
            txgen_set_port_flags(info, SEND_FOREVER);

        txgen_set_port_flags(info, (DO_TX_SETUP | SENDING_PACKETS));
    }
}

/**
 *
 * txgen_stop_transmitting - Stop lport transmitting packets.
 *
 * DESCRIPTION
 * Stop the given lports from sending traffic.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_stop_transmitting(port_info_t *info)
{
    if (txgen_tst_port_flags(info, SENDING_PACKETS)) {
        txgen_clr_port_flags(info, (SENDING_PACKETS | SEND_FOREVER));
    }
}

/**
 *
 * single_set_proto - Set up the protocol type for a lport/packet.
 *
 * DESCRIPTION
 * Setup all single packets with a protocol types with the lport list.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_proto(port_info_t *info, char *type)
{
    info->pkt.ipProto = (type[0] == 'u') ? IPPROTO_UDP : IPPROTO_TCP;

    /* ICMP only works on IPv4 packets. */
    if (type[0] == 'i')
        info->pkt.ethType = CNE_ETHER_TYPE_IPV4;

    txgen_packet_ctor(info);
}

/**
 *
 * single_set_pkt_type - Set the packet type value.
 *
 * DESCRIPTION
 * Set the packet type value for the given lport list.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_pkt_type(port_info_t *info, const char *type __cne_unused)
{
    pkt_seq_t *pkt = &info->pkt;

    pkt->ethType = CNE_ETHER_TYPE_IPV4;

    txgen_packet_ctor(info);
}

/**
 *
 * txgen_clear_stats - Clear a given lport list of stats.
 *
 * DESCRIPTION
 * Clear the given lport list of all statistics.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_clear_stats(port_info_t *info)
{
    int pid = info->lport->lpid;

    /* curr_stats are reset each time the stats are read */
    memset(&info->sizes, 0, sizeof(port_sizes_t));
    memset(&info->prev_stats, 0, sizeof(eth_stats_t));
    memset(&info->rate_stats, 0, sizeof(eth_stats_t));

    /* Normalize the stats to a zero base line */
    pktdev_stats_get(pid, &info->prev_stats);
    pktdev_stats_get(pid, &info->base_stats);

    txgen.max_total_ipackets = 0;
    txgen.max_total_opackets = 0;
    info->max_ipackets       = 0;
    info->max_opackets       = 0;
    info->stats.dropped_pkts = 0;
    info->stats.arp_pkts     = 0;
    info->stats.echo_pkts    = 0;
    info->stats.ip_pkts      = 0;
    info->stats.unknown_pkts = 0;
    info->stats.tx_failed    = 0;
    info->max_missed         = 0;

    memset(&txgen.cumm_rate_totals, 0, sizeof(eth_stats_t));
}

/**
 *
 * txgen_port_defaults - Set all lports back to the default values.
 *
 * DESCRIPTION
 * Reset the lports back to the defaults.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_port_defaults(uint32_t pid)
{
    port_info_t *info = &txgen.info[pid];
    pkt_seq_t *pkt    = &info->pkt;

    pkt->pktSize = MIN_PKT_SIZE;
    pkt->sport   = DEFAULT_SRC_PORT;
    pkt->dport   = DEFAULT_DST_PORT;
    pkt->ttl     = DEFAULT_TTL;
    pkt->ipProto = IPPROTO_TCP;
    pkt->ethType = CNE_ETHER_TYPE_IPV4;

    atomic_exchange(&info->transmit_count, DEFAULT_TX_COUNT);
    atomic_exchange(&info->current_tx_count, 0);
    info->tx_rate  = DEFAULT_TX_RATE;
    info->tx_burst = DEFAULT_BURST_SIZE;
    info->delta    = 0;

    pkt->ip_mask = DEFAULT_NETMASK;
    if ((pid & 1) == 0) {
        pkt->ip_src_addr.s_addr = DEFAULT_IP_ADDR | (pid << 8) | 1;
        pkt->ip_dst_addr.s_addr = DEFAULT_IP_ADDR | ((pid + 1) << 8) | 1;
    } else {
        pkt->ip_src_addr.s_addr = DEFAULT_IP_ADDR | (pid << 8) | 1;
        pkt->ip_dst_addr.s_addr = DEFAULT_IP_ADDR | ((pid - 1) << 8) | 1;
    }

    memset(&pkt->eth_dst_addr, 0, sizeof(pkt->eth_dst_addr));

    txgen_packet_ctor(info);

    txgen.flags |= PRINT_LABELS_FLAG;
}

/**
 *
 * txgen_reset - Reset all lports to the default state
 *
 * DESCRIPTION
 * Reset all lports to the default state.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_reset(port_info_t *info)
{
    char off[8];

    if (info == NULL)
        info = &txgen.info[0];

    strcpy(off, "off");
    txgen_stop_transmitting(info);

    info->pkt.pktSize = MIN_PKT_SIZE;

    txgen_port_defaults(info->lport->lpid);

    txgen_clear_stats(info);

    txgen_update_display();
}

/**
 *
 * txgen_port_restart - Reset all lports
 *
 * DESCRIPTION
 * Reset all lports
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_port_restart(port_info_t *info)
{
    if (info == NULL)
        info = &txgen.info[0];

    txgen_stop_transmitting(info);

    usleep(10 * 1000);

    /* Stop and start the device to flush TX and RX buffers from the device rings. */
    pktdev_stop(info->lport->lpid);

    usleep(250);

    pktdev_start(info->lport->lpid);

    txgen_update_display();
}

/**
 *
 * single_set_tx_count - Set the number of packets to transmit on a lport.
 *
 * DESCRIPTION
 * Set the transmit count for all lports in the list.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_tx_count(port_info_t *info, uint32_t cnt)
{
    atomic_exchange(&info->transmit_count, cnt);
}

/**
 *
 * single_set_tx_burst - Set the transmit burst count.
 *
 * DESCRIPTION
 * Set the transmit burst count for all packets.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_tx_burst(port_info_t *info, uint32_t burst)
{
    if (burst == 0)
        burst = 1;
    else if (burst > DEFAULT_BURST_SIZE)
        burst = DEFAULT_BURST_SIZE;
    info->tx_burst  = burst;
    info->tx_cycles = 0;

    txgen_packet_rate(info);
}

/**
 *
 * single_set_pkt_size - Set the size of the packets to send.
 *
 * DESCRIPTION
 * Set the pkt size for the single packet transmit.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_pkt_size(port_info_t *info, uint16_t size)
{
    pkt_seq_t *pkt = &info->pkt;

    if (size < ETHER_CRC_LEN)
        size = ETHER_CRC_LEN;

    if ((size - ETHER_CRC_LEN) < MIN_PKT_SIZE)
        size = MIN_PKT_SIZE;
    if ((size - ETHER_CRC_LEN) > MAX_PKT_SIZE)
        size = MAX_PKT_SIZE;

    pkt->pktSize = (size - ETHER_CRC_LEN);

    txgen_packet_ctor(info);
}

/**
 *
 * single_set_port_value - Set the lport value for single or sequence packets.
 *
 * DESCRIPTION
 * Set the lport value for single or sequence packets for the lports listed.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_port_value(port_info_t *info, char type, uint32_t portValue)
{
    if (type == 'd')
        info->pkt.dport = (uint16_t)portValue;
    else
        info->pkt.sport = (uint16_t)portValue;
    txgen_packet_ctor(info);
}

/**
 *
 * single_set_tx_rate - Set the transmit rate as a percent value.
 *
 * DESCRIPTION
 * Set the transmit rate as a percent value for all lports listed.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_tx_rate(port_info_t *info, const char *r)
{
    double rate = strtod(r, NULL);

    if (rate == 0)
        rate = 0.01;
    else if (rate > 100.00)
        rate = 100.00;
    info->tx_rate   = rate;
    info->tx_cycles = 0;

    txgen_packet_rate(info);
}

/**
 *
 * single_set_ipaddr - Set the IP address for all lports listed
 *
 * DESCRIPTION
 * Set an IP address for all lports listed in the call.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_ipaddr(port_info_t *info, char type, struct in_addr *ip, int prefixlen)
{
    if (type == 's') {
        info->pkt.ip_mask            = __size_to_mask(prefixlen);
        info->pkt.ip_src_addr.s_addr = ntohl(ip->s_addr);
    } else
        info->pkt.ip_dst_addr.s_addr = ntohl(ip->s_addr);

    txgen_packet_ctor(info);
}

/**
 *
 * single_set_mac - Setup the MAC address
 *
 * DESCRIPTION
 * Set the MAC address for all lports given.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_mac(port_info_t *info, const char *which, struct ether_addr *mac)
{
    if (!strcmp(which, "dst")) {
        memcpy(&info->pkt.eth_dst_addr, mac, 6);
        txgen_packet_ctor(info);
    } else if (!strcmp(which, "src")) {
        memcpy(&info->pkt.eth_src_addr, mac, 6);
        txgen_packet_ctor(info);
    }
}

/**
 *
 * single_set_dst_mac - Setup the destination MAC address
 *
 * DESCRIPTION
 * Set the destination MAC address for all lports given.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_dst_mac(port_info_t *info, struct ether_addr *mac)
{
    memcpy(&info->pkt.eth_dst_addr, mac, 6);
    txgen_packet_ctor(info);
}

/**
 *
 * single_set_src_mac - Setup the source MAC address
 *
 * DESCRIPTION
 * Set the source MAC address for all lports given.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_src_mac(port_info_t *info, struct ether_addr *mac)
{
    memcpy(&info->pkt.eth_src_addr, mac, 6);
    txgen_packet_ctor(info);
}

/**
 *
 * single_set_ttl_ttl - Setup the Time to Live
 *
 * DESCRIPTION
 * Set the TTL  for all lports given.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
single_set_ttl_value(port_info_t *info, uint8_t ttl)
{
    info->pkt.ttl = ttl;
    txgen_packet_ctor(info);
}

/**
 *
 * pattern_set_type - Set the pattern type per lport.
 *
 * DESCRIPTION
 * Set the given pattern type.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
pattern_set_type(port_info_t *info, char *str)
{
    if (strncmp(str, "abc", 3) == 0)
        info->fill_pattern_type = ABC_FILL_PATTERN;
    else if (strncmp(str, "none", 4) == 0)
        info->fill_pattern_type = NO_FILL_PATTERN;
    else if (strncmp(str, "user", 4) == 0)
        info->fill_pattern_type = USER_FILL_PATTERN;
    else if (strncmp(str, "zero", 4) == 0)
        info->fill_pattern_type = ZERO_FILL_PATTERN;
}

/**
 *
 * pattern_set_user_pattern - Set the user pattern string.
 *
 * DESCRIPTION
 * Set the given user pattern string.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
pattern_set_user_pattern(port_info_t *info, char *str)
{
    char copy[USER_PATTERN_SIZE + 1], *cp;

    memset(copy, 0, sizeof(copy));
    strlcpy(copy, str, USER_PATTERN_SIZE);
    cp = &copy[0];
    if (strnlen(cp, USER_PATTERN_SIZE) && ((cp[0] == '"') || (cp[0] == '\''))) {
        cp[strnlen(cp, USER_PATTERN_SIZE) - 1] = 0;
        cp++;
    }
    memset(info->user_pattern, 0, sizeof(info->user_pattern));
    strlcat(info->user_pattern, cp, sizeof(info->user_pattern));
    info->fill_pattern_type = USER_FILL_PATTERN;
}

#define _cp(s) (strcmp(str, s) == 0)

/**
 *
 * txgen_quit - Exit txgen.
 *
 * DESCRIPTION
 * Close and exit TXGen.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_quit(void)
{
    cli_set_quit_flag();
}

/**
 *
 * enable_pcap - Enable or disable PCAP sending of packets.
 *
 * DESCRIPTION
 * Enable or disable PCAP packet sending.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
enable_pcap(port_info_t *info, uint32_t state)
{
    if ((info->pcap != NULL) && (info->pcap->pkt_count != 0)) {
        if (state == ENABLE_STATE) {
            txgen_clr_port_flags(info, EXCLUSIVE_MODES);
            txgen_set_port_flags(info, SEND_PCAP_PKTS);
        } else
            txgen_clr_port_flags(info, SEND_PCAP_PKTS);
        info->tx_cycles = 0;
    }
}

/**
 *
 * pcap_filter - Compile a PCAP filter for a portlist
 *
 * DESCRIPTION
 * Compile a pcap filter for a portlist
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
pcap_filter(port_info_t *info, char *str)
{
    pcap_t *pc = pcap_open_dead(DLT_EN10MB, 65535);

    info->pcap_result = pcap_compile(pc, &info->pcap_program, str, 1, PCAP_NETMASK_UNKNOWN);

    pcap_close(pc);
}

/**
 *
 * enable_capture - Enable or disable capture packet processing.
 *
 * DESCRIPTION
 * Enable or disable capture packet processing of ICMP, ARP, ...
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
enable_capture(port_info_t *info, uint32_t state)
{
    txgen_set_capture(info, state);
}
