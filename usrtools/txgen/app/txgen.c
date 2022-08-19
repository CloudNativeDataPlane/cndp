/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdint.h>            // for uint64_t, uint8_t, uint16_t, uint...
#include <sched.h>             // for cpu_set_t
#include <cne_system.h>        // for cne_get_timer_hz
#include <cne_cycles.h>        // for cne_rdtsc
#include <cne_pause.h>         // for cne_pause
#include <netinet/in.h>        // for in_addr, IPPROTO_UDP, ntohs
#include <pthread.h>           // for pthread_mutex_lock, pthread_mutex...
#include <string.h>            // for memset, memcpy

#include "txgen.h"
#include "tcp.h"             // for txgen_tcp_hdr_ctor
#include "ipv4.h"            // for txgen_ipv4_ctor
#include "udp.h"             // for txgen_udp_hdr_ctor
#include "display.h"         // for display_set_color
#include "port-cfg.h"        // for port_info_t, port_sizes_t, mbuf_t...
#include "pcap.h"            // for txgen_page_pcap, txgen_pcap_mbuf_...
#include "cmds.h"            // for txgen_force_update
#include "cne_inet.h"
#include "_pcap.h"                        // for pcap_info_t
#include "cne_branch_prediction.h"        // for unlikely, likely
#include "cne_common.h"                   // for __cne_unused
#include <net/cne_ether.h>                // for CNE_ETHER_TYPE_IPV4, cne_ether_hdr
#include "cne_prefetch.h"                 // for cne_prefetch0
#include "cne_log.h"
#include "jcfg.h"                // for jcfg_lport_t, jcfg_thd_t, jcfg_lg...
#include "netdev_funcs.h"        // for netdev_get_mac_addr, netdev_link
#include "pktdev.h"              // for pktdev_rx_burst, pktdev_tx_burst
#include "pktdev_api.h"          // for pktdev_buf_alloc, pktdev_close
#include "pktmbuf.h"             // for DEFAULT_BURST_SIZE, pktmbuf_mtod
#include "seq.h"                 // for pkt_seq_t
#include "stats.h"               // for pkt_stats_t, txgen_page_stats

/* Allocated the txgen structure for global use */
txgen_t txgen;

enum { UNKNOWN_TYPE_THREAD, RXTX_TYPE_THREAD, RX_TYPE_THREAD, TX_TYPE_THREAD };

static int
txgen_thread_type(char *name)
{
    if (!strcasecmp("rxtx", name))
        return RXTX_TYPE_THREAD;
    else if (!strcasecmp("rx_only", name))
        return RX_TYPE_THREAD;
    else if (!strcasecmp("tx_only", name))
        return TX_TYPE_THREAD;
    return UNKNOWN_TYPE_THREAD;
}

/**
 *
 * txgen_wire_size - Calculate the wire size of the data to be sent.
 *
 * DESCRIPTION
 * Calculate the number of bytes/bits in a burst of traffic.
 *
 * RETURNS: Number of bytes in a burst of packets.
 *
 * SEE ALSO:
 */
uint64_t
txgen_wire_size(port_info_t *info)
{
    uint64_t size = 0;

    if (txgen_tst_port_flags(info, SEND_PCAP_PKTS))
        size = info->pcap->pkt_size + PKT_OVERHEAD_SIZE;
    else
        size = info->pkt.pktSize + PKT_OVERHEAD_SIZE;

    return size;
}

/**
 *
 * txgen_packet_rate - Calculate the transmit rate.
 *
 * DESCRIPTION
 * Calculate the number of cycles to wait between sending bursts of traffic.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_packet_rate(port_info_t *info)
{
    uint64_t wire_size = (txgen_wire_size(info) * 8);
    uint64_t lk        = (uint64_t)info->link.link_speed * Million;
    uint64_t pps       = ((lk / wire_size) * info->tx_rate) / 100;
    uint64_t cpp       = (pps > 0) ? (txgen.hz / pps) : txgen.hz;

    info->tx_pps    = pps;
    info->tx_cycles = (cpp * info->tx_burst);
}

/**
 *
 * txgen_fill_pattern - Create the fill pattern in a packet buffer.
 *
 * DESCRIPTION
 * Create a fill pattern based on the arguments for the packet data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static __inline__ void
txgen_fill_pattern(uint8_t *p, uint32_t len, uint32_t type, char *user)
{
    uint32_t i;

    switch (type) {
    case USER_FILL_PATTERN:
        memset(p, 0, len);
        for (i = 0; i < len; i++)
            p[i] = user[i & (USER_PATTERN_SIZE - 1)];
        break;

    case NO_FILL_PATTERN:
        break;

    case ZERO_FILL_PATTERN:
        memset(p, 0, len);
        break;

    default:
    case ABC_FILL_PATTERN: /* Byte wide ASCII pattern */
        for (i = 0; i < len; i++)
            p[i] = "abcdefghijklmnopqrstuvwxyz012345"[i & 0x1f];
        break;
    }
}

/**
 *
 * txgen_send_burst - Send a burst of packet as fast as possible.
 *
 * DESCRIPTION
 * Transmit a burst of packets to a given lport.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static __inline__ void
txgen_send_burst(port_info_t *info)
{
    jcfg_lport_t *lport     = info->lport;
    struct mbuf_table *mtab = &info->tx_mbufs;
    pktmbuf_t **pkts;
    uint32_t ret, cnt;

    if ((cnt = mtab->len) == 0)
        return;

    mtab->len = 0;
    pkts      = mtab->m_table;

    /* Send all of the packets before we can exit this function */
    while (cnt && txgen_tst_port_flags(info, SENDING_PACKETS)) {
        ret = pktdev_tx_burst(lport->lpid, pkts, cnt);
        if (ret == PKTDEV_ADMIN_STATE_DOWN)
            return;
        pkts += ret;
        cnt -= ret;
    }
}

/**
 *
 * txgen_tx_flush - Flush Tx buffers from ring.
 *
 * DESCRIPTION
 * Flush TX buffers from ring.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static __inline__ void
txgen_tx_flush(port_info_t *info)
{
    /* Flush any queued pkts to the driver. */
    txgen_send_burst(info);

    txgen_clr_port_flags(info, DO_TX_FLUSH);
}

/**
 *
 * txgen_packet_ctor - Construct a complete packet with all headers and data.
 *
 * DESCRIPTION
 * Construct a packet type based on the arguments passed with all headers.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_packet_ctor(port_info_t *info)
{
    pkt_seq_t *pkt            = &info->pkt;
    struct cne_ether_hdr *eth = (struct cne_ether_hdr *)&pkt->hdr.eth;
    char *l3_hdr              = (char *)&eth[1]; /* Point to l3 hdr location for GRE header */

    /* Fill in the pattern for data space. */
    txgen_fill_pattern((uint8_t *)&pkt->hdr, (sizeof(pkt_hdr_t) + sizeof(pkt->pad)),
                       info->fill_pattern_type, info->user_pattern);

    l3_hdr = txgen_ether_hdr_ctor(info, pkt, eth);

    if (likely(pkt->ethType == CNE_ETHER_TYPE_IPV4)) {
        if (likely(pkt->ipProto == IPPROTO_TCP)) {
            /* Construct the TCP header */
            txgen_tcp_hdr_ctor(pkt, l3_hdr, CNE_ETHER_TYPE_IPV4);

            /* IPv4 Header constructor */
            txgen_ipv4_ctor(pkt, l3_hdr);
        } else if (pkt->ipProto == IPPROTO_UDP) {
            /* Construct the UDP header */
            txgen_udp_hdr_ctor(pkt, l3_hdr, CNE_ETHER_TYPE_IPV4);

            /* IPv4 Header constructor */
            txgen_ipv4_ctor(pkt, l3_hdr);
        }
    } else
        cne_printf("Unknown EtherType 0x%04x", pkt->ethType);
}

/**
 *
 * txgen_packet_type - Examine a packet and return the type of packet
 *
 * DESCRIPTION
 * Examine a packet and return the type of packet.
 * the packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static __inline__ uint16_t
txgen_packet_type(pktmbuf_t *m)
{
    uint16_t ret;
    struct cne_ether_hdr *eth;

    eth = pktmbuf_mtod(m, struct cne_ether_hdr *);

    ret = ntohs(eth->ether_type);

    return ret;
}

/**
 *
 * txgen_packet_classify - Examine a packet and classify it for statistics
 *
 * DESCRIPTION
 * Examine a packet and determine its type along with counting statistics around
 * the packet.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static void
txgen_packet_classify(pktmbuf_t *m, int pid)
{
    port_info_t *info = &txgen.info[pid];
    uint32_t plen;
    uint16_t pType;

    pType = txgen_packet_type(m);

    plen = pktmbuf_data_len(m);

    /* Count the type of packets found. */
    switch ((int)pType) {
    case CNE_ETHER_TYPE_ARP:
        info->stats.arp_pkts++;
        break;
    case CNE_ETHER_TYPE_IPV4:
        info->stats.ip_pkts++;
        break;
    case CNE_ETHER_TYPE_IPV6:
        info->stats.ipv6_pkts++;
        break;
    case CNE_ETHER_TYPE_VLAN:
        info->stats.vlan_pkts++;
        break;
    default:
        break;
    }

    /* account for the CRC being stripped or not included */
    plen += ETHER_CRC_LEN;

    /* Count the size of each packet. */
    if (plen == ETHER_MIN_LEN)
        info->sizes._64++;
    else if ((plen >= (ETHER_MIN_LEN + 1)) && (plen <= 127))
        info->sizes._65_127++;
    else if ((plen >= 128) && (plen <= 255))
        info->sizes._128_255++;
    else if ((plen >= 256) && (plen <= 511))
        info->sizes._256_511++;
    else if ((plen >= 512) && (plen <= 1023))
        info->sizes._512_1023++;
    else if ((plen >= 1024) && (plen <= ETHER_MAX_LEN))
        info->sizes._1024_1518++;
    else if (plen < ETHER_MIN_LEN)
        info->sizes.runt++;
    else if (plen > ETHER_MAX_LEN)
        info->sizes.jumbo++;
    else
        info->sizes.unknown++;

    /* Process multicast and broadcast packets. */
    if (unlikely(((uint8_t *)m->buf_addr + m->data_off)[0] == 0xFF)) {
        if ((((uint64_t *)m->buf_addr + m->data_off)[0] & 0xFFFFFFFFFFFF0000LL) ==
            0xFFFFFFFFFFFF0000LL)
            info->sizes.broadcast++;
        else if (((uint8_t *)m->buf_addr + m->data_off)[0] & 1)
            info->sizes.multicast++;
    }
}

/**
 *
 * txgen_packet_classify_bulk - Classify a set of packets in one call.
 *
 * DESCRIPTION
 * Classify a list of packets and to improve classify performance.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
#define PREFETCH_OFFSET 3
static __inline__ void
txgen_packet_classify_bulk(pktmbuf_t **pkts, int nb_rx, int pid)
{
    int j, i;

    /* Prefetch first packets */
    for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
        cne_prefetch0(pktmbuf_mtod(pkts[j], void *));

    /* Prefetch and handle already prefetched packets */
    for (i = 0; i < (nb_rx - PREFETCH_OFFSET); i++) {
        cne_prefetch0(pktmbuf_mtod(pkts[j], void *));
        j++;

        txgen_packet_classify(pkts[i], pid);
    }

    /* Handle remaining prefetched packets */
    for (; i < nb_rx; i++)
        txgen_packet_classify(pkts[i], pid);
}

typedef struct {
    port_info_t *info;
} pkt_data_t;

/**
 *
 * txgen_setup_packets - Setup the default packets to be sent.
 *
 * DESCRIPTION
 * Construct the default set of packets for a given lport.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static __inline__ void
txgen_setup_packets(port_info_t *info)
{
    txgen_clr_port_flags(info, DO_TX_SETUP);

    if (pthread_mutex_lock(&info->port_lock))
        cne_printf("*** Failed to lock port\n");

    txgen_packet_ctor(info);

    if (pthread_mutex_unlock(&info->port_lock))
        cne_printf("*** Failed to unlock port\n");
}

/**
 *
 * txgen_send_pkts - Send a set of packet buffers to a given lport.
 *
 * DESCRIPTION
 * Transmit a set of packets mbufs to a given lport.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static __inline__ void
txgen_send_pkts(port_info_t *info)
{
    uint64_t txCnt;
    uint16_t txLen, cnt;
    pktmbuf_t **pkts;

    if (!txgen_tst_port_flags(info, SEND_FOREVER)) {
        txCnt = pkt_atomic64_tx_count(&info->current_tx_count, info->tx_burst);

        if (txCnt == 0) {
            txgen_clr_port_flags(info, (SENDING_PACKETS | SEND_FOREVER));
            txgen_send_burst(info);
            return;
        }
    } else
        txCnt = info->tx_burst;

    txLen = info->tx_mbufs.len;
    pkts  = &info->tx_mbufs.m_table[txLen];
    cnt   = txCnt - txLen;

    if (cnt > info->tx_burst)
        cnt = info->tx_burst;

    int nb = pktdev_buf_alloc(info->lport->lpid, pkts, cnt);
    for (int i = 0; i < nb; i++) {
        pktmbuf_t *xb = info->tx_mbufs.m_table[i];

        if (txgen_tst_port_flags(info, SEND_PCAP_PKTS)) {
            txgen_pcap_mbuf_ctor(info, xb);
        } else {
            xb->data_len = info->pkt.pktSize;
            memcpy(pktmbuf_mtod(xb, uint8_t *), (uint8_t *)&info->pkt.hdr, xb->data_len);
        }
    }
    info->tx_mbufs.len += nb;

    txgen_send_burst(info);
}

/**
 *
 * txgen_main_transmit - Determine the next packet format to transmit.
 *
 * DESCRIPTION
 * Determine the next packet format to transmit for a given lport.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static void
txgen_main_transmit(port_info_t *info)
{
    uint32_t flags;

    flags = atomic_load(&(info->port_flags)) & SENDING_PACKETS;

    /* When not transmitting on this lport then continue. */
    if (flags) {

        if (txgen_tst_port_flags(info, DO_TX_SETUP))
            txgen_setup_packets(info);

        txgen_send_pkts(info);
    }

    if (txgen_tst_port_flags(info, DO_TX_FLUSH))
        txgen_tx_flush(info);
}

/**
 *
 * txgen_main_receive - Main receive routine for packets of a lport.
 *
 * DESCRIPTION
 * Handle the main receive set of packets on a given lport plus handle all of the
 * input processing if required.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static __inline__ void
txgen_main_receive(port_info_t *info __cne_unused, pktmbuf_t *pkts_burst[], uint16_t nb_pkts)
{
    jcfg_lport_t *lport = info->lport;
    uint16_t nb_rx;
    capture_t *capture;
    uint16_t pid;

    pid = lport->lpid;

    /*
     * Read packet from RX queues and free the mbufs
     */
    nb_rx = pktdev_rx_burst(lport->lpid, pkts_burst, nb_pkts);
    if ((nb_rx == 0) || (nb_rx == PKTDEV_ADMIN_STATE_DOWN))
        return;

    /* packets are not freed in the next call. */
    txgen_packet_classify_bulk(pkts_burst, nb_rx, lport->lpid);

    if (unlikely(txgen_tst_port_flags(info, CAPTURE_PKTS))) {
        capture = &txgen.captures[pid];
        if (unlikely((capture->port == pid)))
            txgen_packet_capture_bulk(pkts_burst, nb_rx, capture);
    }

    pktmbuf_free_bulk(pkts_burst, nb_rx);
}

/**
 *
 * txgen_main_rxtx_loop - Single thread loop for tx/rx packets
 *
 * DESCRIPTION
 * Handle sending and receiving packets from a given set of lports. This is the
 * main loop or thread started on a single core.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static void
txgen_rxtx(port_info_t *info)
{
    pktmbuf_t *pkts_burst[DEFAULT_BURST_SIZE];
    uint64_t curr_tsc;

    if (!info->link.link_status)
        return;

    txgen_main_receive(info, pkts_burst, DEFAULT_BURST_SIZE);

    curr_tsc = cne_rdtsc();

    /* Determine when is the next time to send packets */
    if (info->tx_next_cycle == 0 || curr_tsc >= info->tx_next_cycle) {
        uint32_t val;

        info->tx_next_cycle = curr_tsc + info->tx_cycles;

        val = atomic_load(&info->port_flags);
        if (val & SENDING_PACKETS)
            txgen_main_transmit(info);
    }
}

/**
 *
 * txgen_main_tx_loop - Main transmit loop for a core, no receive packet handling
 *
 * DESCRIPTION
 * When Tx and Rx are split across two cores this routing handles the tx packets.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static void
txgen_tx(port_info_t *info)
{
    uint64_t curr_tsc;

    if (!info->link.link_status)
        return;

    curr_tsc = cne_rdtsc();

    /* Determine when is the next time to send packets */
    if (info->tx_next_cycle == 0 || curr_tsc >= info->tx_next_cycle) {
        info->tx_next_cycle = curr_tsc + info->tx_cycles;

        if (atomic_load(&info->port_flags) & SENDING_PACKETS)
            txgen_main_transmit(info);
    }
}

/**
 *
 * txgen_main_rx_loop - Handle only the rx packets for a set of lports.
 *
 * DESCRIPTION
 * When Tx and Rx processing is split between two lports this routine handles
 * only the receive packets.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static void
txgen_rx(port_info_t *info)
{
    pktmbuf_t *pkts_burst[DEFAULT_BURST_SIZE];

    txgen_main_receive(info, pkts_burst, DEFAULT_BURST_SIZE);
}

static int
init_port_info(port_info_t *info, jcfg_lport_t *lport)
{
    if (!info || !lport)
        return -1;

    if (netdev_get_mac_addr(lport->netdev, &info->pkt.eth_src_addr) < 0)
        return -1;

    info->lport                  = lport;
    info->tx_rate                = 100.0;
    info->tx_cycles              = 0;
    info->tx_next_cycle          = 0;
    info->tx_burst               = 64;
    info->pkt.pktSize            = 60;
    info->pkt.sport              = 1234;
    info->pkt.dport              = 5678;
    info->pkt.ipProto            = IPPROTO_UDP;
    info->pkt.ttl                = DEFAULT_TTL;
    info->pkt.ethType            = ETHERTYPE_IP;
    info->pkt.ip_dst_addr.s_addr = DEFAULT_IP_ADDR | ((lport->lpid + 1) << 8) | 1;
    info->pkt.ip_src_addr.s_addr = DEFAULT_IP_ADDR | (lport->lpid << 8) | 1;
    info->pkt.ip_mask            = DEFAULT_NETMASK;
    info->fill_pattern_type      = ABC_FILL_PATTERN;
    strlcpy(info->user_pattern, "0123456789abcdef", sizeof(info->user_pattern));

    txgen_set_port_flags(info, RUNNING_FLAG);

    return 0;
}

#define foreach_thd_lport(_t, _lp) \
    for (int _i = 0; _i < _t->lport_cnt && (_lp = _t->lports[_i]); _i++, _lp = _t->lports[_i])

/**
 *
 * txgen_launch_one_lcore - Launch a single logical core thread.
 *
 * DESCRIPTION
 * Help launch a single thread on one logical core.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_launch_one_lcore(void *arg)
{
    jcfg_thd_t *thd = arg;
    jcfg_lport_t *lport;
    port_info_t *info;
    void (*func)(port_info_t * info);
    struct {
        void (*func)(port_info_t *info);
    } thread_types[] = {{NULL}, {txgen_rxtx}, {txgen_rx}, {txgen_tx}};

    if (thd->group->lcore_cnt > 0)
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &thd->group->lcore_bitmap);

    txgen_force_update();
    foreach_thd_lport (thd, lport) {
        if (init_port_info(&txgen.info[lport->lpid], lport) < 0)
            cne_printf("*** Failed to initialize port_info_t data\n");
    }

    func = thread_types[txgen_thread_type(thd->thread_type)].func;
    if (!func) {
        cne_printf("*** Unable to determine thread type (%s)\n", thd->thread_type);
        return;
    }

    for (;;) {
        foreach_thd_lport (thd, lport) {
            info = &txgen.info[lport->lpid];

            if (thd->quit) /* Make sure we check quit often to break out ASAP */
                break;

            if (atomic_load(&info->port_flags) & RUNNING_FLAG)
                func(info);
        }
    }

    foreach_thd_lport (thd, lport)
        pktdev_close(lport->lpid);
}

static void
_page_display(void)
{
    static unsigned int counter = 0;

    display_set_color("top.spinner");
    cne_printf_pos(1, 1, "%c", "-\\|/"[(counter++ & 3)]);
    display_set_color(NULL);

    if (txgen.flags & PCAP_PAGE_FLAG)
        txgen_page_pcap(txgen.info);
    else
        txgen_page_stats();
}

#define UPDATE_DISPLAY_TICK_INTERVAL 4

/**
 *
 * txgen_page_display - Display the correct page based on timer callback.
 *
 * DESCRIPTION
 * When timer is active update or display the correct page of data.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_page_display(void)
{
    static unsigned int update_display = 1;

    /* Leave if the screen is paused */
    if (display_is_paused())
        return;

    vt_save();

    if (txgen.flags & UPDATE_DISPLAY_FLAG) {
        txgen.flags &= ~UPDATE_DISPLAY_FLAG;
        update_display = 1;
    }

    update_display--;
    if (update_display == 0) {
        update_display = UPDATE_DISPLAY_TICK_INTERVAL;

        _page_display();

        if (txgen.flags & PRINT_LABELS_FLAG)
            txgen.flags &= ~PRINT_LABELS_FLAG;
    }

    vt_restore();
}

void
txgen_stats(void *arg)
{
    jcfg_thd_t *thd = arg;
    uint64_t process_timo, page_timo;
    uint64_t page, stats;

    process_timo = cne_get_timer_hz();
    page_timo    = cne_get_timer_hz() / UPDATE_DISPLAY_TICK_INTERVAL;

    page  = cne_rdtsc() + page_timo;
    stats = cne_rdtsc() + process_timo;

    while (!thd->quit) {
        uint64_t curr = cne_rdtsc();

        if (curr >= page) {
            page = curr + page_timo;
            txgen_page_display();
        } else {
            if (curr >= stats) {
                stats = curr + process_timo;
                PKTDEV_FOREACH (pid) {
                    txgen_process_stats(pid);
                    if (thd->quit)
                        break;
                }
            } else
                cne_pause();
        }
    }
}
