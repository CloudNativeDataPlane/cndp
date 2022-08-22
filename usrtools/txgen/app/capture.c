/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation.
 */

#include "capture.h"

#include <time.h>             // for localtime, strftime, time, time_t
#include <cne_log.h>          // for CNE_INFO, CNE_LOG_INFO, CNE_LOG_WARNING
#include <pcap/dlt.h>         // for DLT_EN10MB
#include <pcap/pcap.h>        // for pcap_pkthdr, pcap_close, pcap_dump, pcap_d...
#include <stdio.h>            // for snprintf
#include <string.h>           // for memset, memcpy
#include <sys/time.h>         // for timeval
#include <sys/types.h>        // for u_char

#include "cne_common.h"          // for CNE_MAX_ETHPORTS
#include "cne_cycles.h"          // for cne_rdtsc
#include "cne_mmap.h"            // for mmap_addr, mmap_alloc, mmap_name_by_type
#include "jcfg.h"                // for jcfg_lport_t
#include "netdev_funcs.h"        // for netdev_link
#include "pktmbuf.h"             // for pktmbuf_info_t, DEFAULT_MBUF_COUNT, DEFAUL...
#include "txgen.h"               // for pktmbuf_t, txgen_tst_port_flags, txgen_clr...

#define CAPTURE_BUFF_SIZE (4 * (1024 * 1024))

/* Helper for building log strings.
 * The macro takes an existing string, a printf-like format string and optional
 * arguments. It formats the string and appends it to the existing string, while
 * avoiding possible buffer overruns.
 */
#define strncatf(dest, fmt, ...)                               \
    do {                                                       \
        char _buff[1024];                                      \
        snprintf(_buff, sizeof(_buff), fmt, ##__VA_ARGS__);    \
        strncat(dest, _buff, sizeof(dest) - strlen(dest) - 1); \
    } while (0)

/**
 *
 * txgen_packet_capture_init - Initialize memory and data structures for packet
 * capture.
 *
 * DESCRIPTION
 * Initialization of memory zones and data structures for packet capture
 * storage.
 *
 * PARAMETERS:
 * capture: capture_t struct that will keep a pointer to the allocated memzone
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
void
txgen_packet_capture_init(capture_t *capture)
{
    mmap_t *mmap = NULL;

    if (!capture)
        return;

    mmap = mmap_alloc(DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, MMAP_HUGEPAGE_4KB);
    if (mmap == NULL)
        cne_panic("Unable to mmap(%lu, %s) memory",
                  (uint64_t)DEFAULT_MBUF_COUNT * (uint64_t)DEFAULT_MBUF_SIZE,
                  mmap_name_by_type(MMAP_HUGEPAGE_4KB));

    capture->port = CNE_MAX_ETHPORTS;
    capture->used = 0;

    capture->mp =
        pktmbuf_pool_create(mmap_addr(mmap), DEFAULT_MBUF_COUNT, DEFAULT_MBUF_SIZE, 0, NULL);
}

/**
 *
 * txgen_set_capture - Enable or disable packet capturing
 *
 * DESCRIPTION
 * Set up packet capturing for the given ports
 *
 * PARAMETERS:
 * info: port to capture from
 * onOff: enable or disable capturing?
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
txgen_set_capture(port_info_t *info, uint32_t onOff)
{
    capture_t *cap = {0};

    if (onOff == ENABLE_STATE) {
        /* Enabling an already enabled port is a no-op */
        if (txgen_tst_port_flags(info, CAPTURE_PKTS))
            return;

        cap = &txgen.captures[info->lport->lpid];

        if (cap->mp == NULL) {
            CNE_WARN("No memory allocated for capturing on socket");
            return;
        }

        /* Everything checks out: enable packet capture */
        cap->used = 0;
        cap->port = info->lport->lpid;
        cap->tail = (cap_hdr_t *)cap->mp->addr;
        cap->end  = (cap_hdr_t *)((char *)cap->mp->addr + (cap->mp->bufsz - sizeof(cap_hdr_t)));

        /* Write end-of-data sentinel to start of capture memory. This */
        /* effectively clears previously captured data. */
        memset(cap->tail, 0, sizeof(cap_hdr_t));
        memset(cap->end, 0, sizeof(cap_hdr_t));

        txgen_set_port_flags(info, CAPTURE_PKTS);

        cne_printf("Capturing on port %d buffer size: %.2f MB ", info->lport->lpid,
                   (double)cap->mp->bufsz / (1024 * 1024));

        /* 64 bytes payload + 2 bytes for payload size, Xbit -> Xbyte */
        /* 64 bytes payload + 20 byte etherrnet frame overhead: 84 bytes per packet */
        cne_printf("(~%.2f seconds for 64 byte packets at line rate)\n",
                   (double)cap->mp->bufsz /
                       (66 * ((double)info->link.link_speed * 1000 * 1000 / 8) / 84));
    } else {
        if (!(txgen_tst_port_flags(info, CAPTURE_PKTS)))
            return;

        cap = &txgen.captures[info->lport->lpid];

        /* If there is previously captured data in the buffer, write it to disk. */
        if (cap->used > 0) {

            pcap_t *pcap;
            pcap_dumper_t *pcap_dumper;
            struct pcap_pkthdr pcap_hdr;
            cap_hdr_t *hdr = {0};
            time_t t;
            char filename[128];
            char str_time[64];
            size_t mem_dumped = 0;
            unsigned int pct  = 0;
            struct tm *lt;

            cne_printf("\nDumping ~%.2fMB of captured data to disk: 0%%",
                       (double)cap->used / (1024 * 1024));

            pcap = pcap_open_dead(DLT_EN10MB, 65535);

            t  = time(NULL);
            lt = localtime(&t);
            if (lt)
                strftime(str_time, sizeof(str_time), "%Y%m%d-%H%M%S", lt);
            else
                snprintf(str_time, sizeof(str_time), "20210513-102717");
            snprintf(filename, sizeof(filename), "txgen-%s-%d.pcap", str_time, cap->port);
            pcap_dumper = pcap_dump_open(pcap, filename);

            hdr = (cap_hdr_t *)cap->mp->addr;

            while (hdr->pkt_len) {
                pcap_hdr.ts.tv_sec  = 0; /* FIXME use real timestamp */
                pcap_hdr.ts.tv_usec = 0; /* FIXME use real timestamp */
                pcap_hdr.len        = hdr->pkt_len;
                pcap_hdr.caplen     = hdr->data_len;

                pcap_dump((u_char *)pcap_dumper, &pcap_hdr, (const u_char *)hdr->pkt);

                hdr = (cap_hdr_t *)(hdr->pkt + hdr->data_len);

                mem_dumped = hdr->pkt - (unsigned char *)cap->mp->addr;

                /* The amount of data to dump to disk, is potentially very large */
                /* (a few gigabytes), so print a percentage counter. */
                if (pct < ((mem_dumped * 100) / cap->used)) {
                    pct = (mem_dumped * 100) / cap->used;

                    if (pct % 10 == 0)
                        cne_printf(" %d%%", pct);
                    else if (pct % 2 == 0)
                        cne_printf(" .");
                }
            }
            cne_printf("\n");

            pcap_dump_close(pcap_dumper);
            pcap_close(pcap);
        }

        cap->used = 0;
        cap->tail = (cap_hdr_t *)cap->mp->addr;
        cap->port = CNE_MAX_ETHPORTS;

        txgen_clr_port_flags(info, CAPTURE_PKTS);
    }
}

/**
 *
 * txgen_packet_capture_bulk - Capture packets to memory.
 *
 * DESCRIPTION
 * Capture packet contents to memory, so they can be written to disk later.
 *
 * A captured packet is stored as follows:
 * - uint16_t: untruncated packet length
 * - uint16_t: size of actual packet contents that are stored
 * - unsigned char[]: packet contents (number of bytes stored equals previous
 *       uint16_t)
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */

void
txgen_packet_capture_bulk(pktmbuf_t **pkts, uint32_t nb_dump, capture_t *cap)
{
    uint32_t plen, i;
    pktmbuf_t *pkt;

    /* Don't capture if buffer is full */
    if (cap->tail == cap->end)
        return;

    for (i = 0; i < nb_dump; i++) {
        pkt = pkts[i];

        plen = pkt->data_len;

        /* If packet to capture is larger than available buffer size, stop
         * capturing.
         * The packet data is prepended by the untruncated packet length and
         * the amount of captured data (which can be less than the packet size
         * if CNDP has stored the packet contents in segmented mbufs).
         */
        if ((cap_hdr_t *)(cap->tail->pkt + plen) > cap->end)
            break;

        /* Write untruncated data length and size of the actually captured
         * data. */
        cap->tail->pkt_len  = pkt->buf_len;
        cap->tail->data_len = plen;
        cap->tail->tstamp   = cne_rdtsc();

        memcpy(cap->tail->pkt, (uint8_t *)pkt->buf_addr + pkt->data_off, pkt->buf_len);
        cap->tail = (cap_hdr_t *)(cap->tail->pkt + plen);
    }

    /* Write end-of-data sentinel */
    cap->tail->pkt_len = 0;
    cap->used          = (unsigned char *)cap->tail - (unsigned char *)cap->mp->addr;
}
