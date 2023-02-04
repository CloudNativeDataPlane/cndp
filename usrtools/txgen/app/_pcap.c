/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#include <stdio.h>             // for fread, fseek, NULL, fflush, rewind, fclose
#include <stdlib.h>            // for free, malloc
#include <stdint.h>            // for uint16_t, uint32_t
#include <string.h>            // for memset, strdup
#include <netinet/in.h>        // for ntohl, ntohs
#include <_pcap.h>

#include "cne_log.h"          // for CNE_ERR_GOTO, CNE_LOG_ERR
#include "cne_stdio.h"        // for cne_printf

pcap_info_t *
_pcap_open(char *filename, uint16_t port)
{
    pcap_info_t *pcap = NULL;

    CNE_SET_USED(port);

    if (filename == NULL)
        CNE_ERR_GOTO(leave, "%s: filename is NULL\n", __func__);

    pcap = (pcap_info_t *)malloc(sizeof(pcap_info_t));
    if (pcap == NULL)
        CNE_ERR_GOTO(leave, "%s: malloc failed for pcap_info_t structure\n", __func__);

    memset((char *)pcap, 0, sizeof(pcap_info_t));

    pcap->fd = fopen((const char *)filename, "r");
    if (pcap->fd == NULL)
        CNE_ERR_GOTO(leave, "%s: failed for (%s)\n", __func__, filename);

    if (fread(&pcap->info, 1, sizeof(pcap_hdr_t), pcap->fd) != sizeof(pcap_hdr_t))
        CNE_ERR_GOTO(leave, "%s: failed to read the file header\n", __func__);

    /* Default to little endian format. */
    pcap->endian   = LITTLE_ENDIAN;
    pcap->filename = strdup(filename);

    /* Make sure we have a valid PCAP file for Big or Little Endian formats. */
    if ((pcap->info.magic_number != PCAP_MAGIC_NUMBER) &&
        (pcap->info.magic_number != ntohl(PCAP_MAGIC_NUMBER)))
        CNE_ERR_GOTO(leave, "%s: Magic Number does not match!\n", __func__);

    /* Convert from big-endian to little-endian. */
    if (pcap->info.magic_number == ntohl(PCAP_MAGIC_NUMBER)) {
        pcap->endian             = BIG_ENDIAN;
        pcap->info.magic_number  = ntohl(pcap->info.magic_number);
        pcap->info.network       = ntohl(pcap->info.network);
        pcap->info.sigfigs       = ntohl(pcap->info.sigfigs);
        pcap->info.snaplen       = ntohl(pcap->info.snaplen);
        pcap->info.thiszone      = ntohl(pcap->info.thiszone);
        pcap->info.version_major = ntohs(pcap->info.version_major);
        pcap->info.version_minor = ntohs(pcap->info.version_minor);
    }
    return pcap;

leave:
    _pcap_close(pcap);
    fflush(stdout);

    return NULL;
}

void
_pcap_info(pcap_info_t *pcap, uint16_t port, int flag)
{
    cne_printf("\nPCAP file for port %d: %s\n", port, pcap->filename);
    cne_printf("  magic: %08x,", pcap->info.magic_number);
    cne_printf(" Version: %d.%d,", pcap->info.version_major, pcap->info.version_minor);
    cne_printf(" Zone: %d,", pcap->info.thiszone);
    cne_printf(" snaplen: %d,", pcap->info.snaplen);
    cne_printf(" sigfigs: %d,", pcap->info.sigfigs);
    cne_printf(" network: %d", pcap->info.network);
    cne_printf(" Endian: %s\n", pcap->endian == BIG_ENDIAN ? "Big" : "Little");
    if (flag)
        cne_printf("  Packet count: %d\n", pcap->pkt_count);
    cne_printf("\n");
    fflush(stdout);
}

void
_pcap_rewind(pcap_info_t *pcap)
{
    if (pcap == NULL)
        return;

    /* Rewind to the beginning */
    rewind(pcap->fd);

    /* Seek past the pcap header */
    (void)fseek(pcap->fd, sizeof(pcap_hdr_t), SEEK_SET);
}

void
_pcap_skip(pcap_info_t *pcap, uint32_t skip)
{
    pcaprec_hdr_t hdr, *phdr;

    if (pcap == NULL)
        return;

    /* Rewind to the beginning */
    rewind(pcap->fd);

    /* Seek past the pcap header */
    (void)fseek(pcap->fd, sizeof(pcap_hdr_t), SEEK_SET);

    phdr = &hdr;
    while (skip--) {
        if (fread(phdr, 1, sizeof(pcaprec_hdr_t), pcap->fd) != sizeof(pcaprec_hdr_t))
            break;

        /* Convert the packet header to the correct format. */
        _pcap_convert(pcap, phdr);

        (void)fseek(pcap->fd, phdr->incl_len, SEEK_CUR);
    }
}

void
_pcap_close(pcap_info_t *pcap)
{
    if (pcap == NULL)
        return;

    if (pcap->fd)
        fclose(pcap->fd);
    if (pcap->filename)
        free(pcap->filename);
    free(pcap);
}

size_t
_pcap_read(pcap_info_t *pcap, pcaprec_hdr_t *pHdr, char *pktBuff, uint32_t bufLen)
{
    do {
        if (fread(pHdr, 1, sizeof(pcaprec_hdr_t), pcap->fd) != sizeof(pcaprec_hdr_t))
            return 0;

        /* Convert the packet header to the correct format. */
        _pcap_convert(pcap, pHdr);

        /* Skip packets larger then the buffer size. */
        if (pHdr->incl_len > bufLen) {
            (void)fseek(pcap->fd, pHdr->incl_len, SEEK_CUR);
            return pHdr->incl_len;
        }

        return fread(pktBuff, 1, pHdr->incl_len, pcap->fd);
    } while (1);
}
