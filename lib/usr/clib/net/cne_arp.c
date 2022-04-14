/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <string.h>         // for memset, NULL
#include <pktmbuf.h>        // for pktmbuf_alloc, pktmbuf_append, pktmbuf_free
#include <cne_arp.h>
#include <netinet/in.h>            // for htons
#include <linux/if_ether.h>        // for ETH_ALEN

#include "cne_ether.h"        // for ether_addr_copy, cne_ether_hdr, CNE_ETHE...

// IWYU pragma: no_forward_declare cne_mempool

#define RARP_PKT_SIZE 64
pktmbuf_t *
cne_net_make_rarp_packet(pktmbuf_info_t *pi, const struct ether_addr *mac)
{
    struct cne_ether_hdr *eth_hdr;
    struct cne_arp_hdr *rarp;
    pktmbuf_t *mbuf;

    if (pi == NULL)
        return NULL;

    mbuf = pktmbuf_alloc(pi);
    if (mbuf == NULL)
        return NULL;

    eth_hdr = (struct cne_ether_hdr *)pktmbuf_append(mbuf, RARP_PKT_SIZE);
    if (eth_hdr == NULL) {
        pktmbuf_free(mbuf);
        return NULL;
    }

    /* Ethernet header. */
    memset(eth_hdr->d_addr.ether_addr_octet, 0xff, ETH_ALEN);
    ether_addr_copy(mac, &eth_hdr->s_addr);
    eth_hdr->ether_type = htons(CNE_ETHER_TYPE_RARP);

    /* RARP header. */
    rarp               = (struct cne_arp_hdr *)(eth_hdr + 1);
    rarp->arp_hardware = htons(CNE_ARP_HRD_ETHER);
    rarp->arp_protocol = htons(CNE_ETHER_TYPE_IPV4);
    rarp->arp_hlen     = ETH_ALEN;
    rarp->arp_plen     = 4;
    rarp->arp_opcode   = htons(CNE_ARP_OP_REVREQUEST);

    ether_addr_copy(mac, &rarp->arp_data.arp_sha);
    ether_addr_copy(mac, &rarp->arp_data.arp_tha);
    memset(&rarp->arp_data.arp_sip, 0x00, 4);
    memset(&rarp->arp_data.arp_tip, 0x00, 4);

    return mbuf;
}
