/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 */

#ifndef _CNE_NET_PTYPE_H_
#define _CNE_NET_PTYPE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <net/cne_ip.h>
#include <net/cne_udp.h>
#include <net/cne_tcp.h>
#include <net/cne_sctp.h>

/**
 * Structure containing header lengths associated to a packet, filled
 * by cne_net_get_ptype().
 */
struct cne_net_hdr_lens {
    uint8_t l2_len;
    uint8_t inner_l2_len;
    uint16_t l3_len;
    uint16_t inner_l3_len;
    uint16_t tunnel_len;
    uint8_t l4_len;
    uint8_t inner_l4_len;
};

/**
 * Skip IPv6 header extensions.
 *
 * This function skips all IPv6 extensions, returning size of
 * complete header including options and final protocol value.
 *
 * @param proto
 *   Protocol field of IPv6 header.
 * @param m
 *   The packet mbuf to be parsed.
 * @param off
 *   On input, must contain the offset to the first byte following
 *   IPv6 header, on output, contains offset to the first byte
 *   of next layer (after any IPv6 extension header)
 * @param frag
 *   Contains 1 in output if packet is an IPv6 fragment.
 * @return
 *   Protocol that follows IPv6 header.
 *   -1 if an error occurs during mbuf parsing.
 */
CNDP_API int cne_net_skip_ip6_ext(uint16_t proto, const pktmbuf_t *m, uint32_t *off, int *frag);

/**
 * Parse an Ethernet packet to get its packet type.
 *
 * This function parses the network headers in mbuf data and return its
 * packet type.
 *
 * If it is provided by the user, it also fills a cne_net_hdr_lens
 * structure that contains the lengths of the parsed network
 * headers. Each length field is valid only if the associated packet
 * type is set. For instance, hdr_lens->l2_len is valid only if
 * (retval & CNE_PTYPE_L2_MASK) != CNE_PTYPE_UNKNOWN.
 *
 * Supported packet types are:
 *   L2: Ether, Vlan, QinQ
 *   L3: IPv4, IPv6
 *   L4: TCP, UDP, SCTP
 *   Tunnels: IPv4, IPv6, Gre, Nvgre
 *
 * @param m
 *   The packet mbuf to be parsed.
 * @param hdr_lens
 *   A pointer to a structure where the header lengths will be returned,
 *   or NULL.
 * @param layers
 *   List of layers to parse. The function will stop at the first
 *   empty layer. Examples:
 *   - To parse all known layers, use CNE_PTYPE_ALL_MASK.
 *   - To parse only L2 and L3, use CNE_PTYPE_L2_MASK | CNE_PTYPE_L3_MASK
 * @return
 *   The packet type of the packet.
 */
uint32_t cne_net_get_ptype(const pktmbuf_t *m, struct cne_net_hdr_lens *hdr_lens, uint32_t layers);

/**
 * Prepare pseudo header checksum
 *
 * This function prepares pseudo header checksum for TSO and non-TSO tcp/udp in
 * provided mbufs packet data and based on the requested offload flags.
 *
 * - for non-TSO tcp/udp packets full pseudo-header checksum is counted and set
 *   in packet data,
 * - for TSO the IP payload length is not included in pseudo header.
 *
 * This function expects that used headers are in the first data segment of
 * mbuf, are not fragmented and can be safely modified.
 *
 * @param m
 *   The packet mbuf to be fixed.
 * @param ol_flags
 *   TX offloads flags to use with this packet.
 * @return
 *   0 if checksum is initialized properly
 */
static inline int
cne_net_intel_cksum_flags_prepare(pktmbuf_t *m, uint64_t ol_flags)
{
    /* Initialise ipv4_hdr to avoid false positive compiler warnings. */
    struct cne_ipv4_hdr *ipv4_hdr = NULL;
    struct cne_ipv6_hdr *ipv6_hdr;
    struct cne_tcp_hdr *tcp_hdr;
    struct cne_udp_hdr *udp_hdr;
    uint64_t inner_l3_offset = m->l2_len;

    /*
     * Does packet set any of available offloads?
     * Mainly it is required to avoid fragmented headers check if
     * no offloads are requested.
     */
    if (!(ol_flags & (CNE_MBUF_F_TX_IP_CKSUM | CNE_MBUF_F_TX_L4_MASK | CNE_MBUF_F_TX_TCP_SEG)))
        return 0;

    if (ol_flags & (CNE_MBUF_F_TX_OUTER_IPV4 | CNE_MBUF_F_TX_OUTER_IPV6))
        inner_l3_offset += m->outer_l2_len + m->outer_l3_len;

    /*
     * Check if headers are fragmented.
     * The check could be less strict depending on which offloads are
     * requested and headers to be used, but let's keep it simple.
     */
    if (unlikely(pktmbuf_data_len(m) < inner_l3_offset + m->l3_len + m->l4_len))
        return -ENOTSUP;

    if (ol_flags & CNE_MBUF_F_TX_IPV4) {
        ipv4_hdr = pktmbuf_mtod_offset(m, struct cne_ipv4_hdr *, inner_l3_offset);

        if (ol_flags & CNE_MBUF_F_TX_IP_CKSUM)
            ipv4_hdr->hdr_checksum = 0;
    }

    if ((ol_flags & CNE_MBUF_F_TX_L4_MASK) == CNE_MBUF_F_TX_UDP_CKSUM) {
        if (ol_flags & CNE_MBUF_F_TX_IPV4) {
            udp_hdr              = (struct cne_udp_hdr *)((char *)ipv4_hdr + m->l3_len);
            udp_hdr->dgram_cksum = cne_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
        } else {
            ipv6_hdr = pktmbuf_mtod_offset(m, struct cne_ipv6_hdr *, inner_l3_offset);
            /* non-TSO udp */
            udp_hdr = pktmbuf_mtod_offset(m, struct cne_udp_hdr *, inner_l3_offset + m->l3_len);
            udp_hdr->dgram_cksum = cne_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
        }
    } else if ((ol_flags & CNE_MBUF_F_TX_L4_MASK) == CNE_MBUF_F_TX_TCP_CKSUM ||
               (ol_flags & CNE_MBUF_F_TX_TCP_SEG)) {
        if (ol_flags & CNE_MBUF_F_TX_IPV4) {
            /* non-TSO tcp or TSO */
            tcp_hdr        = (struct cne_tcp_hdr *)((char *)ipv4_hdr + m->l3_len);
            tcp_hdr->cksum = cne_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
        } else {
            ipv6_hdr = pktmbuf_mtod_offset(m, struct cne_ipv6_hdr *, inner_l3_offset);
            /* non-TSO tcp or TSO */
            tcp_hdr = pktmbuf_mtod_offset(m, struct cne_tcp_hdr *, inner_l3_offset + m->l3_len);
            tcp_hdr->cksum = cne_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
        }
    }

    return 0;
}

/**
 * Prepare pseudo header checksum
 *
 * This function prepares pseudo header checksum for TSO and non-TSO tcp/udp in
 * provided mbufs packet data.
 *
 * - for non-TSO tcp/udp packets full pseudo-header checksum is counted and set
 *   in packet data,
 * - for TSO the IP payload length is not included in pseudo header.
 *
 * This function expects that used headers are in the first data segment of
 * mbuf, are not fragmented and can be safely modified.
 *
 * @param m
 *   The packet mbuf to be fixed.
 * @return
 *   0 if checksum is initialized properly
 */
static inline int
cne_net_intel_cksum_prepare(pktmbuf_t *m)
{
    return cne_net_intel_cksum_flags_prepare(m, m->ol_flags);
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_NET_PTYPE_H_ */
