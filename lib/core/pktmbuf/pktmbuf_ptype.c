/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright (c) 2020-2022 Intel Corporation.
 */

#include <stdint.h>        // for uint32_t
#include <stdio.h>         // for snprintf

#include <pktmbuf.h>
#include <pktmbuf_ptype.h>
#include <cne_byteorder.h>
#include <net/cne_ether.h>
#include <net/cne_ip.h>
#include <net/cne_tcp.h>
#include <net/cne_udp.h>
#include <net/cne_sctp.h>
#include <net/cne_gre.h>
#include <net/cne_mpls.h>
#include <net/cne_gtp.h>

/* get the name of the l2 packet type */
const char *
cne_get_ptype_l2_name(uint32_t ptype)
{
    switch (ptype & CNE_PTYPE_L2_MASK) {
    case CNE_PTYPE_L2_ETHER:
        return "L2_ETHER";
    case CNE_PTYPE_L2_ETHER_TIMESYNC:
        return "L2_ETHER_TIMESYNC";
    case CNE_PTYPE_L2_ETHER_ARP:
        return "L2_ETHER_ARP";
    case CNE_PTYPE_L2_ETHER_LLDP:
        return "L2_ETHER_LLDP";
    case CNE_PTYPE_L2_ETHER_NSH:
        return "L2_ETHER_NSH";
    case CNE_PTYPE_L2_ETHER_VLAN:
        return "L2_ETHER_VLAN";
    case CNE_PTYPE_L2_ETHER_QINQ:
        return "L2_ETHER_QINQ";
    case CNE_PTYPE_L2_ETHER_PPPOE:
        return "L2_ETHER_PPPOE";
    case CNE_PTYPE_L2_ETHER_FCOE:
        return "L2_ETHER_FCOE";
    case CNE_PTYPE_L2_ETHER_MPLS:
        return "L2_ETHER_MPLS";
    default:
        return "L2_UNKNOWN";
    }
}

/* get the name of the l3 packet type */
const char *
cne_get_ptype_l3_name(uint32_t ptype)
{
    switch (ptype & CNE_PTYPE_L3_MASK) {
    case CNE_PTYPE_L3_IPV4:
        return "L3_IPV4";
    case CNE_PTYPE_L3_IPV4_EXT:
        return "L3_IPV4_EXT";
    case CNE_PTYPE_L3_IPV6:
        return "L3_IPV6";
    case CNE_PTYPE_L3_IPV4_EXT_UNKNOWN:
        return "L3_IPV4_EXT_UNKNOWN";
    case CNE_PTYPE_L3_IPV6_EXT:
        return "L3_IPV6_EXT";
    case CNE_PTYPE_L3_IPV6_EXT_UNKNOWN:
        return "L3_IPV6_EXT_UNKNOWN";
    default:
        return "L3_UNKNOWN";
    }
}

/* get the name of the l4 packet type */
const char *
cne_get_ptype_l4_name(uint32_t ptype)
{
    switch (ptype & CNE_PTYPE_L4_MASK) {
    case CNE_PTYPE_L4_TCP:
        return "L4_TCP";
    case CNE_PTYPE_L4_UDP:
        return "L4_UDP";
    case CNE_PTYPE_L4_FRAG:
        return "L4_FRAG";
    case CNE_PTYPE_L4_SCTP:
        return "L4_SCTP";
    case CNE_PTYPE_L4_ICMP:
        return "L4_ICMP";
    case CNE_PTYPE_L4_NONFRAG:
        return "L4_NONFRAG";
    case CNE_PTYPE_L4_IGMP:
        return "L4_IGMP";
    default:
        return "L4_UNKNOWN";
    }
}

/* get the name of the tunnel packet type */
const char *
cne_get_ptype_tunnel_name(uint32_t ptype)
{
    switch (ptype & CNE_PTYPE_TUNNEL_MASK) {
    case CNE_PTYPE_TUNNEL_IP:
        return "TUNNEL_IP";
    case CNE_PTYPE_TUNNEL_GRE:
        return "TUNNEL_GRE";
    case CNE_PTYPE_TUNNEL_VXLAN:
        return "TUNNEL_VXLAN";
    case CNE_PTYPE_TUNNEL_NVGRE:
        return "TUNNEL_NVGRE";
    case CNE_PTYPE_TUNNEL_GENEVE:
        return "TUNNEL_GENEVE";
    case CNE_PTYPE_TUNNEL_GRENAT:
        return "TUNNEL_GRENAT";
    case CNE_PTYPE_TUNNEL_GTPC:
        return "TUNNEL_GTPC";
    case CNE_PTYPE_TUNNEL_GTPU:
        return "TUNNEL_GTPU";
    case CNE_PTYPE_TUNNEL_ESP:
        return "TUNNEL_ESP";
    case CNE_PTYPE_TUNNEL_L2TP:
        return "TUNNEL_L2TP";
    case CNE_PTYPE_TUNNEL_VXLAN_GPE:
        return "TUNNEL_VXLAN_GPE";
    case CNE_PTYPE_TUNNEL_MPLS_IN_UDP:
        return "TUNNEL_MPLS_IN_UDP";
    case CNE_PTYPE_TUNNEL_MPLS_IN_GRE:
        return "TUNNEL_MPLS_IN_GRE";
    default:
        return "TUNNEL_UNKNOWN";
    }
}

/* get the name of the inner_l2 packet type */
const char *
cne_get_ptype_inner_l2_name(uint32_t ptype)
{
    switch (ptype & CNE_PTYPE_INNER_L2_MASK) {
    case CNE_PTYPE_INNER_L2_ETHER:
        return "INNER_L2_ETHER";
    case CNE_PTYPE_INNER_L2_ETHER_VLAN:
        return "INNER_L2_ETHER_VLAN";
    case CNE_PTYPE_INNER_L2_ETHER_QINQ:
        return "INNER_L2_ETHER_QINQ";
    default:
        return "INNER_L2_UNKNOWN";
    }
}

/* get the name of the inner_l3 packet type */
const char *
cne_get_ptype_inner_l3_name(uint32_t ptype)
{
    switch (ptype & CNE_PTYPE_INNER_L3_MASK) {
    case CNE_PTYPE_INNER_L3_IPV4:
        return "INNER_L3_IPV4";
    case CNE_PTYPE_INNER_L3_IPV4_EXT:
        return "INNER_L3_IPV4_EXT";
    case CNE_PTYPE_INNER_L3_IPV6:
        return "INNER_L3_IPV6";
    case CNE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN:
        return "INNER_L3_IPV4_EXT_UNKNOWN";
    case CNE_PTYPE_INNER_L3_IPV6_EXT:
        return "INNER_L3_IPV6_EXT";
    case CNE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN:
        return "INNER_L3_IPV6_EXT_UNKNOWN";
    default:
        return "INNER_L3_UNKNOWN";
    }
}

/* get the name of the inner_l4 packet type */
const char *
cne_get_ptype_inner_l4_name(uint32_t ptype)
{
    switch (ptype & CNE_PTYPE_INNER_L4_MASK) {
    case CNE_PTYPE_INNER_L4_TCP:
        return "INNER_L4_TCP";
    case CNE_PTYPE_INNER_L4_UDP:
        return "INNER_L4_UDP";
    case CNE_PTYPE_INNER_L4_FRAG:
        return "INNER_L4_FRAG";
    case CNE_PTYPE_INNER_L4_SCTP:
        return "INNER_L4_SCTP";
    case CNE_PTYPE_INNER_L4_ICMP:
        return "INNER_L4_ICMP";
    case CNE_PTYPE_INNER_L4_NONFRAG:
        return "INNER_L4_NONFRAG";
    default:
        return "INNER_L4_UNKNOWN";
    }
}

/* write the packet type name into the buffer */
int
cne_get_ptype_name(uint32_t ptype, char *buf, size_t buflen)
{
    int ret;

    if (!buf || buflen == 0)
        return -1;

    buf[0] = '\0';
    if ((ptype & CNE_PTYPE_ALL_MASK) == CNE_PTYPE_UNKNOWN) {
        ret = snprintf(buf, buflen, "UNKNOWN");
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        return 0;
    }

    if ((ptype & CNE_PTYPE_L2_MASK) != 0) {
        ret = snprintf(buf, buflen, "%s ", cne_get_ptype_l2_name(ptype));
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        buf += ret;
        buflen -= ret;
    }
    if ((ptype & CNE_PTYPE_L3_MASK) != 0) {
        ret = snprintf(buf, buflen, "%s ", cne_get_ptype_l3_name(ptype));
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        buf += ret;
        buflen -= ret;
    }
    if ((ptype & CNE_PTYPE_L4_MASK) != 0) {
        ret = snprintf(buf, buflen, "%s ", cne_get_ptype_l4_name(ptype));
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        buf += ret;
        buflen -= ret;
    }
    if ((ptype & CNE_PTYPE_TUNNEL_MASK) != 0) {
        ret = snprintf(buf, buflen, "%s ", cne_get_ptype_tunnel_name(ptype));
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        buf += ret;
        buflen -= ret;
    }
    if ((ptype & CNE_PTYPE_INNER_L2_MASK) != 0) {
        ret = snprintf(buf, buflen, "%s ", cne_get_ptype_inner_l2_name(ptype));
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        buf += ret;
        buflen -= ret;
    }
    if ((ptype & CNE_PTYPE_INNER_L3_MASK) != 0) {
        ret = snprintf(buf, buflen, "%s ", cne_get_ptype_inner_l3_name(ptype));
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        buf += ret;
        buflen -= ret;
    }
    if ((ptype & CNE_PTYPE_INNER_L4_MASK) != 0) {
        ret = snprintf(buf, buflen, "%s ", cne_get_ptype_inner_l4_name(ptype));
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        buf += ret;
        buflen -= ret;
    }

    return 0;
}

/* get l3 packet type from ip6 next protocol */
static uint32_t
ptype_l3_ip6(uint8_t ip6_proto)
{
    static const uint32_t ip6_ext_proto_map[256] = {
        [IPPROTO_HOPOPTS]  = CNE_PTYPE_L3_IPV6_EXT - CNE_PTYPE_L3_IPV6,
        [IPPROTO_ROUTING]  = CNE_PTYPE_L3_IPV6_EXT - CNE_PTYPE_L3_IPV6,
        [IPPROTO_FRAGMENT] = CNE_PTYPE_L3_IPV6_EXT - CNE_PTYPE_L3_IPV6,
        [IPPROTO_ESP]      = CNE_PTYPE_L3_IPV6_EXT - CNE_PTYPE_L3_IPV6,
        [IPPROTO_AH]       = CNE_PTYPE_L3_IPV6_EXT - CNE_PTYPE_L3_IPV6,
        [IPPROTO_DSTOPTS]  = CNE_PTYPE_L3_IPV6_EXT - CNE_PTYPE_L3_IPV6,
    };

    return CNE_PTYPE_L3_IPV6 + ip6_ext_proto_map[ip6_proto];
}

/* get l3 packet type from ip version and header length */
static uint32_t
ptype_l3_ip(uint8_t ipv_ihl)
{
    static const uint32_t ptype_l3_ip_proto_map[256] = {
        [0x45] = CNE_PTYPE_L3_IPV4,     [0x46] = CNE_PTYPE_L3_IPV4_EXT,
        [0x47] = CNE_PTYPE_L3_IPV4_EXT, [0x48] = CNE_PTYPE_L3_IPV4_EXT,
        [0x49] = CNE_PTYPE_L3_IPV4_EXT, [0x4A] = CNE_PTYPE_L3_IPV4_EXT,
        [0x4B] = CNE_PTYPE_L3_IPV4_EXT, [0x4C] = CNE_PTYPE_L3_IPV4_EXT,
        [0x4D] = CNE_PTYPE_L3_IPV4_EXT, [0x4E] = CNE_PTYPE_L3_IPV4_EXT,
        [0x4F] = CNE_PTYPE_L3_IPV4_EXT,
    };

    return ptype_l3_ip_proto_map[ipv_ihl];
}

/* get l4 packet type from proto */
static uint32_t
ptype_l4(uint8_t proto)
{
    static const uint32_t ptype_l4_proto[256] = {
        [IPPROTO_UDP]  = CNE_PTYPE_L4_UDP,
        [IPPROTO_TCP]  = CNE_PTYPE_L4_TCP,
        [IPPROTO_SCTP] = CNE_PTYPE_L4_SCTP,
    };

    return ptype_l4_proto[proto];
}

/* get inner l3 packet type from ip6 next protocol */
static uint32_t
ptype_inner_l3_ip6(uint8_t ip6_proto)
{
    static const uint32_t ptype_inner_ip6_ext_proto_map[256] = {
        [IPPROTO_HOPOPTS]  = CNE_PTYPE_INNER_L3_IPV6_EXT - CNE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_ROUTING]  = CNE_PTYPE_INNER_L3_IPV6_EXT - CNE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_FRAGMENT] = CNE_PTYPE_INNER_L3_IPV6_EXT - CNE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_ESP]      = CNE_PTYPE_INNER_L3_IPV6_EXT - CNE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_AH]       = CNE_PTYPE_INNER_L3_IPV6_EXT - CNE_PTYPE_INNER_L3_IPV6,
        [IPPROTO_DSTOPTS]  = CNE_PTYPE_INNER_L3_IPV6_EXT - CNE_PTYPE_INNER_L3_IPV6,
    };

    return CNE_PTYPE_INNER_L3_IPV6 + ptype_inner_ip6_ext_proto_map[ip6_proto];
}

/* get inner l3 packet type from ip version and header length */
static uint32_t
ptype_inner_l3_ip(uint8_t ipv_ihl)
{
    static const uint32_t ptype_inner_l3_ip_proto_map[256] = {
        [0x45] = CNE_PTYPE_INNER_L3_IPV4,     [0x46] = CNE_PTYPE_INNER_L3_IPV4_EXT,
        [0x47] = CNE_PTYPE_INNER_L3_IPV4_EXT, [0x48] = CNE_PTYPE_INNER_L3_IPV4_EXT,
        [0x49] = CNE_PTYPE_INNER_L3_IPV4_EXT, [0x4A] = CNE_PTYPE_INNER_L3_IPV4_EXT,
        [0x4B] = CNE_PTYPE_INNER_L3_IPV4_EXT, [0x4C] = CNE_PTYPE_INNER_L3_IPV4_EXT,
        [0x4D] = CNE_PTYPE_INNER_L3_IPV4_EXT, [0x4E] = CNE_PTYPE_INNER_L3_IPV4_EXT,
        [0x4F] = CNE_PTYPE_INNER_L3_IPV4_EXT,
    };

    return ptype_inner_l3_ip_proto_map[ipv_ihl];
}

/* get inner l4 packet type from proto */
static uint32_t
ptype_inner_l4(uint8_t proto)
{
    static const uint32_t ptype_inner_l4_proto[256] = {
        [IPPROTO_UDP]  = CNE_PTYPE_INNER_L4_UDP,
        [IPPROTO_TCP]  = CNE_PTYPE_INNER_L4_TCP,
        [IPPROTO_SCTP] = CNE_PTYPE_INNER_L4_SCTP,
    };

    return ptype_inner_l4_proto[proto];
}

/* get the tunnel packet type if any, update proto and off. */
static uint32_t
ptype_tunnel(uint16_t *proto, const pktmbuf_t *m, uint32_t *off)
{
    switch (*proto) {
    case IPPROTO_GRE: {
        static const uint8_t opt_len[16] = {
            [0x0] = 4,  [0x1] = 8,  [0x2] = 8,  [0x8] = 8,
            [0x3] = 12, [0x9] = 12, [0xa] = 12, [0xb] = 16,
        };
        const struct cne_gre_hdr *gh;
        uint16_t flags;

        gh = pktmbuf_mtod_offset(m, struct cne_gre_hdr *, *off);
        if (unlikely(gh == NULL))
            return 0;

        flags = be16toh(*(const uint16_t *)gh);
        flags >>= 12;
        if (opt_len[flags] == 0)
            return 0;

        *off += opt_len[flags];
        *proto = gh->proto;
        if (*proto == htobe16(CNE_ETHER_TYPE_TEB))
            return CNE_PTYPE_TUNNEL_NVGRE;
        else
            return CNE_PTYPE_TUNNEL_GRE;
    }
    case IPPROTO_IPIP:
        *proto = htobe16(CNE_ETHER_TYPE_IPV4);
        return CNE_PTYPE_TUNNEL_IP;
    case IPPROTO_IPV6:
        *proto = htobe16(CNE_ETHER_TYPE_IPV6);
        return CNE_PTYPE_TUNNEL_IP; /* IP is also valid for IPv6 */
    default:
        return 0;
    }
}

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
static int
skip_ip6_ext(uint16_t proto, const pktmbuf_t *m, uint32_t *off, int *frag)
{
    struct ext_hdr {
        uint8_t next_hdr;
        uint8_t len;
    };
    const struct ext_hdr *xh;
    unsigned int i;

    *frag = 0;

#define MAX_EXT_HDRS 5
    for (i = 0; i < MAX_EXT_HDRS; i++) {
        switch (proto) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
            xh = pktmbuf_mtod_offset(m, struct ext_hdr *, *off);
            if (xh == NULL)
                return -1;
            *off += (xh->len + 1) * 8;
            proto = xh->next_hdr;
            break;
        case IPPROTO_FRAGMENT:
            xh = pktmbuf_mtod_offset(m, struct ext_hdr *, *off);
            if (xh == NULL)
                return -1;
            *off += 8;
            proto = xh->next_hdr;
            *frag = 1;
            return proto; /* this is always the last ext hdr */
        case IPPROTO_NONE:
            return 0;
        default:
            return proto;
        }
    }
    return -1;
}

/* parse mbuf data to get packet type */
uint32_t
cne_get_ptype(const pktmbuf_t *m, struct cne_net_hdr_lens *hdr_lens, uint32_t layers)
{
    struct cne_net_hdr_lens local_hdr_lens;
    const struct cne_ether_hdr *eh;
    uint32_t pkt_type = CNE_PTYPE_L2_ETHER;
    uint32_t off      = 0;
    uint16_t proto;
    int ret;

    if (hdr_lens == NULL)
        hdr_lens = &local_hdr_lens;

    eh = pktmbuf_mtod_offset(m, struct cne_ether_hdr *, off);
    if (unlikely(eh == NULL))
        return 0;
    proto            = eh->ether_type;
    off              = sizeof(struct cne_ether_hdr);
    hdr_lens->l2_len = off;

    if ((layers & CNE_PTYPE_L2_MASK) == 0)
        return 0;

    if (proto == htobe16(CNE_ETHER_TYPE_ARP))
        return CNE_PTYPE_L2_ETHER_ARP;

    if (proto == htobe16(CNE_ETHER_TYPE_IPV4))
        goto l3; /* fast path if packet is IPv4 */

    if (proto == htobe16(CNE_ETHER_TYPE_VLAN)) {
        const struct cne_vlan_hdr *vh;

        pkt_type = CNE_PTYPE_L2_ETHER_VLAN;
        vh       = pktmbuf_mtod_offset(m, struct cne_vlan_hdr *, off);
        if (unlikely(vh == NULL))
            return pkt_type;
        off += sizeof(struct cne_vlan_hdr);
        hdr_lens->l2_len += sizeof(struct cne_vlan_hdr);
        proto = vh->eth_proto;
    } else if (proto == htobe16(CNE_ETHER_TYPE_QINQ)) {
        const struct cne_vlan_hdr *vh;

        pkt_type = CNE_PTYPE_L2_ETHER_QINQ;
        vh       = pktmbuf_mtod_offset(m, struct cne_vlan_hdr *, off + sizeof(*vh));
        if (unlikely(vh == NULL))
            return pkt_type;
        off += 2 * sizeof(struct cne_vlan_hdr);
        hdr_lens->l2_len += 2 * sizeof(struct cne_vlan_hdr);
        proto = vh->eth_proto;
    } else if ((proto == htobe16(CNE_ETHER_TYPE_MPLS)) ||
               (proto == htobe16(CNE_ETHER_TYPE_MPLSM))) {
        unsigned int i;
        const struct cne_mpls_hdr *mh;

#define MAX_MPLS_HDR 5
        for (i = 0; i < MAX_MPLS_HDR; i++) {
            mh = pktmbuf_mtod_offset(m, struct cne_mpls_hdr *,
                                     off + (i * sizeof(struct cne_mpls_hdr)));
            if (unlikely(mh == NULL))
                return pkt_type;
        }
        if (i == MAX_MPLS_HDR)
            return pkt_type;
        pkt_type = CNE_PTYPE_L2_ETHER_MPLS;
        hdr_lens->l2_len += (sizeof(struct cne_mpls_hdr) * i);
        return pkt_type;
    }

l3:
    if ((layers & CNE_PTYPE_L3_MASK) == 0)
        return pkt_type;

    if (proto == htobe16(CNE_ETHER_TYPE_IPV4)) {
        const struct cne_ipv4_hdr *ip4h;

        ip4h = pktmbuf_mtod_offset(m, struct cne_ipv4_hdr *, off);
        if (unlikely(ip4h == NULL))
            return pkt_type;

        pkt_type |= ptype_l3_ip(ip4h->version_ihl);
        hdr_lens->l3_len = cne_ipv4_hdr_len(ip4h);
        off += hdr_lens->l3_len;

        if ((layers & CNE_PTYPE_L4_MASK) == 0)
            return pkt_type;

        if (ip4h->fragment_offset & htobe16(CNE_IPV4_HDR_OFFSET_MASK | CNE_IPV4_HDR_MF_FLAG)) {
            pkt_type |= CNE_PTYPE_L4_FRAG;
            hdr_lens->l4_len = 0;
            return pkt_type;
        }
        proto = ip4h->next_proto_id;
        pkt_type |= ptype_l4(proto);
    } else if (proto == htobe16(CNE_ETHER_TYPE_IPV6)) {
        const struct cne_ipv6_hdr *ip6h;
        int frag = 0;

        ip6h = pktmbuf_mtod_offset(m, struct cne_ipv6_hdr *, off);
        if (unlikely(ip6h == NULL))
            return pkt_type;

        proto            = ip6h->proto;
        hdr_lens->l3_len = sizeof(struct cne_ipv6_hdr);
        off += hdr_lens->l3_len;
        pkt_type |= ptype_l3_ip6(proto);
        if ((pkt_type & CNE_PTYPE_L3_MASK) == CNE_PTYPE_L3_IPV6_EXT) {
            ret = skip_ip6_ext(proto, m, &off, &frag);
            if (ret < 0)
                return pkt_type;
            proto            = ret;
            hdr_lens->l3_len = off - hdr_lens->l2_len;
        }
        if (proto == 0)
            return pkt_type;

        if ((layers & CNE_PTYPE_L4_MASK) == 0)
            return pkt_type;

        if (frag) {
            pkt_type |= CNE_PTYPE_L4_FRAG;
            hdr_lens->l4_len = 0;
            return pkt_type;
        }
        pkt_type |= ptype_l4(proto);
    }

    if ((pkt_type & CNE_PTYPE_L4_MASK) == CNE_PTYPE_L4_UDP) {
        const struct cne_udp_hdr *udp =
            pktmbuf_mtod_offset(m, struct cne_udp_hdr *, hdr_lens->l2_len + hdr_lens->l3_len);

        hdr_lens->l4_len = sizeof(struct cne_udp_hdr);
        if (udp->dst_port == be16toh(CNE_GTPU_UDP_PORT))
            pkt_type |= CNE_PTYPE_TUNNEL_GTPU;
        else if (udp->dst_port == be16toh(CNE_GTPC_UDP_PORT))
            pkt_type |= CNE_PTYPE_TUNNEL_GTPC;
        return pkt_type;
    } else if ((pkt_type & CNE_PTYPE_L4_MASK) == CNE_PTYPE_L4_TCP) {
        const struct cne_tcp_hdr *th =
            pktmbuf_mtod_offset(m, struct cne_tcp_hdr *, hdr_lens->l2_len + hdr_lens->l3_len);

        hdr_lens->l4_len = (th->data_off & 0xf0) >> 2;
        return pkt_type;
    } else if ((pkt_type & CNE_PTYPE_L4_MASK) == CNE_PTYPE_L4_SCTP) {
        hdr_lens->l4_len = sizeof(struct cne_sctp_hdr);
        return pkt_type;
    } else {
        uint32_t prev_off = off;

        hdr_lens->l4_len = 0;

        if ((layers & CNE_PTYPE_TUNNEL_MASK) == 0)
            return pkt_type;

        pkt_type |= ptype_tunnel(&proto, m, &off);
        hdr_lens->tunnel_len = off - prev_off;
    }

    /* same job for inner header: we need to duplicate the code
     * because the packet types do not have the same value.
     */
    if ((layers & CNE_PTYPE_INNER_L2_MASK) == 0)
        return pkt_type;

    hdr_lens->inner_l2_len = 0;
    if (proto == htobe16(CNE_ETHER_TYPE_TEB)) {
        eh = pktmbuf_mtod_offset(m, struct cne_ether_hdr *, off);
        if (unlikely(eh == NULL))
            return pkt_type;
        pkt_type |= CNE_PTYPE_INNER_L2_ETHER;
        proto = eh->ether_type;
        off += sizeof(*eh);
        hdr_lens->inner_l2_len = sizeof(*eh);
    }

    if (proto == htobe16(CNE_ETHER_TYPE_VLAN)) {
        const struct cne_vlan_hdr *vh;

        pkt_type &= ~CNE_PTYPE_INNER_L2_MASK;
        pkt_type |= CNE_PTYPE_INNER_L2_ETHER_VLAN;
        vh = pktmbuf_mtod_offset(m, struct cne_vlan_hdr *, off);
        if (unlikely(vh == NULL))
            return pkt_type;
        off += sizeof(struct cne_vlan_hdr);
        hdr_lens->inner_l2_len += sizeof(struct cne_vlan_hdr);
        proto = vh->eth_proto;
    } else if (proto == htobe16(CNE_ETHER_TYPE_QINQ)) {
        const struct cne_vlan_hdr *vh;

        pkt_type &= ~CNE_PTYPE_INNER_L2_MASK;
        pkt_type |= CNE_PTYPE_INNER_L2_ETHER_QINQ;
        vh = pktmbuf_mtod_offset(m, struct cne_vlan_hdr *, off + sizeof(struct cne_vlan_hdr));
        if (unlikely(vh == NULL))
            return pkt_type;
        off += 2 * sizeof(struct cne_vlan_hdr);
        hdr_lens->inner_l2_len += 2 * sizeof(struct cne_vlan_hdr);
        proto = vh->eth_proto;
    }

    if ((layers & CNE_PTYPE_INNER_L3_MASK) == 0)
        return pkt_type;

    if (proto == htobe16(CNE_ETHER_TYPE_IPV4)) {
        const struct cne_ipv4_hdr *ip4h;

        ip4h = pktmbuf_mtod_offset(m, struct cne_ipv4_hdr *, off);
        if (unlikely(ip4h == NULL))
            return pkt_type;

        pkt_type |= ptype_inner_l3_ip(ip4h->version_ihl);
        hdr_lens->inner_l3_len = cne_ipv4_hdr_len(ip4h);
        off += hdr_lens->inner_l3_len;

        if ((layers & CNE_PTYPE_INNER_L4_MASK) == 0)
            return pkt_type;
        if (ip4h->fragment_offset & htobe16(CNE_IPV4_HDR_OFFSET_MASK | CNE_IPV4_HDR_MF_FLAG)) {
            pkt_type |= CNE_PTYPE_INNER_L4_FRAG;
            hdr_lens->inner_l4_len = 0;
            return pkt_type;
        }
        proto = ip4h->next_proto_id;
        pkt_type |= ptype_inner_l4(proto);
    } else if (proto == htobe16(CNE_ETHER_TYPE_IPV6)) {
        const struct cne_ipv6_hdr *ip6h;
        int frag = 0;

        ip6h = pktmbuf_mtod_offset(m, struct cne_ipv6_hdr *, off);
        if (unlikely(ip6h == NULL))
            return pkt_type;

        proto                  = ip6h->proto;
        hdr_lens->inner_l3_len = sizeof(*ip6h);
        off += hdr_lens->inner_l3_len;
        pkt_type |= ptype_inner_l3_ip6(proto);
        if ((pkt_type & CNE_PTYPE_INNER_L3_MASK) == CNE_PTYPE_INNER_L3_IPV6_EXT) {
            uint32_t prev_off;

            prev_off = off;
            ret      = skip_ip6_ext(proto, m, &off, &frag);
            if (ret < 0)
                return pkt_type;
            proto = ret;
            hdr_lens->inner_l3_len += off - prev_off;
        }
        if (proto == 0)
            return pkt_type;

        if ((layers & CNE_PTYPE_INNER_L4_MASK) == 0)
            return pkt_type;

        if (frag) {
            pkt_type |= CNE_PTYPE_INNER_L4_FRAG;
            hdr_lens->inner_l4_len = 0;
            return pkt_type;
        }
        pkt_type |= ptype_inner_l4(proto);
    }

    if ((pkt_type & CNE_PTYPE_INNER_L4_MASK) == CNE_PTYPE_INNER_L4_UDP) {
        hdr_lens->inner_l4_len = sizeof(struct cne_udp_hdr);
    } else if ((pkt_type & CNE_PTYPE_INNER_L4_MASK) == CNE_PTYPE_INNER_L4_TCP) {
        const struct cne_tcp_hdr *th;

        th = pktmbuf_mtod_offset(m, struct cne_tcp_hdr *, off);
        if (unlikely(th == NULL))
            return pkt_type & (CNE_PTYPE_INNER_L2_MASK | CNE_PTYPE_INNER_L3_MASK);
        hdr_lens->inner_l4_len = (th->data_off & 0xf0) >> 2;
    } else if ((pkt_type & CNE_PTYPE_INNER_L4_MASK) == CNE_PTYPE_INNER_L4_SCTP) {
        hdr_lens->inner_l4_len = sizeof(struct cne_sctp_hdr);
    } else {
        hdr_lens->inner_l4_len = 0;
    }

    return pkt_type;
}
