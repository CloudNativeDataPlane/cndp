/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright (c) 2020-2022 Intel Corporation.
 */

#include <stdint.h>        // for uint32_t
#include <pktmbuf_ptype.h>
#include <stdio.h>        // for snprintf

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
