/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <cnet_nd6.h>
#include <net/cne_ip.h>        // for cne_ipv6_hdr
#include <cnet_icmp6.h>
#include <icmp6_input_priv.h>
#include <icmp6_output_priv.h>
#include "ip6_flowlabel.h"

/* ND output functions */
static inline void
nd6_send_rs(void)
{
    CNE_DEBUG("Not implemented yet\n");
}

static inline void
nd6_send_ra(void)
{
    CNE_DEBUG("Not implemented yet\n");
}

void
nd6_send_ns(struct cne_graph *graph, struct cne_node *node, struct in6_addr *src_addr,
            struct in6_addr *target, bool verify_reach)
{
    /*
     * The NS msg is sent to solicited-node multicast address corresponding to the
     * target address
     */
    struct netif *nif;
    struct cne_ipv6_hdr *ip6;
    struct nd_neighbor_solicit *ns_pkt;
    uint32_t tclass = 0, flw_label = 0;
    struct nd_opt_hdr *nopt;
    uint32_t optlen = 0;
    pktmbuf_t *mbuf;
    cne_edge_t nxt;

    nxt = ICMP6_OUTPUT_NEXT_IP6_OUTPUT;
    nif = cnet6_netif_match_subnet(src_addr);
    if (nif == NULL)
        return;

    /* Get pktmbuf and assign to ip6, ns_pkt & nopt */
    if (pktdev_buf_alloc(nif->lpid, &mbuf, 1) == 0)
        CNE_RET("Unable to allocate packet buffer\n");

    mbuf->l3_len = sizeof(struct cne_ipv6_hdr);

    ip6 = (struct cne_ipv6_hdr *)pktmbuf_prepend(mbuf, mbuf->l3_len);
    if (!ip6)
        return;
    ns_pkt = pktmbuf_mtod(mbuf, struct nd_neighbor_solicit *);
    /* Populate icmp6 and NS header */
    ns_pkt->nd_ns_type     = ND_NEIGHBOR_SOLICIT;
    ns_pkt->nd_ns_code     = 0;
    ns_pkt->nd_ns_cksum    = 0;
    ns_pkt->nd_ns_reserved = 0;
    inet6_addr_copy(&ns_pkt->nd_ns_target, target);

    if (cnet_ipv6_ipaddr_find(nif, src_addr)) {
        nopt              = (struct nd_opt_hdr *)ns_pkt + sizeof(struct nd_neighbor_solicit) + 1;
        nopt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
        nopt->nd_opt_len  = sizeof(struct nd_opt_hdr) + sizeof(struct ether_addr);
        memcpy(nopt + 1, &nif->mac, sizeof(struct ether_addr));
        optlen = nopt->nd_opt_len;
    }

    /* Populate ipv6 header */
    ip6_flow_hdr(ip6, tclass, flw_label);
    ip6->payload_len = htons(sizeof(struct nd_neighbor_solicit) + optlen);
    ip6->proto       = IPPROTO_ICMPV6;
    ip6->hop_limits  = 255;
    /* ipv6 addr of this host's interface through which this packet will be sent*/
    inet6_addr_copy((struct in6_addr *)&ip6->src_addr, src_addr);
    /*
     * Neighbor Solicitations are multicast when the node needs
     * to resolve an address and unicast when the node seeks to verify the
     * reachability of a neighbor.
     */
    if (verify_reach)
        inet6_addr_copy((struct in6_addr *)&ip6->dst_addr, target);
    else
        inet6_ns_multicast_addr((struct in6_addr *)&ip6->dst_addr, target);

    ns_pkt->nd_ns_cksum = cne_ipv6_icmpv6_cksum(ip6, ns_pkt);

    cnet_nd6_add(nif->netif_idx, target, NULL, ND_INCOMPLETE); /* Create a nd6 cache entry */

    /* Send it now */
    cne_node_enqueue_x1(graph, node, nxt, mbuf);
}

static inline void
nd6_send_na(struct cne_graph *graph, struct cne_node *node, struct in6_addr *src_addr,
            struct in6_addr *target, uint32_t flags, struct in6_addr *invoke_src)
{
    struct cne_ipv6_hdr *ip6;
    struct nd_neighbor_advert *na_pkt = NULL;
    uint32_t tclass = 0, flw_label = 0;
    struct nd_opt_hdr *nopt;
    uint32_t optlen = 0;
    pktmbuf_t *mbuf;
    struct netif *nif;
    cne_edge_t nxt;

    nxt = ICMP6_OUTPUT_NEXT_IP6_OUTPUT;

    nif = cnet6_netif_match_subnet(target);
    if (nif == NULL)
        return;

    /* Get pktmbuf and assign to ip6, na_pkt & nopt */
    if (pktdev_buf_alloc(nif->lpid, &mbuf, 1) == 0)
        CNE_RET("Unable to allocate packet buffer\n");
    mbuf->l3_len = sizeof(struct cne_ipv6_hdr);

    ip6 = (struct cne_ipv6_hdr *)pktmbuf_prepend(mbuf, mbuf->l3_len);
    if (!ip6)
        return;
    na_pkt = pktmbuf_mtod(mbuf, struct nd_neighbor_advert *);
    /* Populate icmp6 and NS header */
    na_pkt->nd_na_type           = ND_NEIGHBOR_ADVERT;
    na_pkt->nd_na_code           = 0;
    na_pkt->nd_na_cksum          = 0;
    na_pkt->nd_na_flags_reserved = flags;
    inet6_addr_copy(&na_pkt->nd_na_target, target); /* For solicited
       advertisements, the Target Address field in the Neighbor Solicitation
       message that prompted this advertisement. For an unsolicited advertisement,
       the address whose link-layer address has changed. The Target Address MUST
       NOT be a multicast address.*/

    if (cnet_ipv6_ipaddr_find(nif, target)) {
        nopt              = (struct nd_opt_hdr *)na_pkt + sizeof(struct nd_neighbor_advert) + 1;
        nopt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
        nopt->nd_opt_len  = sizeof(struct nd_opt_hdr) + sizeof(struct ether_addr);
        /* We are sending ND_OPT_TARGET_LINKADDR even if the dst addr of incoming NS packet i.e.
         * src_addr is a multicast. Though it's not necessary in case of multicast as per RFC 4861,
         * section 7.2.4.
         */
        memcpy(nopt + 1, &nif->mac, sizeof(struct ether_addr));
        optlen = nopt->nd_opt_len;
    }

    /* Populate ipv6 header */
    ip6_flow_hdr(ip6, tclass, flw_label);
    ip6->payload_len = htons(sizeof(struct nd_neighbor_advert) + optlen);
    ip6->proto       = IPPROTO_ICMPV6;
    ip6->hop_limits  = 255;
    /* ipv6 addr of this host's interface through which this packet will be sent
     */
    if (inet6_is_multicast_addr(
            src_addr)) /* src_addr was the destination addr for incoming NS packet */
        inet6_addr_copy((struct in6_addr *)&ip6->src_addr, target);
    else
        inet6_addr_copy((struct in6_addr *)&ip6->src_addr, src_addr);

    /* Fill with ipv6 addr of Source Address of an invoking
     * Neighbor Solicitation or all-nodes multicast address.
     */
    if (invoke_src)
        inet6_addr_copy((struct in6_addr *)&ip6->dst_addr, invoke_src);
    else
        inet6_all_node_multicast_addr((struct in6_addr *)&ip6->dst_addr);

    na_pkt->nd_na_cksum = cne_ipv6_icmpv6_cksum(ip6, na_pkt);

    /* Send it now */
    cne_node_enqueue_x1(graph, node, nxt, mbuf);
}

static inline void
nd6_send_redirect(void)
{
    CNE_DEBUG("Not implemented yet\n");
}

/* ND6 input functions */
static inline uint16_t
nd6_process_rs(icmp6ip_t *iip)
{
    CNE_SET_USED(iip);

    CNE_DEBUG("Not implemented yet\n");
    return ICMP6_INPUT_NEXT_PKT_DROP;
}

static inline uint16_t
nd6_process_ra(icmp6ip_t *iip)
{
    CNE_SET_USED(iip);

    CNE_DEBUG("Not implemented yet\n");
    return ICMP6_INPUT_NEXT_PKT_DROP;
}

static inline uint16_t
nd6_process_ns(struct cne_graph *graph, struct cne_node *node, icmp6ip_t *iip)
{
    struct nd_neighbor_solicit *ns_pkt;
    struct nd_opt_hdr *nopt;
    struct in6_addr *src_ip = NULL;
    cne_edge_t nxt;

    nxt = ICMP6_INPUT_NEXT_PKT_DROP;

    ns_pkt = (struct nd_neighbor_solicit *)&iip->icmp6;

    src_ip = (struct in6_addr *)&iip->ip6.dst_addr;
    if (inet6_is_unspec_addr((struct in6_addr *)&iip->ip6.src_addr))
        nd6_send_na(graph, node, src_ip, &ns_pkt->nd_ns_target, 0, NULL);
    else {
        nopt = (struct nd_opt_hdr *)iip + sizeof(icmp6ip_t) + 1;
        if (nopt->nd_opt_type == ND_OPT_SOURCE_LINKADDR) /* Update nd6 cache entry */
            cnet_nd6_update((struct in6_addr *)&iip->ip6.src_addr,
                            (struct ether_addr *)nopt + sizeof(struct nd_opt_hdr) + 1, ND_STALE,
                            NULL);

        nd6_send_na(graph, node, src_ip, &ns_pkt->nd_ns_target, ND_NA_FLAG_SOLICITED,
                    (struct in6_addr *)&iip->ip6.src_addr);
    }

    /* If the Target Address is an anycast address, the sender SHOULD
     * delay sending a response for a random time between 0 and
     * MAX_ANYCAST_DELAY_TIME seconds.
     * Note:- This is not implemented yet.
     */

    return nxt;
}

static inline uint16_t
nd6_process_na(icmp6ip_t *iip)
{
    struct nd_neighbor_advert *na_pkt;
    struct nd6_cache_entry *entry;
    struct nd_opt_hdr *nopt;
    struct ether_addr *mac = NULL;
    bool routerFlag;
    cne_edge_t nxt;

    nxt = ICMP6_INPUT_NEXT_PKT_DROP;

    na_pkt = (struct nd_neighbor_advert *)&iip->icmp6;

    entry = cnet_nd6_entry_lookup(&na_pkt->nd_na_target);

    if (!entry)
        return nxt; /* Discard it */

    if (entry->reach_state == ND_INCOMPLETE) {

        nopt = (struct nd_opt_hdr *)iip + sizeof(icmp6ip_t) + 1;
        if (nopt->nd_opt_type != ND_OPT_TARGET_LINKADDR) /* Update nd6 cache entry */
            return nxt;                                  /* Discard it */
        mac        = (struct ether_addr *)nopt + sizeof(struct nd_opt_hdr) + 1;
        routerFlag = (na_pkt->nd_na_flags_reserved & ND_NA_FLAG_ROUTER);
        if (na_pkt->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED)
            cnet_nd6_update(&na_pkt->nd_na_target, mac, ND_REACHABLE, &routerFlag);
        else
            cnet_nd6_update(&na_pkt->nd_na_target, mac, ND_STALE, &routerFlag);

        /* As per RFC 4861 ideally any packets queued in entry->ar_packets_queue which are awaiting
         * for the neighbor address resolution to complete are sent after arrival of corresponding
         NA.
         * e.g.
            pktmbuf_t *quedPkts    = NULL;
            quedPkts = entry->ar_packets_queue;
            while (quedPkts) {
                cne_node_enqueue_x1(graph, node, nxt, quedPkts);
                //Now process next packet in the queue
            }
         * But in this implementation ar_packets_queue is NULL and we make
         nd6_request_process_mbuf()
         * send such packets to kernel without making them wait.
         */
    } else {

        if (!(na_pkt->nd_na_flags_reserved & ND_NA_FLAG_OVERRIDE)) {
            if (!ether_addr_is_same(mac, &entry->ll_addr)) {
                if (entry->reach_state == ND_REACHABLE)
                    cnet_nd6_update(&na_pkt->nd_na_target, NULL, ND_STALE, NULL);
                else
                    return nxt; /* Ignore the packet */
            }

        } else {
            if (!ether_addr_is_same(mac, &entry->ll_addr)) {
                if (na_pkt->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED)
                    cnet_nd6_update(&na_pkt->nd_na_target, mac, ND_REACHABLE, NULL);
                else
                    cnet_nd6_update(&na_pkt->nd_na_target, mac, ND_STALE, NULL);
            }
        }
    }

    return nxt;
}

static inline uint16_t
nd6_process_redirect(icmp6ip_t *iip)
{
    CNE_SET_USED(iip);
    CNE_DEBUG("Not implemented yet\n");
    return ICMP6_INPUT_NEXT_PKT_DROP;
}

/* Message Validations */

static inline void
nd6_validate_rs(void)
{
    /* Hosts MUST silently discard any received Router Solicitation
    Messages. */

    /*
    A router MUST silently discard any received Router Solicitation
    messages that do not satisfy all of the following validity checks:

    - The IP Hop Limit field has a value of 255, i.e., the packet
    could not possibly have been forwarded by a router.
    - ICMP Checksum is valid.
    - ICMP Code is 0.
    - ICMP length (derived from the IP length) is 8 or more octets.
    - All included options have a length that is greater than zero.
    - If the IP source address is the unspecified address, there is no
    source link-layer address option in the message.
     */

    CNE_DEBUG("Not implemented yet\n");
}

static inline void
nd6_validate_ra(void)
{
    /*
     node MUST silently discard any received Router Advertisement
    messages that do not satisfy all of the following validity checks:
    - IP Source Address is a link-local address. Routers must use
    their link-local address as the source for Router Advertisement
    and Redirect messages so that hosts can uniquely identify
    routers.
    - The IP Hop Limit field has a value of 255, i.e., the packet
    could not possibly have been forwarded by a router.
    - ICMP Checksum is valid.
    - ICMP Code is 0.
    - ICMP length (derived from the IP length) is 16 or more octets.
    - All included options have a length that is greater than zero.
    */

    CNE_DEBUG("Not implemented yet\n");
}

static inline bool
nd6_validate_ns(icmp6ip_t *iip)
{
    /*
    A node MUST silently discard any received Neighbor Solicitation
    messages that do not satisfy all of the following validity checks:
    - The IP Hop Limit field has a value of 255, i.e., the packet
    could not possibly have been forwarded by a router.
    - ICMP Checksum is valid.
    - ICMP Code is 0.
    - ICMP length (derived from the IP length) is 24 or more octets.
    - Target Address is not a multicast address.
    - All included options have a length that is greater than zero.
    - If the IP source address is the unspecified address, the IP
    destination address is a solicited-node multicast address.
    - If the IP source address is the unspecified address, there is no
    source link-layer address option in the message.
    */

    uint16_t payloadLen, optLen;

    if (iip->ip6.hop_limits != 255)
        return false;

    if (cne_ipv6_icmpv6_cksum_verify((const struct cne_ipv6_hdr *)&iip->ip6,
                                     (const void *)&iip->icmp6))
        return false; /* Checksum failed */

    if (iip->icmp6.icmp6_code != 0)
        return false;

    payloadLen = ntohs(iip->ip6.payload_len);
    if (payloadLen < ND6_NS_MIN_PKT_LEN)
        return false;

    struct nd_neighbor_solicit *ns_pkt = (struct nd_neighbor_solicit *)&iip->icmp6;

    if (inet6_is_multicast_addr(&ns_pkt->nd_ns_target))
        return false;

    optLen = payloadLen - ND6_NS_MIN_PKT_LEN;
    if (optLen < 1)
        return false;

    struct nd_opt_hdr *nopt = (struct nd_opt_hdr *)iip + sizeof(struct nd_neighbor_solicit) + 1;

    if (inet6_is_unspec_addr((struct in6_addr *)&iip->ip6.src_addr)) {
        if (!inet6_is_ns_multicast_addr((struct in6_addr *)&iip->ip6.dst_addr))
            return false;

        if (nopt->nd_opt_type == ND_OPT_SOURCE_LINKADDR)
            return false;
    }

    return true;
}

static inline bool
nd6_validate_na(icmp6ip_t *iip)
{
    /*
    A node MUST silently discard any received Neighbor Advertisement
    messages that do not satisfy all of the following validity checks:
    - The IP Hop Limit field has a value of 255, i.e., the packet
    could not possibly have been forwarded by a router.
    - ICMP Checksum is valid.
    - ICMP Code is 0.
    - ICMP length (derived from the IP length) is 24 or more octets.
    - Target Address is not a multicast address.
    - If the IP Destination Address is a multicast address the
    Solicited flag is zero.
    - All included options have a length that is greater than zero.
    */
    uint16_t payloadLen, optLen;

    if (iip->ip6.hop_limits != 255)
        return false;

    if (cne_ipv6_icmpv6_cksum_verify((const struct cne_ipv6_hdr *)&iip->ip6,
                                     (const void *)&iip->icmp6))
        return false; /* Checksum failed */

    if (iip->icmp6.icmp6_code != 0)
        return false;

    payloadLen = ntohs(iip->ip6.payload_len);
    if (payloadLen < ND6_NA_MIN_PKT_LEN)
        return false;

    struct nd_neighbor_advert *na_pkt = (struct nd_neighbor_advert *)&iip->icmp6;

    if (inet6_is_multicast_addr(&na_pkt->nd_na_target))
        return false;

    if (inet6_is_multicast_addr((struct in6_addr *)iip->ip6.dst_addr)) {
        if (na_pkt->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED)
            return false;
    }

    optLen = payloadLen - ND6_NS_MIN_PKT_LEN;
    if (optLen < 1)
        return false;

    return true;
}

static inline void
nd6_validate_redirect(void)
{
    CNE_DEBUG("Not implemented yet\n");
}

uint16_t
nd6_recv_requests(struct cne_graph *graph, struct cne_node *node, icmp6ip_t *iip)
{
    uint16_t nxt;

    switch (iip->icmp6.icmp6_type) {

    case ND_ROUTER_SOLICIT:

        /* Process Router Solicitation (RS) message */
        nxt = nd6_process_rs(iip);
        break;

    case ND_ROUTER_ADVERT:
        /* Process Router Advertisement (RA) message */
        nxt = nd6_process_ra(iip);
        break;

    case ND_NEIGHBOR_SOLICIT:
        if (!nd6_validate_ns(iip))
            return ICMP6_INPUT_NEXT_PKT_DROP; /* Not valid, drop the packet */
        /* Process Neighbor Solicitation (NS) message */
        nxt = nd6_process_ns(graph, node, iip);

        break;

    case ND_NEIGHBOR_ADVERT:
        if (!nd6_validate_na(iip))
            return ICMP6_INPUT_NEXT_PKT_DROP; /* Not valid, drop the packet */
        /* Process Neighbor Advertisement (NA) message */
        nxt = nd6_process_na(iip);
        break;

    case ND_REDIRECT:
        /* Process Redirect message */
        nxt = nd6_process_redirect(iip);

        break;
    }

    return nxt;
}

static inline void
nd6_init(void)
{
    CNE_DEBUG("All ND6 initializations\n");
}

/* ND6 Utility functions */

const char *
nd6_get_state(struct nd6_cache_entry *entry)
{
    switch (entry->reach_state) {
    case ND_INCOMPLETE:
        return "Incomplete";
    case ND_REACHABLE:
        return "Reachable";
    case ND_STALE:
        return "Stale";
    case ND_DELAY:
        return "Delay";
    case ND_PROBE:
        return "Probe";
    }

    return "";
}
