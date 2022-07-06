/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

#include <net/cne_ether.h>        // for ether_addr_copy, cne_ether_hdr, ether_ad...
#include <cnet.h>                 // for cnet_add_instance, cnet, per_thread_cnet
#include <cnet_stk.h>             // for proto_in_ifunc
#include <cne_inet.h>             // for inet_ntop4, CIN_ADDR
#include <cnet_drv.h>             // for drv_entry
#include <cnet_route.h>           // for
#include <cnet_arp.h>             // for arp_entry
#include <cnet_netif.h>           // for netif, cnet_ipv4_compare
#include <netinet/in.h>           // for ntohs
#include <stddef.h>               // for NULL

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_common.h>              // for __cne_unused
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <net/cne_tcp.h>
#include <cne_log.h>          // for CNE_LOG, CNE_LOG_DEBUG
#include <cnet_ipv4.h>        // for IPv4_VER_LEN_VALUE
#include <mempool.h>          // for mempool_t
#include <pktdev.h>           // for pktdev_rx_burst
#include <pktmbuf.h>          // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cnet_tcp.h>
#include <cnet_meta.h>

#include <cnet_node_names.h>
#include "tcp_input_priv.h"

/* The TCP/IP Pseudo header */
typedef struct tcpip4_s {
    struct cne_ipv4_hdr ip4; /* IPv4 header */
    struct cne_tcp_hdr tcp;  /* TCP header */
} __cne_packed tcpip4_t;

static inline uint16_t
tcp_input_lookup(struct cne_node *node, pktmbuf_t *m, struct pcb_hd *hd)
{
    struct cnet *cnet = this_cnet;
    tcpip4_t *tip;
    struct pcb_key key = {0};
    struct pcb_entry *pcb;
    struct cnet_metadata *md;

    md = pktmbuf_metadata(m);
    if (!md)
        return TCP_INPUT_NEXT_PKT_DROP;

    tip = pktmbuf_mtod(m, struct tcpip4_s *);

    /* Convert this into AVX instructions */
    in_caddr_update(&key.faddr, AF_INET, sizeof(struct in_addr), tip->tcp.src_port);
    key.faddr.cin_addr.s_addr = tip->ip4.src_addr;
    in_caddr_update(&key.laddr, AF_INET, sizeof(struct in_addr), tip->tcp.dst_port);
    key.laddr.cin_addr.s_addr = tip->ip4.dst_addr;

    md->faddr.cin_port = be16toh(tip->tcp.src_port);
    md->laddr.cin_port = be16toh(tip->tcp.dst_port);

    /* Create a 4x PCB lookup routine */
    pcb = cnet_pcb_lookup(hd, &key, BEST_MATCH);
    if (likely(pcb)) {
        int rc = TCP_INPUT_NEXT_PKT_DROP;

        if (cne_ipv4_udptcp_cksum_verify(&tip->ip4, &tip->tcp))
            return rc;

        m->userptr = pcb;
        in_caddr_copy(&md->faddr, &key.faddr); /* Save the foreign address */
        in_caddr_copy(&md->laddr, &key.laddr); /* Save the local address */

        /* returns one of the TCP_INPUT_NEXT_* values */
        rc = cnet_tcp_input(pcb, m);

        CNE_DEBUG("cnet_tcp_input() returned [orange]%s[]\n", node->nodes[rc]->name);

        return rc;
    }

    CNE_DEBUG("PCB lookup failed (%s)\n", (cnet->flags & CNET_PUNT_ENABLED) ? "Punt" : "Drop");
    return (cnet->flags & CNET_PUNT_ENABLED) ? TCP_INPUT_NEXT_PKT_PUNT : TCP_INPUT_NEXT_PKT_DROP;
}

static uint16_t
tcp_input_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                       uint16_t nb_objs)
{
    pktmbuf_t *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
    cne_edge_t next0, next1, next2, next3, next_index;
    void **to_next, **from;
    struct pcb_hd *hd  = &this_stk->tcp->tcp_hd;
    uint16_t last_spec = 0;
    uint16_t n_left_from;
    uint16_t held = 0;

    next_index = TCP_INPUT_NEXT_CHNL_RECV;

    pkts        = (pktmbuf_t **)objs;
    from        = objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        for (int i = 0; i < 4; i++)
            cne_prefetch0(pktmbuf_mtod_offset(pkts[i], void *, sizeof(struct cne_ether_hdr)));
    }

    /* Get stream for the speculated next node */
    to_next = cne_node_next_stream_get(graph, node, next_index, nb_objs);
    while (n_left_from >= 4) {
        /* Prefetch next-next mbufs */
        if (likely(n_left_from > 11)) {
            cne_prefetch0(pkts[8]);
            cne_prefetch0(pkts[9]);
            cne_prefetch0(pkts[10]);
            cne_prefetch0(pkts[11]);
        }

        /* Prefetch next mbuf data */
        if (likely(n_left_from > 7)) {
            cne_prefetch0(pktmbuf_mtod_offset(pkts[4], void *, pkts[4]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[5], void *, pkts[5]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[6], void *, pkts[6]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[7], void *, pkts[7]->l2_len));
        }

        mbuf0 = pkts[0];
        mbuf1 = pkts[1];
        mbuf2 = pkts[2];
        mbuf3 = pkts[3];

        pkts += 4;
        n_left_from -= 4;

        next0 = tcp_input_lookup(node, mbuf0, hd);
        next1 = tcp_input_lookup(node, mbuf1, hd);
        next2 = tcp_input_lookup(node, mbuf2, hd);
        next3 = tcp_input_lookup(node, mbuf3, hd);

        /* Enqueue four to next node */
        cne_edge_t fix_spec = (next_index ^ next0) | (next_index ^ next1) | (next_index ^ next2) |
                              (next_index ^ next3);

        if (unlikely(fix_spec)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            /* Next0 */
            if (next_index == next0) {
                to_next[0] = from[0];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next0, from[0]);

            /* Next1 */
            if (next_index == next1) {
                to_next[0] = from[1];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next1, from[1]);

            /* Next2 */
            if (next_index == next2) {
                to_next[0] = from[2];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next2, from[2]);

            /* Next3 */
            if (next_index == next3) {
                to_next[0] = from[3];
                to_next++;
                held++;
            } else
                cne_node_enqueue_x1(graph, node, next3, from[3]);

            from += 4;

        } else
            last_spec += 4;
    }

    while (n_left_from > 0) {
        mbuf0 = pkts[0];

        pkts += 1;
        n_left_from -= 1;

        next0 = tcp_input_lookup(node, mbuf0, hd);

        if (unlikely(next_index ^ next0)) {
            /* Copy things successfully speculated till now */
            memcpy(to_next, from, last_spec * sizeof(from[0]));
            from += last_spec;
            to_next += last_spec;
            held += last_spec;
            last_spec = 0;

            cne_node_enqueue_x1(graph, node, next0, from[0]);
            from += 1;
        } else
            last_spec += 1;
    }

    /* !!! Home run !!! */
    if (likely(last_spec == nb_objs)) {
        cne_node_next_stream_move(graph, node, next_index);
        return nb_objs;
    }

    held += last_spec;

    /* Copy things successfully speculated till now */
    memcpy(to_next, from, last_spec * sizeof(from[0]));
    cne_node_next_stream_put(graph, node, next_index, held);

    return nb_objs;
}

static struct cne_node_register tcp_input_node_base = {
    .process = tcp_input_node_process,
    .name    = TCP_INPUT_NODE_NAME,

    .nb_edges = TCP_INPUT_NEXT_MAX,
    .next_nodes =
        {
            [TCP_INPUT_NEXT_PKT_DROP]  = PKT_DROP_NODE_NAME,
            [TCP_INPUT_NEXT_CHNL_RECV] = CHNL_RECV_NODE_NAME,
            [TCP_INPUT_NEXT_PKT_PUNT]  = PUNT_KERNEL_NODE_NAME,
        },
};

CNE_NODE_REGISTER(tcp_input_node_base);
