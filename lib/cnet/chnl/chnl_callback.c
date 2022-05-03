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
#include <net/cne_udp.h>
#include <cne_log.h>          // for CNE_LOG, CNE_LOG_DEBUG
#include <cnet_ipv4.h>        // for IPv4_VER_LEN_VALUE
#include <mempool.h>          // for mempool_t
#include <pktdev.h>           // for pktdev_rx_burst
#include <pktmbuf.h>          // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include "chnl_priv.h"
#include <cnet_chnl.h>        // for cnet_chnl_get
#include <cnet_node_names.h>

static inline void
__callback(struct pcb_entry *pcb)
{
    if (pcb->ch->ch_callback) {
        chnl_type_t ctype = (pcb->ip_proto == IPPROTO_TCP) ? CHNL_TCP_RECV_TYPE
                                                           : CHNL_UDP_RECV_TYPE;

        pcb->ch->ch_callback(ctype, pcb->ch->ch_cd);
    }
}

static uint16_t
chnl_callback_node_process(struct cne_graph *graph __cne_unused, struct cne_node *node __cne_unused,
                           void **objs, uint16_t nb_objs)
{
    pktmbuf_t *mbuf, **pkts;
    struct pcb_entry *pcb, *ppcb = NULL;
    uint16_t n_left_from;
    struct chnl_buf *cb;

    pkts        = (pktmbuf_t **)objs;
    n_left_from = nb_objs;

    if (n_left_from >= 4) {
        cne_prefetch0(pkts[0]);
        cne_prefetch0(pkts[1]);
        cne_prefetch0(pkts[2]);
        cne_prefetch0(pkts[3]);
    }

    while (n_left_from > 0) {
        if (likely(n_left_from > 3))
            cne_prefetch0(pkts[4]);

        mbuf = pkts[0];

        pkts++;
        n_left_from--;

        pcb = mbuf->userptr;
        if (!pcb || !pcb->ch) {
            pktmbuf_free(mbuf);
            CNE_ERR("PCB or Chnl pointer is NULL\n");
            continue;
        }
        if (!ppcb)
            ppcb = pcb;
        else if (ppcb != pcb) {
            __callback(ppcb);
            ppcb = pcb;
        }

        cb = &pcb->ch->ch_rcv;
        vec_add(cb->cb_vec, mbuf);
        cb->cb_cc += pktmbuf_data_len(mbuf);
    }

    if (ppcb)
        __callback(ppcb);

    return nb_objs;
}

static int
chnl_callback_node_init(const struct cne_graph *graph __cne_unused,
                        struct cne_node *node __cne_unused)
{
    return 0;
}

static struct cne_node_register chnl_callback_node_base = {
    .process = chnl_callback_node_process,
    .name    = CHNL_CALLBACK_NODE_NAME,

    .init = chnl_callback_node_init,

    .nb_edges   = 0,
    .next_nodes = {},
};

CNE_NODE_REGISTER(chnl_callback_node_base);
