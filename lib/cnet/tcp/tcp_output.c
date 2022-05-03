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

#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>
#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_common.h>              // for __cne_unused
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <net/cne_tcp.h>             // for cne_tcp_hdr
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <cnet_ipv4.h>               // for IPv4_VER_LEN_VALUE
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cnet_tcp.h>

#include <cnet_node_names.h>
#include "tcp_output_priv.h"

static inline void
tcp_enqueue(pktmbuf_t *m, struct pcb_entry *pcb)
{
    struct chnl_buf *cb;

    cb = &pcb->ch->ch_snd;

    vec_add(cb->cb_vec, m);
    cb->cb_cc += pktmbuf_data_len(m);

    pktmbuf_refcnt_update(m, 1);
    CNE_DEBUG("Add mbuf [orange]%p[] to send queue veclen %d\n", (void *)m, vec_len(cb->cb_vec));
}

static uint16_t
tcp_output_node_process(struct cne_graph *graph __cne_unused, struct cne_node *node __cne_unused,
                        void **objs, uint16_t nb_objs)
{
    pktmbuf_t *m;
    struct pcb_entry *pcb;
    struct tcb_entry *tcb = NULL;

    CNE_DEBUG(">>> Add mbufs\n");
    for (int i = 0; i < nb_objs; i++) {
        m = (pktmbuf_t *)objs[i];

        pcb = (struct pcb_entry *)m->userptr;

        tcp_enqueue(m, pcb);

        if (!tcb)
            tcb = pcb->tcb;
        else if (tcb != pcb->tcb) {
            CNE_DEBUG("TCB chagned from [orange]%p[] --> [orange]%p[]\n", tcb, pcb->tcb);
            cnet_tcp_output(tcb);
            tcb = pcb->tcb;
        }
    }

    if (tcb) {
        CNE_DEBUG("Call TCP output for TCB [orange]%p[]\n", tcb);
        cnet_tcp_output(tcb);
    }
    CNE_DEBUG("<<< Add mbufs\n");

    return nb_objs;
}

static struct cne_node_register tcp_output_node_base = {
    .process = tcp_output_node_process,
    .flags   = CNE_NODE_INPUT_F,
    .name    = TCP_OUTPUT_NODE_NAME,

    .nb_edges = TCP_OUTPUT_NEXT_MAX,
    .next_nodes =
        {
            [TCP_OUTPUT_NEXT_PKT_DROP]   = PKT_DROP_NODE_NAME,
            [TCP_OUTPUT_NEXT_IP4_OUTPUT] = IP4_OUTPUT_NODE_NAME,
        },
};

CNE_NODE_REGISTER(tcp_output_node_base);
