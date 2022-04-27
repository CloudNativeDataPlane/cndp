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
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_common.h>              // for __cne_unused
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <cne_vec.h>                 // for vec_len, vec_ptr_at_index, vec_next_mbuf_pre...
#include <cnet_ipv4.h>               // for IPv4_VER_LEN_VALUE
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cne_vec.h>        // for
#include <cnet_fib_info.h>
#include <cnet_eth.h>
#include <net/cne_udp.h>
#include <sys/uio.h>
#include <net/cne_net.h>
#include <linux/if_tun.h>
#include "ptype_priv.h"        // for PTYPE_NEXT_IP4_LOOKUP, PTYPE_...

#include <cnet_node_names.h>
#include "kernel_recv_priv.h"
#include "tun_alloc.h"

static inline void
mbuf_update(pktmbuf_t **mbufs, uint16_t nb_pkts)
{
    struct cne_net_hdr_lens hdr_lens;
    struct cne_ether_hdr *eth_hdr;
    pktmbuf_t *m;

    for (int i = 0; i < nb_pkts; i++) {
        m = mbufs[i];

        eth_hdr = pktmbuf_mtod(m, struct cne_ether_hdr *);

        m->packet_type = cne_get_ptype(m, &hdr_lens, CNE_PTYPE_ALL_MASK);

        m->ol_flags = 0;

        if (eth_hdr->ether_type == __ETHER_TYPE_IPV6)
            m->ol_flags |= CNE_MBUF_TYPE_IPv6;

        if (ether_addr_is_broadcast(&eth_hdr->d_addr))
            m->ol_flags |= CNE_MBUF_TYPE_BCAST;
        else if (ether_addr_is_multicast(&eth_hdr->d_addr))
            m->ol_flags |= CNE_MBUF_TYPE_MCAST;

        m->tx_offload = 0;
        m->l2_len     = hdr_lens.l2_len;
        m->l3_len     = hdr_lens.l3_len;
        m->l4_len     = hdr_lens.l4_len;

        /* When the packet is sent to an output port, we need to copy
         * the packet into a buffer. This needs to be handled in xskdev. */
        m->lport = CNE_MBUF_INVALID_PORT;
    }
}

static uint16_t
recv_pkt_parse(void **objs, uint16_t nb_pkts)
{
    uint16_t n_left_from;
    pktmbuf_t **pkts;

    pkts        = (pktmbuf_t **)objs;
    n_left_from = nb_pkts;

    if (n_left_from >= 4) {
        for (int i = 0; i < 4; i++)
            cne_prefetch0(pktmbuf_mtod(pkts[i], void *));
    }

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
            cne_prefetch0(pktmbuf_mtod(pkts[4], void *));
            cne_prefetch0(pktmbuf_mtod(pkts[5], void *));
            cne_prefetch0(pktmbuf_mtod(pkts[6], void *));
            cne_prefetch0(pktmbuf_mtod(pkts[7], void *));
        }

        /* Extract ptype of mbuf0, mbuf1, mbuf2, mbuf3 */
        mbuf_update(pkts, 4);

        pkts += 4;
        n_left_from -= 4;
    }

    if (n_left_from > 0)
        mbuf_update(pkts, n_left_from);

    return nb_pkts;
}

static uint16_t
kernel_recv_node_do(struct cne_graph *graph, struct cne_node *node, kernel_recv_node_ctx_t *ctx)
{
    uint16_t len = 0, count = 0, nb_pkts;
    int fd;

    if (!ctx)
        return 0;

    if ((fd = tun_get_fd(ctx->tinfo)) > 0) {
        pktmbuf_t **mbufs;

        /* Get pkts from port */
        nb_pkts = (node->size >= CNE_GRAPH_BURST_SIZE) ? CNE_GRAPH_BURST_SIZE : node->size;

        if (pktmbuf_alloc_bulk(ctx->pi, (pktmbuf_t **)node->objs, nb_pkts) < 0)
            return 0;

        mbufs = (pktmbuf_t **)node->objs;
        for (;;) {
            pktmbuf_t *m = mbufs[0];
            struct iovec vec;

            vec.iov_base = pktmbuf_mtod(m, void *);
            vec.iov_len  = pktmbuf_tailroom(m);

            len = readv(fd, &vec, 1);
            if (len == 0 || len == 0xFFFF)
                break;

            count++;

            pktmbuf_data_len(m) = len;
            mbufs++;
        }

        if (count < nb_pkts)
            pktmbuf_free_bulk(mbufs, nb_pkts - count);

        if (count) {
            recv_pkt_parse(node->objs, count);
            node->idx = count;

            /* Enqueue to next node */
            cne_node_next_stream_move(graph, node, KERNEL_RECV_NEXT_PTYPE);
        }

        return count;
    }

    return 0;
}

static uint16_t
kernel_recv_node_process(struct cne_graph *graph, struct cne_node *node, void **objs,
                         uint16_t nb_objs)
{
    kernel_recv_node_ctx_t *ctx = (kernel_recv_node_ctx_t *)node->ctx;
    int fd;

    CNE_SET_USED(objs);
    CNE_SET_USED(nb_objs);

    if (!ctx)
        return 0;

    if ((fd = tun_get_fd(ctx->tinfo)) > 0) {
        struct pollfd fds = {.fd = fd, .events = POLLIN};

        if (poll(&fds, 1, 0) > 0) {
            if (fds.revents & POLLIN)
                return kernel_recv_node_do(graph, node, ctx);
        }
    }

    return 0;
}

static int
kernel_recv_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    kernel_recv_node_ctx_t *ctx = (kernel_recv_node_ctx_t *)node->ctx;
    pktmbuf_info_t *pi;
    mmap_t *mm;

    if (!ctx)
        CNE_ERR_RET("Node context pointer is NULL\n");

    ctx->tinfo = tun_alloc(IFF_TUN | IFF_NO_PI, "krecv%d");
    if (!ctx->tinfo)
        CNE_ERR_RET("Unable to open TUN/TAP socket\n");

    /* Allocate a memory region and pktmbuf info structure to be used in receiving
     * packets from the kernel */
    mm = mmap_alloc(KERN_RECV_MBUF_COUNT, DEFAULT_MBUF_SIZE, MMAP_HUGEPAGE_DEFAULT);
    if (!mm) {
        tun_free(ctx->tinfo);
        CNE_ERR_RET("mmap_alloc() failed\n");
    }

    pi = pktmbuf_pool_create(mmap_addr(mm), KERN_RECV_MBUF_COUNT, DEFAULT_MBUF_SIZE, 0, NULL);
    if (!pi) {
        mmap_free(mm);
        tun_free(ctx->tinfo);
        CNE_ERR_RET("pktmbuf_pool_create() failed\n");
    }
    pktmbuf_info_name_set(pi, tun_get_name(ctx->tinfo));
    ctx->pi = pi;

    tun_dump(NULL, ctx->tinfo);
    return 0;
}

static struct cne_node_register kernel_recv_node_base = {
    .process = kernel_recv_node_process,
    .flags   = CNE_NODE_SOURCE_F,
    .name    = KERNEL_RECV_NODE_NAME,

    .init = kernel_recv_node_init,

    .nb_edges = KERNEL_RECV_NEXT_MAX,
    .next_nodes =
        {
            [KERNEL_RECV_NEXT_PTYPE] = PTYPE_NODE_NAME,
        },
};

struct cne_node_register *
kernel_recv_node_get(void)
{
    return &kernel_recv_node_base;
}

CNE_NODE_REGISTER(kernel_recv_node_base);
