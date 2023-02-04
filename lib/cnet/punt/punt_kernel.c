/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
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
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/un.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stddef.h>        // for NULL
#include <sys/types.h>
#include <fcntl.h>
#include <bsd/string.h>
#include <sys/uio.h>

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_common.h>              // for __cne_unused
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <cnet_ipv4.h>               // for IPv4_VER_LEN_VALUE
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cne_vec.h>        // for
#include <cnet_fib_info.h>
#include <cnet_eth.h>
#include <net/cne_udp.h>
#include <hexdump.h>
#include <cnet_tcp.h>

#include <cnet_node_names.h>
#include "punt_kernel_priv.h"

#define PREFETCH_CNT 6

static __cne_always_inline void
punt_kernel_process_mbuf(struct cne_node *node, pktmbuf_t **mbufs, uint16_t cnt)
{
    punt_kernel_node_ctx_t *ctx = (punt_kernel_node_ctx_t *)node->ctx;

    if (ctx->sock >= 0) {
        struct cne_ipv4_hdr *ip4;
        struct sockaddr_in sin = {0};
        size_t len;
        char *buf;

        for (int i = 0; i < cnt; i++) {
            ip4 = pktmbuf_mtod(mbufs[i], struct cne_ipv4_hdr *);
            len = pktmbuf_data_len(mbufs[i]);
            buf = (char *)ip4;

            sin.sin_family      = AF_INET;
            sin.sin_port        = 0;
            sin.sin_addr.s_addr = ip4->dst_addr;

            if (sendto(ctx->sock, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
                CNE_WARN("Unable to send packets: %s\n", strerror(errno));
        }
    }
}

static uint16_t
punt_kernel_node_process(struct cne_graph *graph __cne_unused, struct cne_node *node, void **objs,
                         uint16_t nb_objs)
{
    uint16_t n_left_from;
    pktmbuf_t *mbufs[PREFETCH_CNT], **pkts;
    int k;

    pkts        = (pktmbuf_t **)objs;
    n_left_from = nb_objs;

    for (k = 0; k < PREFETCH_CNT && k < n_left_from; k++)
        cne_prefetch0(pktmbuf_mtod_offset(pkts[k], void *, sizeof(struct cne_ether_hdr)));

    while (n_left_from >= PREFETCH_CNT) {
        /* Prefetch next-next mbufs */
        if (likely(n_left_from > ((PREFETCH_CNT * 3) - 1))) {
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 0]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 1]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 2]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 3]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 4]);
            cne_prefetch0(pkts[(PREFETCH_CNT * 2) + 5]);
        }

        /* Prefetch next mbuf data */
        if (likely(n_left_from > ((PREFETCH_CNT * 2) - 1))) {
            uint16_t pre = PREFETCH_CNT;

            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 0], void *, pkts[pre + 0]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 1], void *, pkts[pre + 1]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 2], void *, pkts[pre + 2]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 3], void *, pkts[pre + 3]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 4], void *, pkts[pre + 4]->l2_len));
            cne_prefetch0(pktmbuf_mtod_offset(pkts[pre + 5], void *, pkts[pre + 5]->l2_len));
        }

        memcpy(mbufs, pkts, (PREFETCH_CNT * sizeof(void *)));

        pkts += PREFETCH_CNT;
        n_left_from -= PREFETCH_CNT;

        punt_kernel_process_mbuf(node, mbufs, PREFETCH_CNT);
    }

    while (n_left_from > 0) {
        mbufs[0] = pkts[0];

        n_left_from--;
        pkts++;

        punt_kernel_process_mbuf(node, mbufs, 1);
    }

    cne_node_next_stream_move(graph, node, PUNT_KERNEL_NEXT_PKT_DROP);
    return nb_objs;
}
static int
punt_kernel_node_init(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    punt_kernel_node_ctx_t *ctx = (punt_kernel_node_ctx_t *)node->ctx;

    ctx->sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (ctx->sock < 0)
        CNE_ERR_RET("Unable to open RAW socket\n");

    return 0;
}

static void
punt_kernel_node_fini(const struct cne_graph *graph __cne_unused, struct cne_node *node)
{
    punt_kernel_node_ctx_t *ctx = (punt_kernel_node_ctx_t *)node->ctx;

    if (ctx->sock >= 0) {
        close(ctx->sock);
        ctx->sock = -1;
    }
}

static struct cne_node_register punt_kernel_node_base = {
    .process = punt_kernel_node_process,
    .name    = PUNT_KERNEL_NODE_NAME,

    .init = punt_kernel_node_init,
    .fini = punt_kernel_node_fini,

    .nb_edges = PUNT_KERNEL_NEXT_MAX,
    .next_nodes =
        {
            [PUNT_KERNEL_NEXT_PKT_DROP] = PKT_DROP_NODE_NAME,
        },
};

struct cne_node_register *
punt_kernel_node_get(void)
{
    return &punt_kernel_node_base;
}

CNE_NODE_REGISTER(punt_kernel_node_base);
