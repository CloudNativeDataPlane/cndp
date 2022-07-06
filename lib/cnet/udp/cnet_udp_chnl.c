/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

/* cnet_udp_chnl.c - UDP chnl support routines. */

/**
 * This module is the interface between the generic channels module and the UDP
 * protocol processing module.
 */

#include <cnet.h>        // for cnet_add_instance
#include <cnet_reg.h>
#include <cnet_stk.h>        // for stk_entry, per_thread_stk, this_stk, pro...
#include <cne_inet.h>        // for inet_ntop4, in_caddr, CIN_PORT, in_caddr...
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>             // for chnl, chnl_buf, chnl_OK, chnl_connect2_c...
#include <cnet_pcb.h>              // for cnet_pcb_alloc, pcb_entry, pcb_key, cnet...
#include <cnet_udp.h>              // for udp_entry
#include <cnet_ip_common.h>        // for ip_info
#include <endian.h>                // for be16toh
#include <errno.h>                 // for ENOBUFS, EACCES, EPIPE
#include <netinet/in.h>            // for IPPROTO_UDP, INADDR_BROADCAST
#include <stddef.h>                // for NULL
#include <stdint.h>                // for int32_t
#include <sys/socket.h>            // for MSG_DONTWAIT
#include <sys/types.h>             // for ssize_t
#include <cnet_meta.h>
#include <cne_ring.h>
#include <cnet_node_names.h>

#include "cne_common.h"          // for __cne_unused, CNE_SET_USED
#include "cne_log.h"             // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_WARNING
#include "cne_vec.h"             // for vec_pool_free, vec_start_mbuf_prefetch, vec_add
#include "cnet_const.h"          // for __errno_set, UDP_IO, CNET_UDP_CHNL_PRIO
#include "cnet_protosw.h"        // for
#include "pktmbuf.h"             // for pktmbuf_free, pktmbuf_data_len, pktmbuf_t

/*
 * This routine is the protocol-specific bind() back-end function for
 * UDP channels.
 *
 * RETURNS: 0 or -1.
 */
static int
udp_chnl_bind(struct chnl *ch, struct in_caddr *to, int tolen)
{
    int ret;

    if (!ch)
        return -1;
    ret = chnl_bind_common(ch, to, tolen, &this_stk->udp->udp_hd);
    if (ret == 0)
        chnl_state_set(ch, _ISCONNECTED);

    return ret;
}

static int
udp_accept(struct chnl *ch __cne_unused, struct in_caddr *addr __cne_unused,
           int *addrlen __cne_unused)
{
    return -1;
}

static int
udp_listen(struct chnl *ch __cne_unused, int backlog __cne_unused)
{
    return 0;
}

/*
 * This routine is the protocol-specific bind() back-end function for receives.
 */
static int
udp_chnl_recv(struct chnl *ch, pktmbuf_t **mbufs, int nb_mbufs)
{
    uint32_t sz = 0;
    int tlen, n = 0;

    if (nb_mbufs == 0)
        return 0;

    if (!ch || !mbufs)
        return __errno_set(EFAULT);

    tlen = vec_len(ch->ch_rcv.cb_vec);
    if (tlen > 0) {
        n = (tlen > nb_mbufs) ? nb_mbufs : tlen;
        memcpy(mbufs, ch->ch_rcv.cb_vec, sizeof(pktmbuf_t *) * n);

        tlen -= n;
        memmove(ch->ch_rcv.cb_vec, ch->ch_rcv.cb_vec + (sizeof(pktmbuf_t *) * n),
                tlen * sizeof(pktmbuf_t *));
        vec_set_len(ch->ch_rcv.cb_vec, tlen);
    }
    for (int i = 0; i < n; i++)
        sz += pktmbuf_data_len(mbufs[i]);

    ch->ch_rcv.cb_cc -= sz;

    return n;
}

/*
 * This routine is the protocol-specific send() back-end function for
 * UDP channels.
 *
 * Sending for UDP is different from TCP sending data, the reason is TCP data
 * may need to be retransmitted and UDP is best effort. In this case we assume that
 * data is consumed by this routine and we do not have to deal with send buffer
 * limitation. CNET does not attempt to retransmit or copy data into a channel buffer,
 * which would have a limited size, performance hit and would need to be managed
 * via a buffer size. This means you can not get an error about
 * the send buffer being full.
 *
 * This routine will enqueue the packets to the 'chnl_send' node to be passed to the
 * UDP output node.
 */
static int
udp_chnl_send(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    struct in_caddr *to;

    if (!ch)
        return -1;
    if (!ch->ch_node) {
        ch->ch_node =
            cne_graph_node_get(this_stk->graph->id, cne_node_from_name(UDP_OUTPUT_NODE_NAME));
        if (!ch->ch_node)
            return __errno_set(EFAULT);
    }

    for (int i = 0; i < nb_mbufs; i++) {
        pktmbuf_t *m = mbufs[i];
        struct cnet_metadata *md;

        md = pktmbuf_metadata(m);
        if (!md)
            return __errno_set(EFAULT);

        to = &md->faddr;
        if (CIN_LEN(to) == 0) {
            if (chnl_connect(ch->ch_cd, (struct sockaddr *)to, to->cin_len) < 0)
                continue;
        }

        m->userptr = ch->ch_pcb;
    }

    cne_node_add_objects_to_input(this_stk->graph, ch->ch_node, (void **)mbufs, nb_mbufs);

    return nb_mbufs;
}

static int
udp_shutdown(struct chnl *ch __cne_unused, int how __cne_unused)
{
    return 0;
}

static struct proto_funcs udpFuncs = {
    .close_func    = chnl_OK,             /**< close routine */
    .recv_func     = udp_chnl_recv,       /**< recv routine */
    .send_func     = udp_chnl_send,       /**< send routine */
    .bind_func     = udp_chnl_bind,       /**< bind routine */
    .connect_func  = chnl_connect_common, /**< connect routine */
    .shutdown_func = udp_shutdown,        /**< shutdown routine*/
    .accept_func   = udp_accept,          /**< accept routine */
    .listen_func   = udp_listen           /**< listen routine */
};

static int
udp_chnl_create(void *_stk __cne_unused)
{
    struct protosw_entry *psw;

    psw = cnet_protosw_find(AF_INET, SOCK_DGRAM, 0);
    if (!psw)
        return -1;
    psw->funcs = &udpFuncs;

    return 0;
}

CNE_INIT_PRIO(cnet_udp_chnl_constructor, STACK)
{
    cnet_add_instance("UDP chnl", CNET_UDP_CHNL_PRIO, udp_chnl_create, NULL);
}
