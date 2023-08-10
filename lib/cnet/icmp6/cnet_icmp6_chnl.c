/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

/* cnet_icmp6_chnl.c - ICMP6 chnl support routines. */

/**
 * This module is the interface between the generic channels module and the
 * ICMP6 protocol processing module.
 */

#include "../chnl/chnl_priv.h"
#include <cne_inet.h>        // for inet_ntop4, in_caddr, CIN_PORT, in_caddr...
#include <cne_ring.h>
#include <cnet.h>                  // for cnet_add_instance
#include <cnet_chnl.h>             // for chnl, chnl_buf, chnl_OK, chnl_connect2_c...
#include <cnet_icmp6.h>            // for icmp6_entry
#include <cnet_ip_common.h>        // for ip_info
#include <cnet_meta.h>
#include <cnet_node_names.h>
#include <cnet_reg.h>
#include <cnet_stk.h>          // for stk_entry, per_thread_stk, this_stk, pro...
#include <endian.h>            // for be16toh
#include <errno.h>             // for ENOBUFS, EACCES, EPIPE
#include <netinet/in.h>        // for IPPROTO_ICMPV6, INADDR_BROADCAST
#include <stddef.h>            // for NULL
#include <stdint.h>            // for int32_t
#include <sys/socket.h>        // for MSG_DONTWAIT
#include <sys/types.h>         // for ssize_t

#include "cne_common.h"          // for __cne_unused, CNE_SET_USED
#include "cne_log.h"             // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_WARNING
#include "cne_vec.h"             // for vec_pool_free, vec_start_mbuf_prefetch, vec_add
#include "cnet_const.h"          // for __errno_set, ICMP6_IO, CNET_ICMP6_CHNL_PRIO
#include "cnet_protosw.h"        // for
#include "pktmbuf.h"             // for pktmbuf_free, pktmbuf_data_len, pktmbuf_t

/*
 * This routine is the protocol-specific bind() back-end function for
 * ICMP6 channels.
 *
 * RETURNS: 0 or -1.
 */
static int
icmp6_chnl_bind(struct chnl *ch, struct in_caddr *to, int tolen)
{
    int ret;

    if (!ch)
        return -1;
    ret = chnl_bind_common(ch, to, tolen, &this_stk->icmp6->icmp6_hd);
    if (ret == 0)
        chnl_state_set(ch, _ISCONNECTED);

    return ret;
}

static int
icmp6_accept(struct chnl *ch __cne_unused, struct in_caddr *addr __cne_unused,
             int *addrlen __cne_unused)
{
    return -1;
}

static int
icmp6_listen(struct chnl *ch __cne_unused, int backlog __cne_unused)
{
    return 0;
}

/*
 * This routine is the protocol-specific bind() back-end function for receives.
 */
static int
icmp6_chnl_recv(struct chnl *ch, pktmbuf_t **mbufs, int nb_mbufs)
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

        vec_remove(ch->ch_rcv.cb_vec, n);
    }
    for (int i = 0; i < n; i++)
        sz += pktmbuf_data_len(mbufs[i]);

    ch->ch_rcv.cb_cc -= sz;

    return n;
}

/*
 * This routine is the protocol-specific send() back-end function for
 * ICMP6 channels.
 *
 * Sending for ICMP6 is different from TCP sending data, the reason is TCP data
 * may need to be retransmitted and ICMP6 is best effort. In this case we assume
 * that data is consumed by this routine and we do not have to deal with send
 * buffer limitation. CNET does not attempt to retransmit or copy data into a
 * channel buffer, which would have a limited size, performance hit and would
 * need to be managed via a buffer size. This means you can not get an error
 * about the send buffer being full.
 *
 * This routine will enqueue the packets to the 'chnl_send' node to be passed to
 * the ICMP6 output node.
 */
static int
icmp6_chnl_send(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    struct in_caddr *to;

    if (!ch)
        return -1;
    if (!ch->ch_node) {
        ch->ch_node =
            cne_graph_node_get(this_stk->graph->id, cne_node_from_name(ICMP6_OUTPUT_NODE_NAME));
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
icmp6_shutdown(struct chnl *ch __cne_unused, int how __cne_unused)
{
    return 0;
}

static struct proto_funcs icmp6Funcs = {
    .close_func    = chnl_OK,             /**< close routine */
    .recv_func     = icmp6_chnl_recv,     /**< recv routine */
    .send_func     = icmp6_chnl_send,     /**< send routine */
    .bind_func     = icmp6_chnl_bind,     /**< bind routine */
    .connect_func  = chnl_connect_common, /**< connect routine */
    .shutdown_func = icmp6_shutdown,      /**< shutdown routine*/
    .accept_func   = icmp6_accept,        /**< accept routine */
    .listen_func   = icmp6_listen         /**< listen routine */
};

static int
icmp6_chnl_create(void *_stk __cne_unused)
{
    struct protosw_entry *psw;

    psw = cnet_protosw_find(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (!psw) {
        psw = cnet_protosw_find(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (!psw)
            return -1;
    }
    psw->funcs = &icmp6Funcs;

    return 0;
}

CNE_INIT_PRIO(cnet_icmp6_chnl_constructor, STACK)
{
    cnet_add_instance("ICMP6 chnl", CNET_ICMP6_CHNL_PRIO, icmp6_chnl_create, NULL);
}
