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
#include <cnet_stk.h>              // for stk_entry, per_thread_stk, this_stk, pro...
#include <cne_inet.h>              // for inet_ntop4, in_caddr, CIN_PORT, in_caddr...
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

#include "cne_common.h"          // for __cne_unused, CNE_SET_USED
#include "cne_log.h"             // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_WARNING
#include "cne_vec.h"             // for vec_pool_free, vec_start_mbuf_prefetch, vec_add
#include "cnet_const.h"          // for __errno_set, UDP_IO, CNET_UDP_CHNL_PRIO
#include "cnet_protosw.h"        // for
#include "pktmbuf.h"             // for pktmbuf_free, pktmbuf_data_len, pktmbuf_t

/*
 * This routine initializes the UDP-specific portions of a new channel.
 *
 * RETURNS: 0 or -1.
 */
static int
udp_chnl_channel(struct chnl *ch, int domain __cne_unused, int type __cne_unused,
                 int proto __cne_unused)
{
    stk_t *stk = this_stk;
    struct pcb_entry *pcb;

    ch->ch_rcv.cb_size = stk->udp->rcv_size;
    ch->ch_snd.cb_size = stk->udp->snd_size;

    if ((pcb = cnet_pcb_alloc(&stk->udp->udp_hd, IPPROTO_UDP)) == NULL)
        return __errno_set(ENOBUFS);

    if (stk->udp->cksum_on)
        pcb->opt_flag |= UDP_CHKSUM_FLAG;

    ch->ch_pcb = pcb;

    return 0;
}

static int
udp_chnl_channel2(struct chnl *ch1, struct chnl *ch2)
{
    stk_t *stk = this_stk;
    struct pcb_entry *pcb1, *pcb2;

    ch1->ch_rcv.cb_size = stk->udp->rcv_size;
    ch1->ch_snd.cb_size = stk->udp->snd_size;

    if ((pcb1 = cnet_pcb_alloc(&stk->udp->udp_hd, IPPROTO_UDP)) == NULL)
        return __errno_set(ENOBUFS);

    if (stk->udp->cksum_on)
        pcb1->opt_flag |= UDP_CHKSUM_FLAG;

    ch1->ch_pcb = pcb1;

    ch2->ch_rcv.cb_size = stk->udp->rcv_size;
    ch2->ch_snd.cb_size = stk->udp->snd_size;

    if ((pcb2 = cnet_pcb_alloc(&stk->udp->udp_hd, IPPROTO_UDP)) == NULL) {
        cnet_pcb_free(pcb1);
        return __errno_set(ENOBUFS);
    }

    if (stk->udp->cksum_on)
        pcb2->opt_flag |= UDP_CHKSUM_FLAG;

    ch2->ch_pcb = pcb2;

    return 0;
}

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

    ret = chnl_bind_common(ch, to, tolen, &this_stk->udp->udp_hd);
    if (ret == 0)
        ch->ch_state |= _ISCONNECTED;

    return ret;
}

/*
 * This routine is the protocol-specific send() back-end function for
 * UDP channels.
 *
 */
static int
udp_chnl_send(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    struct in_caddr *to;

    if (ch->ch_node == NULL)
        ch->ch_node = cne_graph_node_get(this_stk->graph->id, cne_node_from_name("chnl_send"));
    if (!ch->ch_node)
        return -1;
    for (int i = 0; i < nb_mbufs; i++) {
        pktmbuf_t *m = mbufs[i];
        struct cnet_metadata *md;

        /* Was the socket shut down or closed while we were waiting? */
        if (is_set(ch->ch_state, _CANTSENDMORE | _CHNL_FREE))
            continue;

        md = cnet_mbuf_metadata(m);

        to = &md->faddr;
        if (CIN_LEN(to) == 0) {
            if (chnl_connect(ch, (struct sockaddr *)to, to->cin_len) < 0)
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

static struct chnl *
udp_accept(struct chnl *ch __cne_unused, struct in_caddr *addr __cne_unused,
           int *addrlen __cne_unused)
{
    return NULL;
}

static int
udp_listen(struct chnl *ch __cne_unused, int backlog __cne_unused)
{
    return 0;
}

static struct proto_funcs udpFuncs = {
    .channel_func  = udp_chnl_channel,     /**< Channel Initialize routine */
    .channel2_func = udp_chnl_channel2,    /**< Channel2 Initialize routine */
    .close_func    = chnl_OK,              /**< close routine */
    .send_func     = udp_chnl_send,        /**< send routine */
    .bind_func     = udp_chnl_bind,        /**< bind routine */
    .connect_func  = chnl_connect_common,  /**< connect routine */
    .connect2_func = chnl_connect2_common, /**< connect2 routine */
    .shutdown_func = udp_shutdown,         /**< shutdown routine*/
    .accept_func   = udp_accept,           /**< accept routine */
    .listen_func   = udp_listen            /**< listen routine */
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
