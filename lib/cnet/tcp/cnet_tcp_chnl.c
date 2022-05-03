/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

/* cnet_tcp_chnl.c - TCP chnl support routines. */

/*
 * This module is the interface between the generic sockets module and the TCP
 * protocol processing module.
 */

#include <netinet/tcp.h>        // for tcp_info, SOL_TCP, TCP_MAXSEG
#include <cnet.h>               // for cnet_add_instance
#include <cnet_stk.h>           // for stk_entry, per_thread_stk, this_stk, prot...
#include <cne_inet.h>           // for CIN_PORT, in_caddr, CIN_LEN
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>        // for chnl, chnl_buf, _ISCONNECTED
#include <cnet_pcb.h>         // for pcb_entry, pcb_key, cnet_pcb_alloc, pcb_hd
#include <cnet_tcp.h>         // for tcb_entry, tcp_entry, cnet_tcb_new, tcp_a...
#include <cnet_tcp_chnl.h>
#include <cnet_chnl_opt.h>        // for cnet_chnl_opt_add, chnl_optval_get, chnl_...
#include <errno.h>                // for ENOPROTOOPT, EINVAL, EFAULT, ENOBUFS, EIS...
#include <netinet/in.h>           // for IPPROTO_TCP
#include <string.h>               // for NULL, memcpy, size_t
#include <sys/socket.h>           // for linger, MSG_DONTWAIT, SOL_SOCKET
#include <sys/types.h>            // for ssize_t
#include <pktdev.h>
#include <cnet_node_names.h>

#include "cne_common.h"        // for __cne_unused, CNE_MIN
#include "cne_log.h"           // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_ERR, CNE_...
#include "cne_vec.h"           // for vec_len, vec_add, vec_at_index, vec_pool_free
#include "cnet_const.h"        // for __errno_set, __errno_set_null, is_set, bool_t
#include "cnet_reg.h"
#include "cnet_protosw.h"        // for
#include "pktmbuf.h"             // for pktmbuf_tailroom, pktmbuf_t

/*
 * Drop the acked data from the chnl queue and free any complete
 * packet structures.
 */
void
cnet_drop_acked_data(struct chnl_buf *cb, int32_t acked)
{
    int idx, len, free_cnt = 0;

    if (!stk_lock())
        CNE_RET("Unable to acquire mutex\n");

    len = vec_len(cb->cb_vec);

    CNE_DEBUG("\n");
    CNE_DEBUG(">>> Begin Ack %d bytes. vec_len %d\n", acked, len);

    /* For the number of bytes acked we need to adjust the resend queue */
    for (idx = 0; acked > 0 && idx < len; idx++) {
        pktmbuf_t *m;
        int32_t size;

        /* get the pointer to the packet on the send queue */
        m = vec_at_index(cb->cb_vec, idx);

        size = pktmbuf_data_len(m);
        if (size == 0) {
            CNE_WARN("[magenta]mbuf [orange]%p [magenta]length is [orange]Zero[] @ [cyan]%d[]\n",
                     (void *)m, idx);
            continue;
        }

        size = CNE_MIN(size, acked);

        if (pktmbuf_adj_offset(m, size) == NULL) {
            CNE_ERR("Acked data %d > %d size of mbuf\n", acked, size);
            break;
        }
        CNE_DEBUG("Acked %d bytes, data offset %d, data len %d\n", size, pktmbuf_data_off(m),
                  pktmbuf_data_len(m));

        /* Adjust size to the amount acked */
        cb->cb_cc -= size;
        acked -= size;

        /* When data length becomes zero we can free this mbuf */
        if (pktmbuf_data_len(m) == 0) {
            pktmbuf_refcnt_update(m, -1);
            free_cnt++;
        }
    }

    CNE_DEBUG("Free [orange]%3d[] mbufs\n", free_cnt);
    if (free_cnt) {
        pktmbuf_free_bulk(cb->cb_vec, free_cnt);

        vec_remove(cb->cb_vec, free_cnt);
    }
    CNE_DEBUG("<<< Data left to ack [orange]%d[] bytes\n", acked);

    stk_unlock();
}

void
cnet_tcp_chnl_scale_set(struct tcb_entry *tcb, struct chnl *ch)
{
    /*
     * Given a sb_hiwat greater then 64K scale it down by 64K to
     * determine the scaling factor. Increase the scaling factor until
     * the scaled value is greater then or equal to sb_hiwat.
     */
    while ((tcb->req_recv_scale < TCP_MAX_WINSHIFT) &&
           ((TCP_MAXWIN << tcb->req_recv_scale) < (int)ch->ch_rcv.cb_hiwat))
        tcb->req_recv_scale++;
}

static int
tcp_chnl_accept(struct chnl *ch, struct in_caddr *addr, int *addrlen)
{
    struct tcb_entry *tcb;
    struct pcb_entry *pcb;
    struct chnl *nch;

    if (!ch || !addr || !addrlen)
        return __errno_set(EFAULT);

    if (*addrlen > (int)sizeof(struct in_caddr)) {
        CNE_DEBUG("Address length is incorrect %d should be %lu\n", *addrlen,
                  sizeof(struct in_caddr));
    }

    /* Obtain the listening TCB pointer */
    if ((tcb = ch->ch_pcb->tcb) == NULL)
        CNE_ERR_RET_VAL(__errno_set(EFAULT), "TCB is Null\n");

    /* Must be in the correct state to do an accept call */
    if (tcb->state != TCPS_LISTEN)
        CNE_ERR_RET_VAL(__errno_set(EINVAL), "Invalid state <%s>\n", tcb_in_states[tcb->state]);

    /* Try to find a waiting chnl in the Backlog queue */
    pcb = tcp_q_pop(&tcb->backlog_q);
    if (!pcb)
        return __errno_set(EWOULDBLOCK);

    if ((nch = pcb->ch) == NULL)
        return __errno_set(EFAULT);

    /* copy the peer address to the user's buffer, if present
     * POSIX says: "If the actual length of the address is greater than the
     * length of the supplied sockaddr structure, the stored address shall be
     * truncated."
     */
    if (addr) {
        *addrlen = CNE_MIN(*addrlen, CIN_LEN(&pcb->key.faddr));
        memcpy(addr, &pcb->key.faddr, *addrlen);
    }
    return nch->ch_cd;
}

static int
tcp_chnl_bind(struct chnl *ch, struct in_caddr *addr, int32_t len)
{
    stk_t *stk = this_stk;
    struct tcb_entry *tcb;

    if (!ch || !stk)
        return __errno_set(EFAULT);

    /* cannot rebind a tcp chnl */
    if (CIN_PORT(&ch->ch_pcb->key.laddr) != 0)
        return __errno_set(EINVAL);

    if (chnl_bind_common(ch, addr, len, &stk->tcp->tcp_hd) == -1)
        CNE_ERR_RET("cnet_bind_common failed\n");

    /* Add the pointer back to the chnl structure in the PCB. */
    ch->ch_pcb->ch = ch;

    /* will return the tcb pointer if already allocated */
    if ((tcb = cnet_tcb_new(ch->ch_pcb)) == NULL)
        CNE_ERR_RET_VAL(__errno_set(ENOBUFS), "cnet_tcb_new failed\n");

    cnet_tcp_chnl_scale_set(tcb, ch);

    tcb->tflags |= TCBF_BOUND;

    return 0;
}

static int
tcp_connect(struct chnl *ch, struct in_caddr *to __cne_unused, int slen __cne_unused)
{
    struct tcb_entry *tcb;

    if (!ch)
        return __errno_set(EFAULT);

    /* If we're called after a non-blocking connect(), report progress */
    if (chnl_state_tst(ch, _ISCONNECTING))
        return __errno_set(EALREADY);

    if (chnl_state_tst(ch, _ISCONNECTED) || chnl_state_tst(ch, _ISDISCONNECTING))
        return __errno_set(EISCONN);

    /* return errors from non-blocking connect - ECONNREFUSED, ETIMEDOUT */
    if (ch->ch_error)
        return __errno_set(ch->ch_error);

    /* connection is shutdown/closed, but no ch_error (already reported?) */
    if (chnl_state_tst(ch, _ISDISCONNECTED) ||
        is_set(ch->ch_state, (_CANTSENDMORE | _CANTRECVMORE)))
        return __errno_set(EINVAL);

    /* Add the pointer back to the chnl structure in the PCB. */
    if (!ch->ch_pcb->ch)
        ch->ch_pcb->ch = ch;

    /* Make sure we have a TCB attached. */
    if ((tcb = cnet_tcb_new(ch->ch_pcb)) == NULL)
        return __errno_set(ENOBUFS);

    cnet_tcp_chnl_scale_set(tcb, ch);

    return cnet_tcp_connect(ch->ch_pcb);
}

static int
tcp_chnl_connect(struct chnl *ch, struct in_caddr *to, int slen)
{
    return tcp_connect(ch, to, slen);
}

static int
tcp_chnl_listen(struct chnl *ch, int32_t backlog)
{
    struct tcb_entry *tcb;

    if (!ch)
        return -1;
    tcb = ch->ch_pcb->tcb;

    /* tcb is null if chnl is not bound */
    if (!tcb || !tcb->pcb)
        CNE_ERR_RET_VAL(__errno_set(EFAULT), "Channel Not bound\n");

    if (tcb->state > TCPS_LISTEN)
        CNE_ERR_RET_VAL(__errno_set(EISCONN), "Invalid state %d\n", tcb->state);

    /* Make sure the backlog value is not larger then CNET_TCP_BACKLOG_COUNT */
    tcb->qLimit = ((backlog >= 0) && (backlog <= CNET_TCP_BACKLOG_COUNT)) ? backlog
                                                                          : CNET_TCP_BACKLOG_COUNT;

    tcb->state = TCPS_LISTEN;
    tcb->tflags |= TCBF_PASSIVE_OPEN;

    return 0;
}

static int
tcp_chnl_recv(struct chnl *ch, pktmbuf_t **mbufs, int nb_mbufs)
{
    uint32_t sz = 0;
    int tlen, n = 0;

    if (nb_mbufs == 0)
        return 0;

    if (!ch || !mbufs)
        return __errno_set(EFAULT);

    tlen = vec_len(ch->ch_rcv.cb_vec);
    if (tlen > 0) {
        n = CNE_MIN(tlen, nb_mbufs);

        CNE_DEBUG("Number of mbufs to recv [orange]%3d[], nb_mbufs [cyan]%3d[]\n", n, nb_mbufs);
        memmove(mbufs, ch->ch_rcv.cb_vec, sizeof(pktmbuf_t *) * n);

        vec_remove(ch->ch_rcv.cb_vec, n);

        for (int i = 0; i < n; i++)
            sz += pktmbuf_data_len(mbufs[i]);

        ch->ch_rcv.cb_cc -= sz;
    }

    return n;
}

/*
 * This routine is the protocol-specific send() back-end function for
 * TCP channels.
 *
 * A TCP channel needs to hold onto mbufs or data for retransmission if needed,
 * which means we need to manage the send buffer. The send buffers is a vector
 * of mbufs and as data is acked we remove or adjust mbuf vector.
 *
 * Because we must hold onto mbufs for retransmission, we put the mbufs in a vector
 * to be held waiting for ACKs to removed or adjusted based on ACKed data.
 *
 * This routine will enqueue the packets to the 'chnl_send' node to be passed to the
 * TCP output node.
 */
static int
tcp_chnl_send(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    if (!ch)
        return __errno_set(EFAULT);

    if (!ch->ch_node) {
        ch->ch_node =
            cne_graph_node_get(this_stk->graph->id, cne_node_from_name(TCP_OUTPUT_NODE_NAME));
        if (!ch->ch_node)
            return __errno_set(EFAULT);
    }

    /* Do not allow data to be sent before connection is complete */
    if (!chnl_state_tst(ch, _ISCONNECTED))
        return __errno_set(ENOTCONN);

    CNE_DEBUG("[cyan]Enqueue [orange]%d [cyan]mbufs[]\n", nb_mbufs);

    for (int i = 0; i < nb_mbufs; i++) {
        pktmbuf_t *m = mbufs[i];

        m->userptr = ch->ch_pcb;
    }

    cne_node_add_objects_to_input(this_stk->graph, ch->ch_node, (void **)mbufs, nb_mbufs);

    return nb_mbufs;
}

/*
 * Shutting down the send side initiates a protocol-level connection
 * close (send FIN and progress to FIN_WAIT_1 state).
 */
static int
tcp_chnl_shutdown(struct chnl *ch, int32_t how)
{
    /* The ch pointer is validated in the caller routine. */
    if (!ch || ch->ch_pcb == NULL)
        return 0;

    /* Shutdown the send side, when we have a tcb */
    if (is_set(how, SHUT_BIT_WR))
        return cnet_tcp_close(ch->ch_pcb);

    return 0;
}

static int
tcp_chnl_close(struct chnl *ch)
{
    struct pcb_entry *pcb;
    bool doAbort;

    if (!ch)
        return -1;

    pcb = ch->ch_pcb;
    if (pcb == NULL)
        return 0;

    doAbort = !chnl_state_tst(ch, _ISCONNECTED);

    if (doAbort)
        cnet_tcp_abort(pcb);
    else if (cnet_tcp_close(pcb)) {
        chnl_state_set(ch, _ISDISCONNECTING);

        /* returns -1 if the TCB can not be freed immediately */
        return -1;
    }

    return 0;
}

static int
tcp_chnl_opt_set(struct chnl *ch, int level, int optname, const void *optval, uint32_t optlen)
{
    uint32_t val;

    if (!ch || ch->ch_proto->proto != IPPROTO_TCP)
        return __errno_set(ENOPROTOOPT);

    val = chnl_optval_get(optval, optlen);

#define setsockoptBit(reg, bit, val) \
    if (val) {                       \
        (reg) |= (bit);              \
    } else {                         \
        (reg) &= ~(bit);             \
    }

    switch (level) {
    case SO_CHANNEL:
        return __errno_set(ENOPROTOOPT);

    case SOL_TCP:
        switch (optname) {
        case TCP_NODELAY:
            setsockoptBit(ch->ch_pcb->opt_flag, TCP_NODELAY_FLAG, val);
            break;
        case TCBF_NOOPT:
            setsockoptBit(ch->ch_pcb->opt_flag, TCP_NOOPT_FLAG, val);
            break;
        case TCBF_NOPUSH:
            setsockoptBit(ch->ch_pcb->opt_flag, TCP_NOPUSH_FLAG, val);
            break;
        default:
            return __errno_set(ENOPROTOOPT);
        }
        break;

    default:
        return __errno_set(ENOPROTOOPT);
    }

    return 0;
}

static int
tcp_chnl_opt_get(struct chnl *ch, int level, int optname, void *optval, uint32_t *optlen)
{
    uint64_t opt[8]      = {0};
    void *resP           = (void *)opt;
    int *resI            = (int *)opt;
    struct tcp_info tcpi = {0};
    struct tcb_entry *tcb;
    uint32_t len;

    if (!ch || ch->ch_proto->proto != IPPROTO_TCP)
        return __errno_set(ENOPROTOOPT);

    len = CNE_MIN(*optlen, sizeof(int)); /* most options are int */

    switch (level) {
    case SO_CHANNEL:
        switch (optname) {
        case SO_ACCEPTCONN:
            *resI = (int)((ch->ch_pcb->tcb != (struct tcb_entry *)NULL) &&
                          (ch->ch_pcb->tcb->state == TCPS_LISTEN));
            break;

        default:
            return __errno_set(ENOPROTOOPT);
        }
        break;

    case SOL_TCP:
        switch (optname) {
        case TCP_NODELAY:
            *resI = ch->ch_pcb->opt_flag & TCP_NODELAY_FLAG;
            break;
        case TCP_MAXSEG:
            if (ch->ch_pcb->tcb == NULL)
                *resI = TCP_MAXSEG;
            else {
                *resI = ch->ch_pcb->tcb->max_mss;
                if (*resI == 0)
                    *resI = TCP_MAXSEG;
            }
            break;
        case TCBF_NOOPT:
            *resI = ch->ch_pcb->opt_flag & TCP_NOOPT_FLAG;
            break;
        case TCBF_NOPUSH:
            *resI = ch->ch_pcb->opt_flag & TCP_NOPUSH_FLAG;
            break;
        case TCP_CONGESTION:
            resP = (void *)(uintptr_t) "reno";
            len  = 5;
            break;
        case TCP_INFO:
            resP = (void *)&tcpi;
            len  = sizeof(struct tcp_info);
            tcb  = ch->ch_pcb->tcb;
            if (!tcb)
                return __errno_set(EINVAL);
            tcpi.tcpi_state         = tcb->state;
            tcpi.tcpi_snd_wscale    = tcb->snd_scale;
            tcpi.tcpi_rcv_wscale    = tcb->rcv_scale;
            tcpi.tcpi_snd_mss       = tcb->max_mss;
            tcpi.tcpi_rcv_mss       = tcb->max_mss;
            tcpi.tcpi_snd_cwnd      = tcb->snd_cwnd;
            tcpi.tcpi_snd_ssthresh  = tcb->snd_ssthresh;
            tcpi.tcpi_rcv_ssthresh  = tcb->rcv_ssthresh;
            tcpi.tcpi_backoff       = tcb->qLimit;
            tcpi.tcpi_last_ack_sent = tcb->last_ack_sent;
            tcpi.tcpi_unacked       = tcb->snd_una;
            tcpi.tcpi_rtt           = tcb->rtt;
            tcpi.tcpi_rcv_space     = cb_space(&ch->ch_rcv);
            tcpi.tcpi_total_retrans = tcb->total_retrans;
            break;
        default:
            CNE_WARN("Unknown TCP %d\n", optname);
            return __errno_set(ENOPROTOOPT);
        }
        break;

    default:
        CNE_WARN("Unknown level %d\n", level);
        return __errno_set(ENOPROTOOPT);
    }

    memcpy(optval, resP, (*optlen = len));

    return 0;
}

static struct proto_funcs tcpFuncs = {
    .close_func    = tcp_chnl_close,    /* close routine */
    .recv_func     = tcp_chnl_recv,     /* receive routine */
    .send_func     = tcp_chnl_send,     /* send routine */
    .bind_func     = tcp_chnl_bind,     /* bind routine */
    .connect_func  = tcp_chnl_connect,  /* connect routine */
    .shutdown_func = tcp_chnl_shutdown, /* shutdown routine*/
    .accept_func   = tcp_chnl_accept,   /* accept routine */
    .listen_func   = tcp_chnl_listen    /* listen routine */
};

static struct chnl_optsw tcp_sol_opts = {
    .level = SOL_SOCKET, .setfunc = tcp_chnl_opt_set, .getfunc = tcp_chnl_opt_get};

static struct chnl_optsw tcp_ipproto_opts = {
    .level = SOL_TCP, .setfunc = tcp_chnl_opt_set, .getfunc = tcp_chnl_opt_get};

static int
tcp_chnl_create(void *_stk __cne_unused)
{
    struct protosw_entry *psw;

    psw = cnet_protosw_find(AF_INET, SOCK_STREAM, 0);
    if (!psw)
        return -1;
    psw->funcs = &tcpFuncs;

    cnet_chnl_opt_add(&tcp_sol_opts);
    cnet_chnl_opt_add(&tcp_ipproto_opts);

    return 0;
}

CNE_INIT_PRIO(cnet_tcp_chnl_constructor, STACK)
{
    cnet_add_instance("TCP chnl", CNET_TCP_CHNL_PRIO, tcp_chnl_create, NULL);
}
