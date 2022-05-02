/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

/* cnet_tcp_chnl.c - TCP chnl support routines. */

/**
 * This module is the interface between the generic sockets module and the TCP
 * protocol processing module.
 */

#include <netinet/tcp.h>        // for tcp_info, SOL_TCP, TCP_MAXSEG
#include <cnet.h>               // for cnet_add_instance
#include <cnet_stk.h>           // for stk_entry, per_thread_stk, this_stk, prot...
#include <cne_inet.h>           // for CIN_PORT, in_caddr, CIN_LEN
#include <cnet_chnl.h>          // for chnl, chnl_buf, chnl_cb_wait, _ISCONNECTED
#include <cnet_pcb.h>           // for pcb_entry, pcb_key, cnet_pcb_alloc, pcb_hd
#include <cnet_tcp.h>           // for tcb_entry, tcp_entry, cnet_tcb_new, tcp_a...
#include <cnet_tcp_chnl.h>
#include <cnet_chnl_opt.h>        // for cnet_chnl_opt_add, chnl_optval_get, chnl_...
#include <errno.h>                // for ENOPROTOOPT, EINVAL, EFAULT, ENOBUFS, EIS...
#include <netinet/in.h>           // for IPPROTO_TCP
#include <string.h>               // for NULL, memcpy, size_t
#include <sys/socket.h>           // for linger, MSG_DONTWAIT, SOL_SOCKET
#include <sys/types.h>            // for ssize_t
#include <pktdev.h>

#include "cne_common.h"        // for __cne_unused, CNE_MIN
#include "cne_log.h"           // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_ERR, CNE_...
#include "cne_vec.h"           // for vec_len, vec_add, vec_at_index, vec_pool_free
#include "cnet_const.h"        // for __errno_set, __errno_set_null, is_set, bool_t
#include "cnet_reg.h"
#include "cnet_protosw.h"        // for
#include "pktmbuf.h"             // for pktmbuf_tailroom, pktmbuf_t

/**
 * Drop the acked data from the chnl queue and free any complete
 * packet structures.
 */
void
cnet_drop_acked_data(struct chnl_buf *cb, int32_t acked)
{
    if (pthread_mutex_lock(&cb->mutex))
        CNE_RET("Unable to acquire mutex\n");

    /* For the number of bytes acked we need to adjust the resend queue */
    while (acked > 0) {
        pktmbuf_t *m;
        int32_t size;

        if (vec_len(cb->cb_vec) == 0) {
            CNE_WARN("list empty, break\n");
            break;
        }

        /* get the pointer to the packet on the send queue */
        m = vec_at_index(cb->cb_vec, 0);

        size = pktmbuf_data_len(m);

        /*
         * When the amount acked is greater then the packet size, the packet
         * can be removed from the send_queue and freed.
         */
        if (size <= acked)
            pktmbuf_free(vec_at_index(cb->cb_vec, 0));
        else {
            /*
             * Acked only part of the packet data, need to adjust it packet.
             *
             * Fixup packet and make sure the IP/TCP header is long word
             * aligned, when we need to retransmit the packet.
             *
             * Note: The TCP header could have NOP option bytes to align the
             * TCP header on a long word boundary.
             */
            pktmbuf_data_off(m) += acked;

            size = acked; /* Adjust size to the amount acked */
        }
        acked -= size;
        cb->cb_cc -= size;
    }
    if (pthread_mutex_unlock(&cb->mutex))
        CNE_RET("Unable to release lock\n");
}

/**
 * This routine determines the scaling factor the receive buffer in channels.
 */
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

/**
 * This routine initializes the TCP-specific portions of a new socket.
 */
static int
tcp_chnl_channel(struct chnl *ch, int domain __cne_unused, int type __cne_unused,
                 int proto __cne_unused)
{
    stk_t *stk = this_stk;

    ch->ch_rcv.cb_size = stk->tcp->rcv_size;
    ch->ch_snd.cb_size = stk->tcp->snd_size;

    /* Set up the lower layer output routine */
    ch->ch_proto->proto = IPPROTO_TCP;

    /* Add the pcb to the chnl */
    if ((ch->ch_pcb = cnet_pcb_alloc(&this_stk->tcp->tcp_hd, IPPROTO_TCP)) == NULL) {
        CNE_WARN("PCB allocate failed\n");
        errno = ENOBUFS;
        return -1;
    }

    return 0;
}

static int
tcp_chnl_channel2(struct chnl *ch1, struct chnl *ch2)
{
    int ret;

    ret = tcp_chnl_channel(ch1, 0, 0, 0);
    if (ret)
        return -1;
    return tcp_chnl_channel(ch2, 0, 0, 0);
}

/**
 * This routine is the protocol-specific bind() back-end function for
 * TCP sockets.
 */
static int
tcp_chnl_bind(struct chnl *ch, struct in_caddr *addr, int32_t len)
{
    struct tcb_entry *tcb;

    /* cannot rebind a tcp chnl */
    if (CIN_PORT(&ch->ch_pcb->key.laddr) != 0) {
        CNE_NOTICE("laddr port is not zero %d!\n", CIN_PORT(&ch->ch_pcb->key.laddr));
        return __errno_set(EINVAL);
    }

    if (chnl_bind_common(ch, addr, len, &this_stk->tcp->tcp_hd) == -1) {
        CNE_ERR("cnet_bind_common failed\n");
        return -1;
    }

    /* Add the pointer back to the chnl structure in the PCB. */
    ch->ch_pcb->ch = ch;

    /* will return the tcb pointer if already allocated */
    if ((tcb = cnet_tcb_new(ch->ch_pcb)) == NULL) {
        CNE_WARN("TCB Null\n");
        return __errno_set(ENOBUFS);
    }

    cnet_tcp_chnl_scale_set(tcb, ch);

    tcb->tflags |= TCBF_BOUND;

    return 0;
}

/**
 * This routine is the protocol-specific send() back-end function for
 * TCP sockets.
 */
static int
tcp_chnl_send(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    /* Do not allow data to be sent before connection is complete */
    if (is_clr(ch->ch_state, _ISCONNECTED)) {
        CNE_ERR("Not connected\n");
        __errno_set(ENOTCONN);
        return -1;
    }

    if (chnl_cant_snd_more(ch) || is_set(ch->ch_state, _CHNL_FREE)) {
        __errno_set(EPIPE);
        return -1;
    }

    if (ch->ch_node == NULL)
        ch->ch_node = cne_graph_node_get(this_stk->graph->id, cne_node_from_name("chnl_send"));
    if (!ch->ch_node)
        return -1;
    for (int i = 0; i < nb_mbufs; i++)
        mbufs[i]->userptr = ch->ch_pcb;

    cne_node_add_objects_to_input(this_stk->graph, ch->ch_node, (void **)mbufs, nb_mbufs);

    return nb_mbufs;
}

/**
 * This routine is the protocol-specific listen() back-end function for
 * TCP sockets.
 */
static int
tcp_chnl_listen(struct chnl *ch, int32_t backlog)
{
    struct tcb_entry *tcb = ch->ch_pcb->tcb;

    /* tcb is null if chnl is not bound */
    if (!tcb) {
        CNE_ERR("Socket Not bound\n");
        return __errno_set(EFAULT);
    }

    if (tcb->state > TCPS_LISTEN) {
        CNE_ERR("Invalid state %d\n", tcb->state);
        return __errno_set(EISCONN);
    }

    /* Make sure the backlog value is not larger then CNET_TCP_BACKLOG_COUNT */
    tcb->qLimit = ((backlog >= 0) && (backlog <= CNET_TCP_BACKLOG_COUNT)) ? backlog
                                                                          : CNET_TCP_BACKLOG_COUNT;

    tcb->state = TCPS_LISTEN;
    tcb->tflags |= TCBF_PASSIVE_OPEN;

    return 0;
}

/**
 * This routine is the protocol-specific accept() back-end function for
 * TCP sockets.
 */
static struct chnl *
tcp_chnl_accept(struct chnl *ch, struct in_caddr *addr, int *addrlen)
{
    struct tcb_entry *tcb;
    struct pcb_entry *pcb;
    struct chnl *chNew;

    if (!addr && !addrlen)
        return __errno_set_null(EFAULT);

    if (*addrlen > (int)sizeof(struct in_caddr)) {
        CNE_DEBUG("Address length is incorrect %d shoud be %lu\n", *addrlen,
                  sizeof(struct in_caddr));
    }

    /* Obtain the listening TCB pointer */
    if ((tcb = ch->ch_pcb->tcb) == NULL) {
        CNE_ERR("TCB is Null\n");
        return __errno_set_null(EFAULT);
    }

    /* Must be in the correct state to do an accept call */
    if (tcb->state != TCPS_LISTEN) {
        CNE_ERR("Invalid state <%s>\n", tcb_in_states[tcb->state]);
        return __errno_set_null(EINVAL);
    }

    /* Try to find a waiting chnl in the Backlog queue */
    pcb = tcp_vec_qpop(&tcb->backlog_q, 1);
    if (!pcb)
        return __errno_set_null(EWOULDBLOCK);

    if ((chNew = pcb->ch) == NULL)
        return __errno_set_null(EFAULT);

    chNew->ch_state &= ~_NOFDREF;

    /* copy the peer address to the user's buffer, if present */
    /* POSIX says: "If the actual length of the address is greater than the
     * length of the supplied sockaddr structure, the stored address shall be
     * truncated."
     */
    if (addr) {
        *addrlen = CNE_MIN(*addrlen, CIN_LEN(&pcb->key.faddr));
        memcpy(addr, &pcb->key.faddr, *addrlen);
    }
    return chNew;
}

static int
tcp_connect(struct chnl *ch, struct in_caddr *to __cne_unused, int slen __cne_unused)
{
    struct tcb_entry *tcb;

    /* If we're called after a non-blocking connect(), report progress */
    if (is_set(ch->ch_state, _ISCONNECTING))
        return __errno_set(EALREADY);

    if (is_set(ch->ch_state, (_ISCONNECTED | _ISDISCONNECTING)))
        return __errno_set(EISCONN);

    /* return errors from non-blocking connect - ECONNREFUSED, ETIMEDOUT */
    if (ch->ch_error)
        return __errno_set(ch->ch_error);

    /* connection is shutdown/closed, but no ch_error (already reported?) */
    if (ch->ch_state & (_ISDISCONNECTED | _CANTSENDMORE | _CANTRECVMORE))
        return __errno_set(EINVAL);

    /* Add the pointer back to the chnl structure in the PCB. */
    if (!ch->ch_pcb->ch)
        ch->ch_pcb->ch = ch;

    /* Make sure we have a TCB attached. */
    if ((tcb = cnet_tcb_new(ch->ch_pcb)) == NULL)
        return __errno_set(ENOBUFS);

    cnet_tcp_chnl_scale_set(tcb, ch);

    (void)cnet_tcp_connect(ch->ch_pcb);

    if (ch->ch_state & _ISCONNECTED)
        return 0;

    if (ch->ch_state & _NBIO)
        return __errno_set(EINPROGRESS);

    if (chnl_cb_wait(ch, &ch->ch_snd) == -1)
        return -1;

    if (ch->ch_state & _ISCONNECTED)
        return 0;

    /* otherwise look for an asynchronous error, e.g. ECONNREFUSED */
    return __errno_set(ch->ch_error);
}

/**
 * This routine is the protocol-specific connect() back-end function for
 * TCP sockets.
 */
static int
tcp_chnl_connect(struct chnl *ch, struct in_caddr *to, int slen)
{
    return tcp_connect(ch, to, slen);
}

static int
tcp_chnl_connect2(struct chnl *ch1, struct chnl *ch2)
{
    int ret;

    ret = tcp_connect(ch1, NULL, 0);

    if (ret)
        return -1;
    return tcp_connect(ch2, NULL, 0);
}

/**
 * This routine is the protocol-specific shutdown() back-end function for
 * TCP sockets. The <so> pointer must be validated in the caller routine.
 *
 * Shutting down the send side initiates a protocol-level connection
 * close (send FIN and progress to FIN_WAIT_1 state).
 */
static int
tcp_chnl_shutdown(struct chnl *ch, int32_t how)
{
    /* The ch pointer is validated in the caller routine. */
    if (ch->ch_pcb == NULL)
        return 0;

    /* Shutdown the send side, when we have a tcb */
    if (is_set(how, SHUT_BIT_WR))
        /* ignore the return status as the connection is closing */
        (void)tcp_close(ch->ch_pcb);

    return 0;
}

/**
 * This routine is the protocol-specific close() back-end function for
 * TCP sockets. If ch->ch_pcb is null then return OK, as the entry has already
 * been released.
 */
static int
tcp_chnl_close(struct chnl *ch)
{
    struct pcb_entry *pcb = ch->ch_pcb;
    bool doAbort, doBlock;

    if (pcb == NULL)
        return 0;

    doAbort = !(ch->ch_state & _ISCONNECTED) ||
              ((ch->ch_options & SO_LINGER) && (ch->ch_linger == 0));

    if (doAbort)
        tcp_abort(pcb);
    else if (tcp_close(pcb)) {
        doBlock = (ch->ch_options & SO_LINGER) && (ch->ch_linger > 0);

        if (doBlock) {
            /* Set up the linger timeout value */
            ch->ch_rcv.cb_timeo = ch->ch_linger * this_stk->tcp->now_tick;

            /* When lingering close timed out, abort the connection. */
            if (chnl_cb_wait(ch, &ch->ch_rcv) == -1)
                tcp_abort(pcb);
        } else {
            /* let the callback free the socket/pcb/tcb */
            ch->ch_state |= _ISDISCONNECTING;

            /* returns -1 if the TCB can not be freed immediately */
            return -1;
        }
    }

    return 0;
}

/**
 * This routine sets TCP options associated with a socket.
 */
static int
tcp_chnl_opt_set(struct chnl *ch, int level, int optname, const void *optval, uint32_t optlen)
{
    uint32_t val;
    struct linger const *li;

    if (ch->ch_proto->proto != IPPROTO_TCP)
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
        switch (optname) {
        case SO_LINGER:
            if (optlen != sizeof(struct linger))
                return __errno_set(EINVAL);

            li = (struct linger const *)optval;
            setsockoptBit(ch->ch_options, optname, li->l_onoff);
            ch->ch_linger = (uint16_t)li->l_linger;
            break;

        case SO_OOBINLINE:
            /* We only support OOBINLINE; don't try to turn it off */
            if (val == 0)
                return __errno_set(EINVAL);
            break;

        default:
            return __errno_set(ENOPROTOOPT);
        }
        break;

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

/**
 * This routine gets TCP options associated with a socket.
 */
static int
tcp_chnl_opt_get(struct chnl *ch, int level, int optname, void *optval, uint32_t *optlen)
{
    uint64_t opt[8]      = {0};
    struct linger *resL  = (struct linger *)opt;
    void *resP           = (void *)opt;
    int *resI            = (int *)opt;
    struct tcp_info tcpi = {0};
    struct tcb_entry *tcb;
    uint32_t len;

    if (ch->ch_proto->proto != IPPROTO_TCP)
        return __errno_set(ENOPROTOOPT);

    len = CNE_MIN(*optlen, sizeof(int)); /* most options are int */

    switch (level) {
    case SO_CHANNEL:
        switch (optname) {
        case SO_LINGER:
            resL->l_linger = (int)ch->ch_linger;
            resL->l_onoff  = (int)((ch->ch_options & optname) != 0);
            len            = CNE_MIN(*optlen, sizeof(struct linger));
            break;

        /* OOBINLINE is always on */
        case SO_OOBINLINE:
            *resI = 1;
            break;

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
    .channel_func  = tcp_chnl_channel,  /* Socket init routine */
    .channel2_func = tcp_chnl_channel2, /* Socket2 init routine */
    .close_func    = tcp_chnl_close,    /* close routine */
    .send_func     = tcp_chnl_send,     /* send routine */
    .bind_func     = tcp_chnl_bind,     /* bind routine */
    .connect_func  = tcp_chnl_connect,  /* connect routine */
    .connect2_func = tcp_chnl_connect2, /* connect2 routine */
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

static int
tcp_chnl_destroy(void *_stk __cne_unused)
{
    return 0;
}

CNE_INIT_PRIO(cnet_tcp_chnl_constructor, STACK)
{
    cnet_add_instance("TCP chnl", CNET_TCP_CHNL_PRIO, tcp_chnl_create, tcp_chnl_destroy);
}
