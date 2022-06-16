/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
 *  The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <cnet.h>                  // for cnet_add_instance
#include <cnet_stk.h>              // for stk_entry, stk_get_timer_ticks, per_thre...
#include <cne_inet.h>              // for inet_ntop4, _in_addr
#include <cnet_netif.h>            // for cnet_netif_match_subnet, cnet_ipv4_compare
#include <cnet_route.h>            // for rtLookup
#include <cnet_route4.h>           // for rtLookup
#include <cnet_pcb.h>              // for pcb_entry, pcb_key, cnet_pcb_free, pcb_hd
#include <cnet_tcp.h>              // for tcb_entry, seg_entry, tcp_entry, DROP_PA...
#include <cnet_pkt.h>              // for tcp_ipv4
#include <cnet_ip_common.h>        // for ip_info
#include <cnet_meta.h>             // for cnet_metadata, cnet_mbuf_metadata, PKT_B...
#include <cnet_tcp_chnl.h>         // for cnet_drop_acked_data, cnet_tcp_chnl_scal...
#include <endian.h>                // for be16toh, htobe32, htobe16, be32toh
#include <errno.h>                 // for errno, ECONNREFUSED, ECONNRESET, ETIMEDOUT
#include <netinet/in.h>            // for ntohs, IPPROTO_TCP, IN_CLASSD, ntohl
#include <pthread.h>               // for pthread_cond_signal, pthread_cond_wait
#include <stdlib.h>                // for free, calloc, rand
#include <string.h>                // for strcat, memcpy, memset

#include "cne_common.h"           // for CNE_MIN, CNE_MAX, CNE_SET_USED, __cne_un...
#include "cne_cycles.h"           // for cne_rdtsc
#include "cne_log.h"              // for CNE_ASSERT
#include <net/cne_ether.h>        // for cne_ether_hdr
#include "net/cne_ip.h"           // for cne_ipv4_hdr, cne_ipv4_udptcp_cksum, CNE...
#include "net/cne_tcp.h"          // for cne_tcp_hdr
#include "cne_vec.h"              // for vec_len, vec_add, vec_at_index
#include <cnet_reg.h>
#include "cnet_ipv4.h"           // for TOS_DEFAULT, TTL_DEFAULT, _OFF_DF
#include "cnet_protosw.h"        // for protosw_entry, cnet_ipproto_set, cnet_pr...
#include "cnet_udp.h"            // for chnl, chnl_buf, cb_space, chnl_cant_snd_...
#include <pktmbuf_ptype.h>
#include <cnet_fib_info.h>
#include <tcp_input_priv.h>
#include <tcp_send_priv.h>

/* static TCP backoff shift values */
static int32_t tcp_syn_backoff[TCP_MAXRXTSHIFT + 1] = {1, 1, 1, 1, 1, 2, 4, 8, 16, 32, 64, 64, 64};
static int32_t tcp_backoff[TCP_MAXRXTSHIFT + 1] = {1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64};
static uint8_t tcp_output_flags[]               = TCP_OUTPUT_FLAGS;

/* globals */

/* forward declares */
static int tcp_destroy(void *_stk);
static int tcb_cleanup(struct tcb_entry *tcb);
static void tcp_update_acked_data(struct seg_entry *seg, struct tcb_entry *tcb);
static int32_t tcp_send_options(struct tcb_entry *tcb, uint8_t *sp, uint8_t flags_n);

const char *tcb_in_states[] = TCP_INPUT_STATES;

#define TCP_FLAGS_MAX_SIZE 128
#define TCB_FLAGS_MAX_SIZE 256
static char tcp_flags[TCP_FLAGS_MAX_SIZE + 1], tcb_flags[TCB_FLAGS_MAX_SIZE + 1];

#define TCP_SEGMENT_COUNT 1024

void *
tcp_vec_qpop(struct tcp_vec *tvec, uint16_t wait_flag)
{
    struct pcb_entry *pcb = NULL;

    for (;;) {
        pcb = (struct pcb_entry *)vec_pop(tvec->vec);

        if (!wait_flag)
            break;

        if (pthread_cond_wait(&tvec->cond, &tvec->mutex))
            break;
    }

    return pcb;
}

/* Return 1 on full or 0 if pushed */
static int
tcp_vec_qadd(struct tcp_vec *tvec, void *val)
{
    vec_add(tvec->vec, val);

    pthread_cond_signal(&tvec->cond);

    return 0;
}

/**
 * This routine returns a string representing the TCP header flag bits.
 *
 * NOTE: The returned string pointer should be considered read-only.
 */
static inline char *
tcp_print_flags(uint8_t flags)
{
    tcp_flags[0] = '\0';

    flags &= TCP_MASK;

    if (is_set(flags, TCP_SYN))
        strcat(tcp_flags, "SYN ");

    if (is_set(flags, TCP_RST))
        strcat(tcp_flags, "RST ");

    if (is_set(flags, TCP_ACK))
        strcat(tcp_flags, "ACK ");

    if (is_set(flags, TCP_FIN))
        strcat(tcp_flags, "FIN ");

    if (is_set(flags, TCP_PSH))
        strcat(tcp_flags, "PSH ");

    if (is_set(flags, TCP_URG))
        strcat(tcp_flags, "URG ");

    return tcp_flags;
}

static inline char *
tcb_print_flags(uint32_t flags)
{
    const char *list[] = TCB_FLAGS;
    int i;

    tcb_flags[0] = '\0';
    for (i = 0; i < (int)(sizeof(flags) * 8); i++) {
        if (flags & (1 << (32 - i))) {
            strlcat(tcb_flags, list[i], TCB_FLAGS_MAX_SIZE);
            strlcat(tcb_flags, " ", TCB_FLAGS_MAX_SIZE);
        }
    }
    return tcb_flags;
}

/**
 * Set the congestion window for slow-start given the valid <tcb>, by looking at
 * the tcb->pcb->faddr and determine the connection is for a local subnet. When
 * the connection is on the local subnet, the code will select a larger
 * congestion window value else it picks the senders max segment size.
 */
static inline void
tcp_set_CWND(struct tcb_entry *tcb)
{
    /**
     * Setup for slow-start congestion window size.
     *
     * For a local address we have a large cwnd value else one segment.
     *
     * RFC2581: pg 4
     * We note that a non-standard, experimental TCP extension allows that a
     * TCP MAY use a large initial window (IW), as define in the equation 1
     * [AFP98].
     *
     *      IW = min( 4 * SMSS, max( 2 * SMSS, 4380 bytes))     [1]
     */
    tcb->snd_cwnd = tcb->max_mss;
    if (tcb->pcb != NULL) {
        if (cnet_netif_match_subnet(&tcb->pcb->key.faddr.cin_addr))
            tcb->snd_cwnd =
                CNE_MIN((4 * tcb->max_mss), CNE_MAX((2 * tcb->max_mss), TCP_INITIAL_CWND));
    }
}

/**
 * Set the correct Sender MSS value for the connection into the struct tcb.max_mss
 * variable.
 *
 * When <mss_offer> is equal to zero set it to tcp.default_MSS value otherwise set
 * it to the maximum value of <mss_offer> and TCP_MIN_MSS. Finally set the
 * tcb->max_mss value to be a minimum value between the new <mss_offer> and
 * TCP_NORMAL_MSS.
 */
static inline void
tcp_set_MSS(struct tcb_entry *tcb, uint16_t mss_offer)
{
    stk_t *stk = this_stk;

    /*
     * When mss_offer equal zero take the tcp.default_MSS, otherwise set to the
     * maximum of TCP_MIN_MSS and mss_offer.
     */
    mss_offer = (mss_offer == 0) ? stk->tcp->default_MSS : CNE_MAX(mss_offer, TCP_MIN_MSS);

    /* Make sure sender mss is not larger then the normal/MAX MSS value. */
    tcb->max_mss = CNE_MIN(mss_offer, TCP_MAX_MSS);
}

/**
 * Allocate a new struct tcb_entry structure if the pcb->tcb does not already contain
 * a struct tcb_entry pointer. If the pcb->tcb contains a valid pointer then return the
 * tcb pointer.
 *
 * If the pcb->tcb is NULL then allocate a new struct tcb_entry and fill in some information
 * in the struct tcb_entry structure.
 *
 */
struct tcb_entry *
cnet_tcb_new(struct pcb_entry *pcb)
{
    stk_t *stk = this_stk;
    struct tcb_entry *tcb;
    pthread_mutexattr_t attr;

    /* If the TCB is already allocated then return the tcb pointer. */
    if ((tcb = pcb->tcb) != NULL)
        return tcb;

    if ((tcb = tcb_alloc()) == NULL) {
        CNE_WARN("TCB allocate failed\n");
        return NULL;
    }

    tcb->reassemble = vec_alloc(tcb->reassemble, CNET_TCP_REASSEMBLE_COUNT);
    if (!tcb->reassemble) {
        tcb_free(tcb);
        CNE_WARN("tcb->backlog allocate failed\n");
        return NULL;
    }
    CNE_DEBUG("Reassemable %p, %d\n", tcb->reassemble, vec_len(tcb->reassemble));

    tcb->backlog_q.vec = vec_alloc(tcb->backlog_q.vec, CNET_TCP_BACKLOG_COUNT);
    if (!tcb->backlog_q.vec) {
        tcb_free(tcb);
        CNE_WARN("tcb->backlog allocate failed\n");
        return NULL;
    }
    pthread_mutexattr_init(&attr);
    pthread_mutex_init(&tcb->backlog_q.mutex, &attr);
    if (pthread_cond_init(&tcb->backlog_q.cond, NULL)) {
        vec_free(tcb->backlog_q.vec);
        tcb_free(tcb);
        pthread_mutexattr_destroy(&attr);
        CNE_WARN("pthread_cond_init() failed\n");
        return NULL;
    }
    pthread_mutexattr_destroy(&attr);

    tcb->half_open_q = vec_alloc(tcb->half_open_q, CNET_TCP_HALF_OPEN_COUNT);
    if (!tcb->half_open_q) {
        vec_free(tcb->backlog_q.vec);
        tcb_free(tcb);
        CNE_WARN("tcb->half_open_q allocate failed\n");
        return NULL;
    }

    /* Enable RFC1323 (TCP Extensions for High Performance), if requested. */
    tcb->tflags = (stk->gflags & RFC1323_SCALE_ENABLED) != 0 ? TCBF_REQ_SCALE : 0;
    tcb->tflags |= (stk->gflags & RFC1323_TSTAMP_ENABLED) != 0 ? TCBF_REQ_TSTAMP : 0;

    tcb->srtt   = TCP_SRTTBASE_TV;
    tcb->rttvar = stk->tcp->default_RTT * (TCP_SLOWHZ << TCP_RTTVAR_SHIFT);
    tcb->rttmin = TCP_MIN_TV;
    tcb->rxtcur = tcp_range_set(((TCP_SRTTBASE_TV >> 2) + (TCP_SRTTDFLT_TV << 2)) >> 1, TCP_MIN_TV,
                                TCP_REXMTMAX_TV);

    /* Set our MSS to the normal large value and peers value to minimum. */
    tcp_set_MSS(tcb, TCP_MAX_MSS);

    tcp_set_CWND(tcb);

    /* Normally set to TCP_MAXWIN as per RFC2001 */
    tcb->snd_ssthresh = tcb->snd_cwnd << 1;

    /* Link the PCB and TCB together */
    tcb->pcb   = pcb;
    pcb->tcb   = tcb;
    tcb->tcp   = stk->tcp;
    tcb->netif = pcb->netif;

    /* Set the new send ISS value. */
    tcp_send_seq_set(tcb, 7);

    tcb->rcv_bsize = tcb->rcv_wnd = pcb->ch->ch_rcv.cb_hiwat;
    return tcb;
}

/**
 * Form the TCP header and send the given segment of data.
 *
 */
static int
tcp_send_segment(struct tcb_entry *tcb, struct seg_entry *seg)
{
    struct pcb_entry *pcb = tcb->pcb;
    struct chnl *ch       = pcb->ch;
    pktmbuf_t *mbuf       = seg->mbuf;
    struct cne_tcp_hdr *tcp;
    uint64_t nexthop = 0;

    seg->mbuf = NULL;

    /* Add the TCP options to the data packet */
    if (seg->optlen > 0) {
        /* point to seg->optlen bytes before data to put options */
        pktmbuf_prepend(mbuf, seg->optlen);
        memcpy(pktmbuf_mtod(mbuf, int8_t *), &seg->opts[0], seg->optlen);
    }

    /* Set the read pointer to the IP header */
    tcp = (struct cne_tcp_hdr *)pktmbuf_prepend(mbuf, sizeof(struct cne_tcp_hdr));

    if (!tcp) {
        pktmbuf_free(mbuf);
        return -1;
    }
    /* Set TCP headers to Zero */
    memset(tcp, 0, sizeof(struct cne_tcp_hdr));

    /* Add the source and destination port values */
    tcp->dst_port = CIN_PORT(&pcb->key.faddr);
    tcp->src_port = CIN_PORT(&pcb->key.laddr);

    /* When source address is zero then lookup an interface to use */
    if (pcb->key.faddr.cin_addr.s_addr == 0) {
        fib_info_t *fi;
        struct netif *nif;
        int32_t k;

        fi = this_cnet->tcb_finfo;

        nif = cnet_netif_match_subnet(&pcb->key.faddr.cin_addr);
        if (!nif) {
            char ip[INET6_ADDRSTRLEN + 4] = {0};

            CNE_ERR("No netif match %s\n",
                    inet_ntop4(ip, sizeof(ip), &pcb->key.faddr.cin_addr, NULL) ?: "Invalid IP");
            pktmbuf_free(mbuf);
            return -1;
        }
        if (fib_info_lookup_index(fi, &pcb->key.faddr.cin_addr.s_addr, &nexthop, 1) <= 0) {
            char ip[INET6_ADDRSTRLEN + 4] = {0};

            CNE_WARN("Route lookup failed %s\n",
                     inet_ntop4(ip, sizeof(ip), &pcb->key.faddr.cin_addr, NULL) ?: "Invalid IP");
            pktmbuf_free(mbuf);
            return -1;
        }

        /* Find the correct subnet IP address for the given request */
        if ((k = cnet_ipv4_compare(nif, (void *)&pcb->key.faddr.cin_addr.s_addr)) == -1) {
            char ip[INET6_ADDRSTRLEN + 4] = {0};

            CNE_WARN(
                "cnet_ipv4_compare(%s) failed\n",
                inet_ntop4(ip, sizeof(ip), (struct in_addr *)&pcb->key.faddr.cin_addr.s_addr, NULL)
                    ?: "Invalid IP");
            pktmbuf_free(mbuf);
            return -1;
        }

        tcb->netif = nif;

        /* Use the interface attached to the route for the source address */
        pcb->key.laddr.cin_addr.s_addr = nif->ip4_addrs[k].ip.s_addr;
    }

    /* Clear the send Ack Now bit, if an ACK is present. */
    if (is_set(seg->flags, TCP_ACK))
        tcb->tflags &= ~(TCBF_ACK_NOW | TCBF_DELAYED_ACK);

    /* Always clear the force tx and need output flags. */
    tcb->tflags &= ~(TCBF_NEED_OUTPUT | TCBF_FORCE_TX);

    CNE_INFO("Packet send seq %u, ack %u\n", seg->ack, seg->ack);

    /* Fill in the rest of the TCP header */
    tcp->recv_ack      = htobe32(seg->ack);
    tcp->sent_seq      = htobe32(seg->seq);
    tcp->data_off      = ((sizeof(struct cne_tcp_hdr) + seg->optlen) >> 2) << 4;
    tcp->rx_win        = htobe16(seg->wnd); /* scaled already */
    tcp->tcp_urp       = htobe16(seg->urp);
    tcb->last_ack_sent = tcb->rcv_nxt; /* Update the last ACK sent */
    tcp->tcp_flags     = seg->flags;

    /* Update the L4 header length with option length */
    mbuf->l4_len = sizeof(struct cne_tcp_hdr) + seg->optlen;

    ch->ch_node = cne_graph_get_node_by_name(this_stk->graph, "tcp_send");
    if (!ch->ch_node) {
        pktmbuf_free(mbuf);
        return -1;
    }
    cne_node_enqueue_x1(this_stk->graph, ch->ch_node, TCP_SEND_NEXT_IP4_OUTPUT, mbuf);

    return 0;
}

/**
 * Set up the persistence timer and maintain the shift value.
 */
static inline void
tcp_set_persist(struct tcb_entry *tcb)
{
    int32_t t = (tcb->srtt + (tcb->rttvar << 2));

    /* Divide by 500 ms to get the correct persist timer value. */
    tcb->timers[TCPT_PERSIST] = tcp_range_set(((t * tcp_backoff[tcb->rxtshift]) / 500) >> 3,
                                              TCP_PERSMIN_TV, TCP_PERSMAX_TV);

    if (tcb->rxtshift < TCP_MAXRXTSHIFT)
        tcb->rxtshift++;
}

/* skip to the offset in the list and copy the data to the buffer. */
static int
tcp_mbuf_copydata(struct chnl_buf *cb, uint32_t off, uint32_t len, char *buf)
{
    pktmbuf_t *m;
    uint32_t total = 0, cnt;
    int i          = 0;

    if (pthread_mutex_lock(&cb->mutex))
        CNE_ERR_RET("Unable to acquire mutex\n");

    m = vec_at_index(cb->cb_vec, i++);

    /* skip to the offset location */
    while (m && off) {
        cnt = pktmbuf_data_len(m);

        if (off < cnt)
            break;

        off -= cnt;
        m = vec_at_index(cb->cb_vec, i++);
    }

    while (m && len > 0) {
        cnt = CNE_MIN(pktmbuf_data_len(m) - off, (uint32_t)len);

        memcpy(buf, pktmbuf_mtod_offset(m, char *, off), cnt);

        total += cnt;
        len -= cnt;
        buf += cnt;
        off = 0;
        m   = vec_at_index(cb->cb_vec, i++);
    }

    if (pthread_mutex_unlock(&cb->mutex))
        CNE_ERR_RET("Unable to release lock\n");
    return total;
}

/**
 * Determine if a segment of data or just a TCP header needs to be sent via
 * the tcb_send_segment routine.
 */
static int
tcp_output(struct tcb_entry *tcb)
{
    struct seg_entry tx_seg;
    struct seg_entry *seg = &tx_seg;
    struct chnl *ch;
    bool idle;

    if (!tcb) {
        CNE_WARN("TCB pointer is NULL\n");
        return -1;
    }

    if (!tcb->pcb || !tcb->pcb->ch) {
        CNE_WARN("PCB or CH pointer is NULL\n");
        return -1;
    }
    ch = tcb->pcb->ch;

    idle = (tcb->snd_max == tcb->snd_una);

    /* when snd_max and snd_una are equal then we are idle */
    if (idle) {
        tcb->tflags |= TCBF_NAGLE_CREDIT;

#ifdef CNET_TCP_FAST_REXMIT
        /* RFC2581: pg 7-8
         * [Jac88] recommends that a TCP use slow start to restart transmission
         * after a relatively long idle period. Slow start serves to restart
         * the ACK clock, just as it does at the beginning of a transfer. This
         * mechanism has been widely deployed in the following manner. When TCP
         * has not received a segment for more than one retransmission timeout,
         * cwnd is reduced to the value of the restart window (RW) before
         * transmission begins.
         *
         * For the purposes of this standard, we define RW = IW.
         *
         * We note that the non-standard experimental extension to TCP defined
         * in [AFP98] defines RW = min(IW, cwnd), with the definition of IW
         * adjusted per equation (1) above.
         */
        if (tcb->idle >= tcb->rxtcur)
            tcb->snd_cwnd =
                CNE_MIN((4 * tcb->max_mss), CNE_MAX((2 * tcb->max_mss), TCP_INITIAL_CWND));
#endif /* CNET_TCP_FAST_REXMIT */
    }

    do {
        uint32_t off;
        int32_t len;
        bool sendalot;
        uint32_t win;
        seq_t prev_rcv_adv;

        /* Send a packet we must clear the segment structure each time */
        memset(seg, 0, sizeof(struct seg_entry));

        do {
            sendalot = false; /* Preset the flag to false */

            /* The offset from snd_nxt to snd_una currently */
            off = tcb->snd_nxt - tcb->snd_una;

            /* Set the window size to send window or congestion window size */
            win = CNE_MIN(tcb->snd_wnd, tcb->snd_cwnd);

            /* Set the TCP output flags based on the current state of the TCB */
            seg->flags = tcp_output_flags[tcb->state];
            tcp_flags_dump("Send flags", seg->flags);

            if (is_set(tcb->tflags, TCBF_FORCE_TX)) {
                /* When win is zero then must be a zero window probe */
                if (win == 0) {
                    /*
                     * Force a zero window update.
                     *
                     * When the off set is less then sb_cc then we have
                     * data to
                     * send but the window is zero.
                     */
                    if (off < ch->ch_snd.cb_cc)
                        seg->flags &= ~TCP_FIN;

                    win = 1; /* Send at least one byte */
                } else {
                    /* Turn off the persistent timer */
                    tcb->timers[TCPT_PERSIST] = 0;
                    tcb->rxtshift             = 0;
                }
            }

            /*
             * The len variable now contains the data size without headers and
             * the length could be negative.
             *
             * Send the window size or the amount of data in the send queue.
             */
            len = CNE_MIN(ch->ch_snd.cb_cc, win) - off;

            if (is_set(seg->flags, TCP_SYN)) {

                /* make sure we do not send a SYN with a FIN bit. */
                len = 0;
                seg->flags &= ~TCP_FIN;
            }

            if (len < 0) {
                /*
                 * If FIN has been sent but not acked.
                 * but we haven't been called to retransmit.
                 * len will be -1. Otherwise, window shrank
                 * after we sent into it. If window shrank to 0.
                 * cancel pending retransmit and pull snd_nxt
                 * back to (closed) window. We will enter persist
                 * state below. If the window didn't close completely
                 * just wait for an ACK.
                 */
                len = 0;

                if (win == 0) {
                    /* When win is zero, we are done doing retransmits. */
                    tcb->timers[TCPT_REXMT] = 0;
                    tcb->snd_nxt            = tcb->snd_una;
                }
            }

            if (len > tcb->max_mss) {
                /* Force the length to be max_mss if it was too large. */
                len      = tcb->max_mss;
                sendalot = true; /* Need to send a lot of data */
            }

            /* when (snd_nxt + len) < (snd_una + so_snd.sb_cc) then clean FIN */
            if (seqLT(tcb->snd_nxt + len, tcb->snd_una + ch->ch_snd.cb_cc))
                seg->flags &= ~TCP_FIN;

            /* Get the current window space to advertise */
            win = cb_space(&ch->ch_rcv);

            /* silly window avoidance */
            if (len) {
                /* The length equals max_mss then we are not in SWS do send. */
                if (len == tcb->max_mss)
                    break;

                /*
                 * When we have credit we can send something reset flag and
                 * go to send.
                 */
                if (idle || (tcb->tflags & TCBF_NAGLE_CREDIT) ||
                    (tcb->pcb->opt_flag & TCP_NODELAY_FLAG)) {
                    tcb->tflags &= ~TCBF_NAGLE_CREDIT;
                    break;
                }

                /*
                 * We are forcing a transmit or length is 1/2 the max window
                 * or snd_nxt is less then snd_max do a send.
                 */
                if (is_set(tcb->tflags, TCBF_FORCE_TX)) {
                    break;
                }

                if (len >= (int64_t)(tcb->max_sndwnd / 2))
                    break;

                if (seqLT(tcb->snd_nxt, tcb->snd_max))
                    break;
            }

            /* Determine if we need to send a window update. */
            if (win > 0) {
                uint32_t adv;

                adv = CNE_MIN(win, (uint32_t)(TCP_MAXWIN << tcb->rcv_scale)) -
                      (tcb->rcv_adv - tcb->rcv_nxt);

                if (adv >= (uint32_t)(2 * tcb->max_mss)) {
                    CNE_DEBUG("Send window update adv %u > 2 * max_mss\n", adv);
                    break;
                }

                if ((2 * adv) >= (uint32_t)ch->ch_rcv.cb_hiwat) {
                    CNE_DEBUG("Send window update 2 * adv %u > rcv.hiwat\n", 2 * adv);
                    break;
                }
            }

            /* Do we owe anyone an ACK ? */
            if (is_set(tcb->tflags, TCBF_ACK_NOW)) {
                CNE_DEBUG("ACK Now flag set\n");
                break;
            }

            if (seg->flags & SYN_RST) {
                CNE_DEBUG("SYN/RST flags are set\n");
                break;
            }

            if (seqGT(tcb->snd_up, tcb->snd_una)) {
                CNE_DEBUG("SND_UP %u > %u SND_UNA\n", tcb->snd_up, tcb->snd_una);
                break;
            }

            if (is_set(seg->flags, TCP_FIN) &&
                (is_clr(tcb->tflags, TCBF_SENT_FIN) || (tcb->snd_nxt == tcb->snd_una))) {
                CNE_DEBUG("Flags ( %s) or send FIN\n", tcp_print_flags(seg->flags));
                break;
            }

            /*
             * TCP window updates are not reliable, rather a polling protocol
             * using 'persist' packets is used to insure receipt of window
             * updates.
             * The three 'states' for the output side are:
             *  idle                not doing retransmits or persists
             *  persisting          to move a small or zero window
             *  (re)transmitting    and thereby not persisting
             *
             * tcb->timers[TCPT_PERSIST] is greater then zero.
             * TCBF_FORCE_TX is set when we are called to send a persist packet.
             * tcb->timers[TCPT_REXMT] is greater then zero.
             * The output side is idle when both timers are zero.
             *
             * If send window is too small, there is data to transmit, and no
             * retransmit or persist is pending, then go to persist state.
             * If nothing happens soon, send when timer expires:
             * if window is nonzero, transmit what we can,
             * otherwise force out a byte.
             */
            if (ch->ch_snd.cb_cc && (tcb->timers[TCPT_REXMT] == 0) &&
                (tcb->timers[TCPT_PERSIST] == 0)) {
                tcb->rxtshift = 0;
                tcp_set_persist(tcb);
            }

            goto leave;
        } while (/*CONSTCOND*/ 0);

        /* SEND Packet ********/

        /* Create the options and obtain the options length */
        seg->optlen = tcp_send_options(tcb, seg->opts, seg->flags);

        if (len > (tcb->max_mss - seg->optlen)) {
            len      = tcb->max_mss - seg->optlen;
            sendalot = true;

            /* Turn off the FIN if it is set */
            seg->flags &= ~TCP_FIN;
        }

        if (pktdev_buf_alloc(seg->lport, &seg->mbuf, 1) <= 0) {
            CNE_WARN("pktmbuf_alloc() return NULL\n");
            return -1;
        }
        seg->mbuf->userptr = tcb->pcb;
        pktmbuf_adj_offset(seg->mbuf, sizeof(struct tcp_ipv4));

        if (len) {
            len = tcp_mbuf_copydata(&ch->ch_snd, off, len, pktmbuf_mtod(seg->mbuf, char *));

            pktmbuf_append(seg->mbuf, len); /* Update length */
        }

        /* Make sure if sending a FIN does not advertise a new sequence number */
        if (is_set(seg->flags, TCP_FIN) && is_set(tcb->tflags, TCBF_SENT_FIN) &&
            (tcb->snd_nxt == tcb->snd_max)) {
            CNE_DEBUG("Do not advertise a new sequence number\n");
            tcb->snd_nxt--;
        }

        /*
         * Calculate the correct sequence number based on the presents of the
         * SIN or FIN flag bits. The ACK is the next receive sequence value.
         */
        if (len || is_set(seg->flags, SYN_FIN) || tcb->timers[TCPT_PERSIST])
            seg->seq = tcb->snd_nxt;
        else
            seg->seq = tcb->snd_max;
        seg->ack = tcb->rcv_nxt;
        CNE_INFO("ACK value %u\n", seg->ack);

        if (tcb->rcv_scale == 0)
            tcb->rcv_scale = tcb->req_recv_scale;

        /*
         * Calculate receive window and don't skrink the window to small
         * to avoid the silly window syndrome.
         */
        if ((win < (uint32_t)(ch->ch_rcv.cb_hiwat / 4)) && (win < (uint32_t)tcb->max_mss))
            win = 0;

        if (win > (uint32_t)(TCP_MAXWIN << tcb->rcv_scale)) {
            win = (uint32_t)(TCP_MAXWIN << tcb->rcv_scale);
            CNE_DEBUG("Set win to %u scaled MAX window %u scale\n", win, tcb->rcv_scale);
        }

        if (win < (uint32_t)(tcb->rcv_adv - tcb->rcv_nxt)) {
            win = (uint32_t)(tcb->rcv_adv - tcb->rcv_nxt);
            CNE_DEBUG("Set win to %u (adv - nxt)\n", (uint32_t)(tcb->rcv_adv - tcb->rcv_nxt));
        }

        seg->wnd = win >> tcb->rcv_scale;

        if (is_clr(tcb->tflags, TCBF_FORCE_TX) || (tcb->timers[TCPT_PERSIST] == 0)) {
            uint32_t startseq = tcb->snd_nxt;

            /* Count the SYN and/or FIN bits */
            tcb->snd_nxt += is_set(seg->flags, SYN_FIN) ? 1 : 0;

            /* Mark we have sent a FIN if the FIN bit is set */
            if (is_set(seg->flags, TCP_FIN))
                tcb->tflags |= TCBF_SENT_FIN;

            /* Bump the snd_nxt value by the length of the data */
            tcb->snd_nxt += len;

            if (seqGT(tcb->snd_nxt, tcb->snd_max)) {
                tcb->snd_max = tcb->snd_nxt;

                /* Not timing a segment then start timing this one */
                if (tcb->rtt == 0) {
                    tcb->rtt    = 1;
                    tcb->rttseq = startseq;
                }
            }

            if ((tcb->timers[TCPT_REXMT] == 0) && (tcb->snd_nxt != tcb->snd_una)) {
                tcb->timers[TCPT_REXMT] = tcb->rxtcur;
                if (tcb->timers[TCPT_PERSIST] != 0) {
                    tcb->timers[TCPT_PERSIST] = 0;
                    tcb->rxtshift             = 0;
                }
            }
        } else if (seqGT(tcb->snd_nxt + len, tcb->snd_max))
            tcb->snd_max = tcb->snd_nxt + len;

        /* When we have given all the data, set the push bit */
        seg->flags |= (((len > 0) && ((off + len) >= ch->ch_snd.cb_cc)) ? TCP_PSH : 0);
        seg->len = len;

        /* Save the previous receive advertise value in case of error. */
        prev_rcv_adv = tcb->rcv_adv;

        /* Keep track of the largest advertised window */
        if (win > 0 && seqGT(tcb->rcv_nxt + win, tcb->rcv_adv))
            tcb->rcv_adv = tcb->rcv_nxt + win;

        /*
         * If send segment returns error the packet has already been
         * freed and does not need to be freed on error. Restore the
         * previous rcv_adv value because of error.
         */
        if (tcp_send_segment(tcb, seg) == -1) {
            tcb->rcv_adv = prev_rcv_adv;
            CNE_ERR("Send segment returned -1\n");
            return -1;
        }

        if (!sendalot)
            break;
    } while (1);

leave:
    return 0;
}

/**
 * Call the tcp output routine and examine the return status and place the
 * error code in struct chnl.ch_error variable, if present.
 */
static inline void
tcp_do_output(struct tcb_entry *tcb)
{
    /*
     * When an error is detected try and set the ch_error value to be
     * retrieved by the SO_ERROR socket option later.
     */
    if (tcp_output(tcb) == -1) {
        struct pcb_entry *pcb = tcb->pcb;
        struct chnl *ch;

        if (pcb && ((ch = pcb->ch) != NULL))

            /*
             * Do not overwrite the previous value if errno is not zero.
             * The previous ch_error maybe overwritten, but it is expected.
             */
            if (errno)
                pcb->ch->ch_error = errno;
    }
}

/**
 * The routine sends a TCP response segment for a given input segment. The
 * values passed are <seg>, <seq>, <ack> and <flags>. Construct a TCP response
 * segment in the packet structure pointed to by <p_pkt> pointer. The <seq> and
 * the <ack> values can be zero, but must be correct for the type of response
 * segment being sent.
 *
 * @param pcb
 *   Current pointer to the struct pcb_entry structure.
 * @param mbuf
 *   Pointer to the packet structure to build the response segment.
 * @param seq
 *   The sequence number to place in the TCP header.
 * @param ack
 *   The ACK value to put in the TCP header.
 * @param flags
 *   The TCP flags value to place in the TCP header.
 */
static void
tcp_do_response(struct netif *netif, struct pcb_entry *pcb, pktmbuf_t *mbuf, uint32_t seq,
                uint32_t ack, uint8_t flags)
{
    uint32_t win = 0;
    struct cne_tcp_hdr *tcp;
    struct cne_ipv4_hdr *ip;
    struct in_addr faddr, laddr;
    uint16_t fport, lport;
    pktmbuf_t **vec;

    tcp = pktmbuf_mtod(mbuf, struct cne_tcp_hdr *);
    ip  = pktmbuf_mtod_offset(mbuf, struct cne_ipv4_hdr *, -sizeof(struct cne_ipv4_hdr));

    if (pcb) {
        faddr.s_addr = CIN_CADDR(&pcb->key.faddr);
        laddr.s_addr = CIN_CADDR(&pcb->key.laddr);
        fport        = CIN_PORT(&pcb->key.faddr);
        lport        = CIN_PORT(&pcb->key.laddr);
    } else {
        faddr.s_addr = ip->src_addr;
        laddr.s_addr = ip->dst_addr;
        fport        = tcp->src_port;
        lport        = tcp->dst_port;
    }

    memset(ip, 0, sizeof(struct cne_tcp_hdr) + sizeof(struct cne_ipv4_hdr));

    ip->src_addr  = laddr.s_addr;
    ip->dst_addr  = faddr.s_addr;
    tcp->src_port = lport;
    tcp->dst_port = fport;

    /* All fields are zeroed from the above Mem32Zero. */
    ip->total_length  = htobe16(sizeof(struct cne_tcp_hdr) + sizeof(struct cne_ipv4_hdr));
    ip->next_proto_id = IPPROTO_TCP;
    tcp->sent_seq     = htobe32(seq);
    tcp->recv_ack     = htobe32(ack);

    tcp->data_off  = (sizeof(struct cne_tcp_hdr) >> 2) << 4; /* 5 long words */
    tcp->tcp_flags = flags;

    /*
     * When socket and TCB are valid and not a RST, then get the current
     * receive space as the window value.
     */
    if ((pcb != NULL) && (pcb->ch != NULL) && (pcb->tcb != NULL) && is_clr(flags, TCP_RST)) {
        win = cb_space(&pcb->ch->ch_rcv);

        if (win > (uint32_t)(TCP_MAXWIN << pcb->tcb->rcv_scale))
            win = (uint32_t)(TCP_MAXWIN << pcb->tcb->rcv_scale);

        win = (win >> pcb->tcb->rcv_scale);
    }

    tcp->rx_win = htobe16(win);

    ip->time_to_live    = TTL_DEFAULT;
    ip->type_of_service = TOS_DEFAULT;

    /* tcp->cksum is zeroed from above */
    if (!pcb)
        tcp->cksum = cne_ipv4_udptcp_cksum(ip, tcp);

    (void)vec;
    (void)netif;
    pktmbuf_free(mbuf);
}

/**
 * The tcp_drop_with_reset will drop the packet if the TCP reset bit is set, the packet
 * is a multicast/broadcast packet or belongs to the Class D group.
 *
 * Otherwise when the ACK bit is set send a response with the following format
 * <SEQ=SEG.ACK><CTL=RST> and if the ACK bit is off then send a segment with the
 * following format <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>.
 *
 * If the SYN bit is set then bump the SEG.LEN of the incoming segment by 1.
 */
static void
tcp_drop_with_reset(struct netif *netif, struct seg_entry *seg, struct pcb_entry *pcb)
{
    pktmbuf_t *mbuf;
    struct cne_ipv4_hdr *ip = (struct cne_ipv4_hdr *)seg->ip;

    /* Steal the input mbuf */
    mbuf      = seg->mbuf;
    seg->mbuf = NULL;

    /* Need to make sure we handle IP Multicast addresses and RST packets */
    if (is_set(seg->flags, TCP_RST) || IN_CLASSD(ip->dst_addr) ||
        (mbuf->ol_flags & CNE_MBUF_IS_MCAST)) {
        pktmbuf_free(mbuf);
    } else {
        /* Only send the RST if the ACK bit is set on the incoming segment */
        if (is_set(seg->flags, TCP_ACK))
            /* Send segment with <SEQ=SEG.ACK><CTL=RST> */
            tcp_do_response(netif, pcb, mbuf, seg->ack, 0, TCP_RST);
        else { /* When ACK is not set, then send a RST/ACK pair */
            if (is_set(seg->flags, TCP_SYN))
                seg->len++; /* SEG.LEN++ */

            /* Send segment with <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK> */
            seg->seq = 0;
            tcp_do_response(netif, pcb, mbuf, seg->seq, seg->seq + seg->len, RST_ACK);
        }
    }
}

/**
 * Send an ACK and allow the segment to be dropped.
 */
static inline int
tcp_drop_after_ack(struct seg_entry *seg)
{
    /* Do not response if we have a incoming RST */
    if (is_clr(seg->flags, TCP_RST)) {
        seg->pcb->tcb->tflags |= TCBF_ACK_NOW;
        tcp_do_output(seg->pcb->tcb);
    }

    return TCP_INPUT_NEXT_PKT_DROP;
}

/**
 * One of the state routines to handle TCP option processing.
 *
 * The ERROR can be returned if the length opts[1] == 0 or the segment offset
 * is less then the sizeof tcp_hdr_t structure. An error is returned if the
 * computed length of each option exceeds the IP options length value.
 *
 * NOTE: Options are ignored if malformed by containing an incorrect length for
 *       the option.
 */
static int
tcp_do_options(struct seg_entry *seg, uint8_t *opts)
{
    int32_t optlen   = seg->offset - sizeof(struct cne_tcp_hdr);
    uint8_t *opt_end = &opts[optlen];
    uint16_t mss;

    if (!opts)
        return 0;

    while (opts < opt_end) {
        switch (opts[0]) {
        case TCP_OPT_EOL:
            return 0;

        case TCP_OPT_NOP:
            opts++;
            continue;

        case TCP_OPT_MSS:
            if ((opts[1] + opts) > opt_end)
                return -1;

            if ((opts[1] == TCP_OPT_MSS_LEN) && is_set(seg->flags, TCP_SYN)) {
                memcpy(&mss, &opts[2], sizeof(mss));
                mss = ntohs(mss);

                mss = (mss > seg->pcb->tcb->max_mss) ? seg->pcb->tcb->max_mss : mss;

                seg->mss = mss;
                seg->sflags |= SEG_MSS_PRESENT;
            }

            break;

        case TCP_OPT_WSOPT:
            if ((opts[1] + opts) > opt_end)
                return -1;

            /* Only grab the window scaling option on a SYN packet */
            if ((opts[1] == TCP_OPT_WSOPT_LEN) && is_set(seg->flags, TCP_SYN)) {
                seg->req_scale = CNE_MIN(opts[2], TCP_MAX_WINSHIFT);
                seg->sflags |= SEG_WS_PRESENT;
            }

            break;

        case TCP_OPT_SACK_OK:
            if ((opts[1] + opts) > opt_end)
                return -1;

            if (opts[1] == TCP_OPT_SACK_LEN)
                seg->pcb->tcb->tflags |= TCBF_SACK_PERMIT;
            break;

        case TCP_OPT_TSTAMP:
            if ((opts[1] + opts) > opt_end) {
                CNE_WARN("Option Length Invalid opts %u\n", *opts);
                return -1;
            }

            if (opts[1] != TCP_OPT_TSTAMP_LEN) {
                CNE_WARN("opts[1] %d != %u\n", opts[1], TCP_OPT_TSTAMP_LEN);
                break;
            }

            /* Timestamp option detection RFC 1323 Appendix A format? */
            memcpy(&seg->ts_val, &opts[2], sizeof(uint32_t));
            seg->ts_val = ntohl(seg->ts_val);

            /*
             * The Timestamp Echo Reply field (TSecr) is only valid if the ACK
             * bit is set in the TCP header; if it is valid, it echos a
             * timestamp value that was sent by the remote TCP in the TSval
             * field of a Timestamps option. When TSecr is not valid, its value
             * must be zero.
             */
            if (is_set(seg->flags, TCP_ACK)) {
                memcpy(&seg->ts_ecr, &opts[6], sizeof(uint32_t));
                seg->ts_ecr = ntohl(seg->ts_ecr);
            } else
                seg->ts_ecr = 0;

            seg->sflags |= SEG_TS_PRESENT;

            /* When ts_ecr is later then current time reset to non-RFC1323 */
            if ((seg->ts_ecr != 0) && tstampLT(stk_get_timer_ticks(), seg->ts_ecr))
                seg->ts_ecr = 0;

            break;

        default:
            CNE_WARN("Unknown Options %d\n", opts[0]);
            break;
        }

        if (opts[1] == 0) /* Malformed option length */
            return -1;

        opts += opts[1];
    }

    return 0;
}

/**
 * Move the TCP connection to the next state and do any processing required
 * for the new state.
 */
static void
tcp_do_state_change(struct pcb_entry *pcb, int32_t new_state)
{
    struct tcb_entry *tcb = pcb->tcb;

    cnet_assert(tcb != NULL);

    switch (new_state) {
    case TCPS_CLOSED:

        /*
         * When tcb_cleanup() is called and returns OK and the socket pointer
         * is valid then cleanup the rest of the connection. When the socket
         * pointer is NULL then a close was done on the socket before we got
         * to the closed state.
         */
        if ((tcb_cleanup(tcb) == 0) && (pcb->ch != NULL)) {
            pcb->ch->ch_state &= ~(_ISCONNECTED | _ISCONNECTING | _ISDISCONNECTING);
            pcb->ch->ch_state |= _ISDISCONNECTED;
            chnl_cant_snd_rcv_more(pcb->ch, _CANTSENDMORE | _CANTRECVMORE);

            if (is_set(pcb->ch->ch_state, _NOFDREF))
                chnl_cleanup(pcb->ch);
        }

        /* Can not allow the code at the end of the switch to be executed */
        return;

    case TCPS_CLOSE_WAIT:
        INC_TCP_STAT(close_count);

        /*
         * Do not clear the _ISCONNECTED flags as we still need to read all
         * of the data off the socket first.
         */
        pcb->ch->ch_state |= _ISDISCONNECTING;
        chnl_cant_snd_rcv_more(pcb->ch, _CANTRECVMORE);
        break;

    case TCPS_LISTEN:
        INC_TCP_STAT(failed_connects);
        break;

    case TCPS_FIN_WAIT_2:
        break;

    case TCPS_CLOSING:
        break;

    case TCPS_LAST_ACK:
        INC_TCP_STAT(last_acks);
        break;

    case TCPS_SYN_RCVD:
        INC_TCP_STAT(passive_connects);

        /* Start up the TIMER for SYN_RCVD state */
        tcb->timers[TCPT_KEEP] = TCP_KEEP_INIT_TV;
        break;

    case TCPS_ESTABLISHED:
        /* Clear the connecting bit and set the connected bit */
        pcb->ch->ch_state &= ~_ISCONNECTING;
        pcb->ch->ch_state |= _ISCONNECTED;

        ch_wwakeup(pcb->ch);

        /* Add the new pcb to the listen TCB or parent */
        if (tcb->ppcb) {
            struct chnl *ch        = tcb->ppcb->ch; /* Listen socket */
            struct tcb_entry *ptcb = tcb->ppcb->tcb;

            /*
             * Take connection off the half open queue and put on
             * backlog. Ignored if not found, because we do not
             * care if the entry was not on the half open queue.
             */
            int idx = vec_find_index(ptcb->half_open_q, pcb);
            if (idx != -1)
                vec_at_index(ptcb->half_open_q, idx) = NULL;

            /* Abort the connection, if the backlog queue is full */
            if (tcp_vec_qadd(&ptcb->backlog_q, pcb)) {
                tcp_abort(pcb);
                return;
            }
            ch_rwakeup(ch);
        }

        tcb->idle              = 0;
        tcb->timers[TCPT_KEEP] = tcb->tcp->keep_idle;

        if ((tcb->tflags & (TCBF_RCVD_SCALE | TCBF_REQ_SCALE)) ==
            (TCBF_RCVD_SCALE | TCBF_REQ_SCALE)) {
            tcb->snd_scale = tcb->req_send_scale;
            tcb->rcv_scale = tcb->req_recv_scale;
        }

        break;

    case TCPS_FIN_WAIT_1:
        pcb->ch->ch_state |= _ISDISCONNECTING;

    /* FALLTHRU */
    case TCPS_TIME_WAIT:
        /*
         * Do errno callback, remove timers, clear keepalive and set
         * the TIME_WAIT timeout.
         */
        tcb_kill_timers(tcb);
        tcb->timers[TCPT_2MSL] = 2 * TCP_MSL_TV;
        break;

    default:
        break;
    }

    tcb->state = new_state;
}

/**
 * Process the given segment <seg> by validating the segment is acceptability.
 */
static bool
tcp_do_segment(struct seg_entry *seg)
{
    struct tcb_entry *tcb = seg->pcb->tcb;
    int32_t test_case     = 0;
    uint32_t lwin, lseq;
    uint8_t tflags;
    bool acceptable = false;

    /* Adjust the length base on SYN and/or FIN bits */
    tflags = seg->flags;
    seg->seq += seg->len; /* seq must include SYN/FIN byte count */

    /* RFC793 p69 - SEGMENT ARRIVES - Otherwise
     *
     * Segments are processed in sequence. Initial tests on arrival
     * are used to discard old duplicates, but further processing is
     * done in SEG.SEQ order. If a segments contents straddle the
     * boundary between old and new, only the new parts should be
     * processed.
     *
     * Define the state value for the segment acceptability test. The four
     * cases for acceptability are:
     *
     * Segment Receive
     * Length  Window   Test
     * ------  ------   ----------------------------------------------------
     *    0       0     SEG.SEQ = RCV.NXT
     *    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND
     *   >0       0     not acceptable
     *   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND
     *               or RCV.NXT =< SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND
     *
     * If the RCV.WND is zero, no segments will be acceptable, but
     * special allowance should be made to accept valid ACKs, URGs and
     * RSTs.
     *
     * If an incoming segment is not acceptable, an acknowledgment
     * should be sent in reply (unless the RST bit is set, if so drop
     * the segment and return):
     *
     * <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
     *
     * After sending the acknowledgment, drop the unacceptable segment
     * and return.
     */

    /*
     * The test_case variable is used to determine which of the four
     * acceptability test to conduct. The state value uses two bits one for
     * Segment Length and the other is for Receive Window. Based in the
     * seglen >0 we set bit 1 and if rcv_win >0 we set bit 0 to create a
     * value between 0-3 and then switch on the value to determine which test
     * to conduct.
     */
    test_case = ((seg->len != 0) ? 2 : 0) | ((tcb->rcv_wnd > 0) ? 1 : 0);

    /* Local values for (RCV.NXT + RCV.WND) and (SEG.SEQ + SEG.LEN - 1) */
    lwin = (tcb->rcv_nxt + tcb->rcv_wnd);
    lseq = (seg->seq + seg->len - 1);

    switch (test_case) {
    /* seglen == 0, rcv_wnd == 0 */
    case 0:
        acceptable = (seg->seq == tcb->rcv_nxt);
        break;

    /* seglen == 0, rcv_wnd   >0 */
    case 1:
        acceptable = (seqLEQ(tcb->rcv_nxt, seg->seq) && seqLT(seg->seq, lwin));
        break;

    /* seglen   >0, rcv_wnd == 0 */
    case 2:
        acceptable = false;
        break;

    /* seglen   >0, rcv_wnd   >0 */
    case 3:
        acceptable = ((seqLEQ(tcb->rcv_nxt, seg->seq) && seqLT(seg->seq, lwin)) ||
                      (seqLEQ(tcb->rcv_nxt, lseq) && seqLT(lseq, lwin)));
        break;
    }

    /*
     * If the RCV.WND is zero, no segments will be acceptable, but special
     * allowance should be make to accept valid ACKs, URGs and RSTs.
     */
    if ((tcb->rcv_wnd == 0) && is_set(tflags, (TCP_ACK | TCP_URG | TCP_RST)))
        acceptable = true;

    return acceptable;
}

/**
 * Process the option values and set the scaling factor for receives.
 */
static inline void
tcp_do_process_options(struct tcb_entry *tcb, struct seg_entry *seg, struct chnl *ch)
{
    /* skip a few tests if none of the bits are set */
    if (is_set(seg->sflags, (SEG_TS_PRESENT | SEG_WS_PRESENT | SEG_MSS_PRESENT))) {
        /* When the Timestamp is present and the SYN bit grab the TS value */
        if (is_set(seg->sflags, SEG_TS_PRESENT)) {
            tcb->tflags |= TCBF_RCVD_TSTAMP;
            tcb->ts_recent     = seg->ts_val;
            tcb->ts_recent_age = stk_get_timer_ticks();
        }

        if (is_set(seg->sflags, SEG_WS_PRESENT)) {
            tcb->tflags |= TCBF_RCVD_SCALE;
            tcb->req_send_scale = seg->req_scale;
        }

        if (is_set(seg->sflags, SEG_MSS_PRESENT))
            tcp_set_MSS(tcb, seg->mss);
    }

    /* Compute proper scaling value from buffer space */
    cnet_tcp_chnl_scale_set(tcb, ch);
}

/********************** TCP State Machine Functions ***************************/

/**
 * Process the TCP state machine for a passive open RFC793 pg 65-66.
 */
static struct pcb_entry *
do_passive_open(struct seg_entry *seg)
{
    struct pcb_entry *ppcb = seg->pcb; /* Parent PCB to the new pcb */
    struct tcb_entry *tcb;
    struct cnet_metadata *md;
    struct chnl *nch;

    /* third check for a SYN */

    /* RFC793 p65-66, SYN set then check security, Not Done */

    /*
     * If SYN is not set then exit, but if a text-bearing segment it will be
     * processed on return.
     */
    if (is_clr(seg->flags, TCP_SYN))
        return NULL;

    /*
     * fourth other text or control  p66
     *
     *   Any other control or text-bearing segment (not containing SYN)
     *   must have an ACK and thus would be discarded by the ACK
     *   processing.  An incoming RST segment could not be valid, since
     *   it could not have been sent in response to anything sent by this
     *   incarnation of the connection.  So you are unlikely to get here,
     *   but if you do, drop the segment, and return.
     */

    /*
     * RFC793 p65, Check ACK, while in Listen state if received then send a RST
     * the format of the RST is <SEQ=SEG.ACK><CTL=RST>
     */
    if (is_set(seg->flags, TCP_ACK)) {
        CNE_WARN("Segment has ACK bit set\n");
        tcp_drop_with_reset(seg->pcb->netif, seg, NULL);
        return NULL;
    }

    /* Clear the SYN bit to make sure it is not processed again in SYN_SENT */
    seg->flags &= ~TCP_SYN;

    tcb = ppcb->tcb; /* use tcb pointer for the next test */

    /*
     * Check the queue limit and see if we can continue, if not drop the SYN
     * request without sending a RST.
     *
     * BSD uses ((q_limit * 3)/2)+1,
     * where  0 <= q_limit <= CNET_TCP_BACKLOG_COUNT as the
     * standard limit formula. For a backlog of 0 at least 1 is allowed.
     */
    int qcnt = vec_len(tcb->half_open_q) + vec_len(tcb->backlog_q.vec);
    if (qcnt > ((3 * tcb->qLimit) / 2))
        return NULL;

    /* Allocate a new PCB/TCB/Chnl for an unbound socket */
    nch = __chnl_create(ppcb->ch->ch_proto->domain, ppcb->ch->ch_proto->type,
                        ppcb->ch->ch_proto->proto, ppcb);
    if (!nch) {
        CNE_WARN("__chnl_create() failed, netif %p\n", tcb->netif);
        tcp_drop_with_reset(tcb->netif, seg, NULL);
        return NULL;
    }

    /* Retain part of the options */
    nch->ch_options =
        ppcb->ch->ch_options & (SO_DONTROUTE | SO_KEEPALIVE | SO_OOBINLINE | SO_LINGER);
    nch->ch_linger = ppcb->ch->ch_linger;

    /*
     * Allocate a new PCB and TCB structure to hold the new connection
     * leaving the old PCB/TCB alone to be used for other listen connections.
     */
    nch->ch_pcb->ch    = nch;
    nch->ch_pcb->netif = ppcb->netif;

    tcb = cnet_tcb_new(nch->ch_pcb);
    if (!tcb) {
        CNE_WARN("TCB allocation failed\n");
        chnl_cleanup(nch);
        tcp_drop_with_reset(ppcb->tcb->netif, seg, NULL);
        return NULL;
    }

    tcp_do_process_options(tcb, seg, nch);

    /* Setup this TCB as having a parent PCB */
    tcb->ppcb = ppcb;

    vec_add(ppcb->tcb->half_open_q, tcb->pcb);

    md = cnet_mbuf_metadata(seg->mbuf);

    /* Add the pkt information to the new pcb */
    in_caddr_copy(&nch->ch_pcb->key.faddr, &md->faddr);
    in_caddr_copy(&nch->ch_pcb->key.laddr, &md->laddr);

    /* Update and set the segment values */
    tcb->rcv_nxt = seg->seq + 1;
    tcb->rcv_irs = seg->seq;

    /* The window value has not been scaled yet, because the SYN is set */
    tcb->snd_wnd = seg->wnd << tcb->snd_scale;

    tcp_do_state_change(nch->ch_pcb, TCPS_SYN_RCVD); /* Move to SYN_RCVD */
    tcb->timers[TCPT_KEEP] = TCP_KEEP_INIT_TV;

    /* Tell the new TCB to send a SYN_ACK */
    tcb->tflags |= TCBF_ACK_NOW;

    INC_TCP_STAT(passive_connects);

    return nch->ch_pcb;
}

/**
 * Drop the current TCP connection and use the <err_code> as the reason for
 * closing the connection.
 */
static inline void
tcp_do_drop_connection(struct pcb_entry *pcb, int32_t err_code)
{
    if (!TCPS_HAVE_RCVD_SYN(pcb->tcb->state))
        INC_TCP_STAT(failed_connects);

    if (pcb->ch != NULL)
        pcb->ch->ch_error = err_code;

    tcp_do_state_change(pcb, TCPS_CLOSED);
}

/**
 * Cleanup a TCB and free all values in the TCB that need freeing. The pcb
 * is removed from the parent half open or backlog queues. If this is a parent
 * to other pcbs then close them too.
 */
static int
tcb_cleanup(struct tcb_entry *tcb)
{
    struct pcb_entry *p;

    if (tcb->state == TCPS_FREE)
        return TCP_INPUT_NEXT_PKT_DROP;

    /* Mark the pcb as closed, to make sure a connection is not created */
    if ((p = tcb->pcb) != NULL) {
        tcb->pcb  = NULL;
        p->tcb    = NULL;
        p->closed = 1;
    }

    if (tcb->state == TCPS_CLOSED)
        return TCP_INPUT_NEXT_PKT_DROP;

    tcb->state = TCPS_CLOSED;

    tcb_kill_timers(tcb); /* Stop all of the timers */

    /* Check the listening PCB or parent */
    if (tcb->ppcb && tcb->ppcb->tcb) {
        struct tcb_entry *t = tcb->ppcb->tcb;
        int idx;

        /* TCB may be on the parents backlog or half open queue */
        idx = vec_find_index(t->backlog_q.vec, p);
        if (idx != -1) {
            vec_at_index(t->backlog_q.vec, idx) = NULL;
            cnet_pcb_free(p);
        }

        idx = vec_find_index(t->half_open_q, p);
        if (idx != -1) {
            vec_at_index(t->half_open_q, idx) = NULL;
            cnet_pcb_free(p);
        }
    }

    /* Remove connections from the backlog queue */
    vec_foreach_ptr (p, tcb->backlog_q.vec) {
        tcp_do_state_change(p, TCPS_CLOSED);
        cnet_pcb_free(p);
    }
    vec_set_len(tcb->backlog_q.vec, 0);

    /* Drop any half open connections */
    vec_foreach_ptr (p, tcb->half_open_q) {
        tcp_do_state_change(p, TCPS_CLOSED);
        cnet_pcb_free(p);
    }
    vec_set_len(tcb->half_open_q, 0);

    CNE_DEBUG("Half Open queue is clean\n");

    pktmbuf_free_bulk(tcb->reassemble, vec_len(tcb->reassemble));

    /* TCB should be disconnected and ready to be freed */
    vec_free(tcb->reassemble);
    vec_free(tcb->backlog_q.vec);
    vec_free(tcb->half_open_q);
    tcb_free(tcb);

    return 0;
}

/**
 * Handle the listen and if a passive open from a listen state, then call the
 * passive open routine.
 */
static inline int
do_segment_listen(struct seg_entry *seg)
{
    /*
     * RFC1122 4.2.3.10, p. 104: discard bcast/mcast SYN
     * in_broadcast() should never return true on a received
     * packet with M_BCAST not set.
     */
    if (seg->mbuf->ol_flags & CNE_MBUF_IS_MCAST ||
        CNE_IS_IPV4_MCAST(((struct cne_ipv4_hdr *)seg->ip)->dst_addr)) {
        CNE_WARN("Multicast packet\n");
        return TCP_INPUT_NEXT_PKT_DROP;
    }

    /*
     *   If the state is LISTEN then
     *     first check for a RST
     *
     *        An incoming RST should be ignored.
     *     Return.
     */
    if (is_set(seg->flags, TCP_RST)) {
        CNE_WARN("RST found Stop Processing\n");
        return TCP_INPUT_NEXT_PKT_DROP;
    }

    /*
     *    second check for an ACK
     *     Any acknowledgment is bad if it arrives on a connection still in
     *     the LISTEN state.  An acceptable reset segment should be formed
     *     for any arriving ACK-bearing segment.  The RST should be
     *     formatted as follows:
     *
     *      <SEQ=SEG.ACK><CTL=RST>
     *
     *      Return.
     */
    if (is_set(seg->flags, TCP_ACK)) {
        struct tcb_entry *tcb = seg->pcb->tcb;

        if (tcb && tcb->netif)
            tcp_drop_with_reset(tcb->netif, seg, NULL);
        return TCP_INPUT_NEXT_PKT_DROP;
    }

    if (is_clr(seg->flags, TCP_SYN)) {
        CNE_WARN("SYN is NOT set, drop\n");
        return TCP_INPUT_NEXT_PKT_DROP;
    }

    /*
     * third check for a SYN p65-p66 (Not handled)
     *
     *   If the SYN bit is set, check the security.  If the
     *   security/compartment on the incoming segment does not exactly
     *   match the security/compartment in the TCB then send a reset and
     *   return.
     *
     *     <SEQ=SEG.ACK><CTL=RST>
     *
     *   If the SEG.PRC is greater than the TCB.PRC then if allowed by
     *   the user and the system set TCB.PRC<-SEG.PRC, if not allowed
     *   send a reset and return.
     *
     *     <SEQ=SEG.ACK><CTL=RST>
     *
     *   If the SEG.PRC is less than the TCB.PRC then continue.
     *
     *   Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other
     *   control or text should be queued for processing later.  ISS
     *   should be selected and a SYN segment sent of the form:
     *
     *     <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
     *
     *   SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
     *   state should be changed to SYN-RECEIVED.  Note that any other
     *   incoming control or data (combined with SYN) will be processed
     *   in the SYN-RECEIVED state, but processing of SYN and ACK should
     *   not be repeated.  If the listen was not fully specified (i.e.,
     *   the foreign socket was not fully specified), then the
     *   unspecified fields should be filled in now.
     */

    /* Handle passive opens.                    p65-p66 */
    if (is_set(seg->pcb->tcb->tflags, TCBF_PASSIVE_OPEN)) {
        struct pcb_entry *pcb;

        if ((pcb = do_passive_open(seg)) == NULL) {
            CNE_WARN("Passive Open failed, Stop Processing\n");
            return TCP_INPUT_NEXT_PKT_DROP;
        }

        /* New PCB for segment as the previous was in the listen state */
        seg->pcb = pcb;
    }
    return TCP_INPUT_NEXT_CHECK_OUTPUT;
}

/**
 * Handle the TCP reassemble queue for the given packet <seg->p_pkt>.
 */
static uint8_t
tcp_reassemble(struct seg_entry *seg)
{
#ifdef ENABLE_TCP_REASSEMBLE
    pktmbuf_t *mbuf       = seg->mbuf;
    struct pcb_entry *pcb = seg->pcb;
    struct tcb_entry *tcb = pcb->tcb;
    struct tcp_ipv4 *tip  = seg->ip;
    struct cne_tcp_hdr *tcp;
    uint8_t flags = 0;
    pktmbuf_t *m, *p;
    struct tcp_ipv4 *t;
    int32_t i;

    if (mbuf == NULL)
        goto handoff;

    tip->tcp.sent_seq = seg->seq; /* Already in host order */
    tip->ip.len       = seg->len; /* Already in host order */

    /* Move the read pointer to the start of TCP data */
    pktmbuf_adj_offset(mbuf, seg->offset);

    /* Find the segment after this one. */
    p = NULL;
    STAILQ_FOREACH (m, &tcb->reassemble, stq_next) {
        t = pktmbuf_mtod(m, struct tcp_ipv4 *);

        if (seqGT(t->tcp.sent_seq, tip->tcp.sent_seq))
            break;
        p = m;
    }

    /* verify we are not pointing to the head of the circular list */
    if (!p) {
        t = pktmbuf_mtod(p, struct tcb_ipv4 *);

        i = t->tcp.sent_seq + t->ip.len - tip->tcp.sent_seq;

        /* when positive we have to trim the incoming segment at the front */
        if (i > 0) {
            /* Duplicate data, return after freeing packet */
            if (i > tip->ip.len) {
                pktmbuf_free(mbuf);
                seg->mbuf = NULL;
                return flags;
            }

            /* Remove data from the front of the segment */
            pktmbuf_adj_offset(mbuf, i);
            tip->ip.len -= i;
            tip->tcp.sent_seq += i;
        }
    }

    while (m != STAILQ_FIRST(&tcb->reassemble)) { /* not at head of list */
        i = (tip->tcp.sent_seq + tip->ip.len) - t->tcp.sent_seq;

        /* When i less then or equal to zero, segment is after this one. */
        if (i <= 0)
            break;

        /* When i is positive and less then current segment length, must trim */
        if (i < t->ip.len) {
            t->tcp.sent_seq += i;
            t->ip.len -= i;

            pktmbuf_append(m, i);

            /* segment fits in the list and no more trimming is required */
            break;
        }

        /* new segment is larger then current segment, which must be freed */
        t = (tcpip_t *)clist_next(t);

        p = reass_pkt((tcpip_t *)t->ip.node.p_back);
        clist_remove(t->ip.node.p_back);
        pktmbuf_free(m);
    }

    clist_insert(&tip->ip.node, t->ip.node.p_back);

handoff:
    if (tcb->state < TCPS_SYN_RCVD)
        return flags;

    tip = (tcpip_t *)clist_next(hd);

    if (clist_empty(hd) || (tip->tcp.seq != tcb->rcv_nxt))
        return flags;

    if ((tcb->state == TCPS_SYN_RCVD) && tip->ip.len)
        return flags;

    do {
        flags = tip->tcp.flags & TCP_FIN;

        clist_remove(tip);

        p = reass_pkt(tip);

        tip = (tcpip_t *)clist_next(tip);

        /* Update rcv_nxt for the total amount of data sent to the user */
        tcb->rcv_nxt += pcb->data_rcv(pcb, p);
    } while ((tip != hd) && (tip->tcp.seq == tcb->rcv_nxt));

    return flags;
#else
    CNE_SET_USED(seg);
    return seg->flags;
#endif
}

static inline void
_process_data(struct seg_entry *seg, struct tcb_entry *tcb __cne_unused)
{
    /* RFC2581: pg 8
     * 4.2 Generating Acknowledgments
     *
     * The delayed ACK algorithm specified in [Bra89] SHOULD be used
     * by a TCP receiver. When used, a TCP receiver MUST NOT
     * excessively delay acknowledgments. Specifically, an ACK
     * SHOULD be generated for at least every second full-sized
     * segment, and MUST be generated within 500 ms of the arrival
     * of the first unacknowledged packet.
     *
     * The requirement that an ACK "SHOULD" be generated for at least
     * every second full-sized segment is listed in [Bra89] in one
     * place as a SHOULD and another as a MUST. Here we unambiguously
     * state it is a SHOULD. We also emphasize that this is a SHOULD,
     * meaning that an implementor should indeed only deviate from
     * this requirement after careful consideration of the
     * implications. See the discussion of "Stretch ACK violation"
     * in [PAD+98] and the references therein for a discussion of
     * the possible performance problems with generating ACKs less
     * frequently than every second full-sized segment.
     */
    if (seg->mbuf) {
        /* Move the read pointer to the start of TCP data */
        pktmbuf_adj_offset(seg->mbuf, seg->offset);

        CNE_INFO("Update rcv_nxt %u + %d\n", tcb->rcv_nxt, pktmbuf_data_len(seg->mbuf));
        /* Update the rcv_nxt with the number of bytes consumed */
        tcb->rcv_nxt += pktmbuf_data_len(seg->mbuf);

        seg->mbuf = NULL; /* Consumed the packet */
    }
}

/**
 * Process the segment data from the received packet and attach to the TCB.
 */
static void
do_process_data(struct seg_entry *seg)
{
    struct tcb_entry *tcb = seg->pcb->tcb;

    if (!seg->len)
        return;

    /* Does the segment contain data if so then ack the data, if required */
    if ((seg->seq == tcb->rcv_nxt) && vec_len(tcb->reassemble) == 0 &&
        (tcb->state == TCPS_ESTABLISHED)) {

        _process_data(seg, tcb);

        if (is_clr(tcb->tflags, TCBF_DELAYED_ACK))
            tcb->tflags |= TCBF_DELAYED_ACK;
        else {
            tcb->tflags |= TCBF_ACK_NOW;
            tcp_output(tcb);
        }
    } else {
        seg->flags = tcp_reassemble(seg);

        tcb->tflags |= TCBF_ACK_NOW;
        tcp_output(tcb);
    }
}

/**
 * Handle the Active open or Syn Sent state in TCP to attempt a complete
 * connection.
 */
static int
do_segment_syn_sent(struct seg_entry *seg)
{
    struct tcb_entry *tcb = seg->pcb->tcb;
    bool acceptable       = false;

    /* First check the ACK bit */
    if (is_set(seg->flags, TCP_ACK)) {
        /*
         * If SEG.ACK =< SEG.ISS or SEG.ACK > SND.NXT send a reset unless
         * RST bit is set, the RST bit is tested in the response routine.
         *
         * The snd_max equals snd_nxt unless we are doing a retransmit.
         */
        if (seqLEQ(seg->ack, tcb->snd_iss) || seqGT(seg->ack, tcb->snd_max)) {
            INC_TCP_STAT(failed_connects);

            /* <SEQ=SEG.ACK><CTL=RST>*/
            tcp_drop_with_reset(tcb->netif, seg, NULL);
            return TCP_INPUT_NEXT_PKT_DROP;
        }
        tcb->snd_una = seg->ack;

        if (seqLT(tcb->snd_nxt, tcb->snd_una))
            tcb->snd_nxt = tcb->snd_una;

        /* If SND.UNA =< SEG.ACK =< SND.NXT then ACK is acceptable */
        if (seqLEQ(tcb->snd_una, seg->ack) && seqLEQ(seg->ack, tcb->snd_nxt))
            acceptable = true;
    }

    /* Second check the RST bit */
    if (is_set(seg->flags, TCP_RST)) {
        INC_TCP_STAT(connect_resets);

        /*
         * If the ACK was acceptable then signal the user "connection reset"
         * drop the segment, enter Closed state, delete TCB and return.
         */
        if (acceptable)
            tcp_do_drop_connection(seg->pcb, ECONNREFUSED);

        /* otherwise (no ACK) drop the segment and return */
        return TCP_INPUT_NEXT_PKT_DROP;
    }

    /* NOT DONE: Third check the security and precedence. */

    /*
     * Fourth check the SYN bit
     *    This step should be reached only if the ACK is ok, or there is
     *    no ACK, and it the segment did not contain a RST.
     *
     *    If the SYN bit is on and the security/compartment and precedence
     *
     *    are acceptable then, RCV.NXT is set to SEG.SEQ+1, IRS is set to
     *    SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
     *    is an ACK), and any segments on the retransmission queue which
     *    are thereby acknowledged should be removed.
     *
     *    If SND.UNA > ISS (our SYN has been ACKed), change the connection
     *    state to ESTABLISHED, form an ACK segment
     *
     *     <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
     *
     *   and send it.  Data or controls which were queued for
     *   transmission may be included.  If there are other controls or
     *   text in the segment then continue processing at the sixth step
     *   below where the URG bit is checked, otherwise return.
     *
     *   Otherwise enter SYN-RECEIVED, form a SYN,ACK segment
     *
     *    <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
     *
     *   and send it.  If there are other controls or text in the
     *   segment, queue them for processing after the ESTABLISHED state
     *   has been reached, return.
     */
    if (is_set(seg->flags, TCP_SYN) && (acceptable || is_clr(seg->flags, TCP_ACK))) {
        tcp_do_process_options(tcb, seg, seg->pcb->ch);

        tcb->timers[TCPT_REXMT] = 0;

        /* RCV.NXT = SEG.SEQ + 1 */
        tcb->rcv_adv = tcb->rcv_nxt = seg->seq + 1;
        tcb->rcv_irs                = seg->seq; /* IRS = SEG.SEQ */

        if (is_set(seg->flags, TCP_ACK)) {
            /* If ACK present then SND.UNA = SEG.ACK; */
            tcb->snd_una = seg->ack;

            /* Update the receive advertised value */
            tcb->rcv_adv += tcb->rcv_wnd;
        }

        /* If SND.UNA > ISS change state to Established */
        if (seqGT(tcb->snd_una, tcb->snd_iss)) {
            INC_TCP_STAT(connect_established);

            tcp_do_state_change(seg->pcb, TCPS_ESTABLISHED);

            tcb->snd_wnd = seg->wnd << tcb->snd_scale;
            tcb->snd_wl1 = seg->seq - 1;

            tcp_set_CWND(tcb);
        } else
            tcp_do_state_change(seg->pcb, TCPS_SYN_RCVD);

        /* Force an ACK to be sent */
        seg->pcb->tcb->tflags |= TCBF_ACK_NOW;

        do_process_data(seg);
        return TCP_INPUT_NEXT_CHNL_RECV;
    }

    return TCP_INPUT_NEXT_PKT_DROP;
}

/**
 * TCP retransmit timer update and calculation code with comments from RFC6299.
 */
static int
tcp_calculate_RTT(struct tcb_entry *tcb, int16_t rtt)
{
    /* RFC6298 pg 2
     *
     * The rules governing the computation of SRTT, RTTVAR, and RTO are as
     * follows:
     *
     * (2.1) Until a round-trip time (RTT) measurement has been made for a
     *       segment sent between the sender and receiver, the sender SHOULD
     *       set RTO <- 1 seconds though the "backing off" on repeated
     *       retransmission discussed in (5.5) still applies.
     *
     *       Note that the previous version of this document used an initial
     *       RTO of 3 seconds [PA00].  A TCP implementation MAY still use
     *       this value (or any other value > 1 second).  This change in the
     *       lower bound on the initial RTO is discussed in further detail
     *       in Appendix A.
     */
    if (tcb->srtt != 0) {
        int16_t delta;

        /*
         * RFC6298 pg 2
         *
         * (2.3) When a subsequent RTT measurement R' is made, a host MUST set
         *      RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
         *      SRTT <- (1 - alpha) * SRTT + alpha * R'
         *
         *      The value of SRTT used in the update to RTTVAR is its value
         *      before updating SRTT itself using the second assignment. That
         *      is, updating RTTVAR and SRTT MUST be computed in the above
         *      order.
         *
         * The above SHOULD be computed using alpha=1/8 and beta=1/4 (as
         * suggested in [JK88]).
         *
         * After the computation, a host MUST update
         *      RTO <- SRTT + max (G, K*RTTVAR)
         *
         * Note: The values are scaled to allow for fixed point math.
         *       srtt is shifted up by 3 or times 8.
         *       rttvar is shifted up by 2 or times 4.
         *
         *       The code uses (srtt >> 3) + (rttvar >> 2) for the RTO value
         *       and is not computed here.
         *
         *       The rtt value is decremented by one because rtt is used as a
         *       flag to detect when a segment is timed. When a segment is to
         *       be timed in tcp output it will be set to one and bumped by
         *       the slow timeout routine.
         *
         * (2.4) Whenever RTO is computed, if it is less than 1 second, then the
         *       RTO SHOULD be rounded up to 1 second.
         *
         *         Traditionally, TCP implementations use coarse grain clocks to
         *         measure the RTT and trigger the RTO, which imposes a large
         *         minimum value on the RTO.  Research suggests that a large
         *         minimum RTO is needed to keep TCP conservative and avoid
         *         spurious retransmissions [AP99].  Therefore, this specification
         *         requires a large minimum RTO as a conservative approach, while
         */
        delta = rtt - 1 - (tcb->srtt >> TCP_RTT_SHIFT);

        if ((tcb->srtt += delta) <= 0)
            tcb->srtt = 1;

        if (delta < 0)
            delta = -delta;

        delta -= (tcb->rttvar >> TCP_RTTVAR_SHIFT);

        if ((tcb->rttvar += delta) <= 0)
            tcb->rttvar = 1;
    } else {
        /* RFC6298 pg 2
         *
         * (2.2) When the first RTT measurement R is made, the host MUST set
         *      SRTT <- R
         *      RTTVAR <- R/2
         *      RTO <- SRTT + max (G, K*RTTVAR)
         * where K = 4.
         */
        tcb->srtt = rtt << TCP_RTT_SHIFT; /* SRTT <- R */
        /* RTTVAR <- SRTT + max(G, K*RTTVAR) */
        tcb->rttvar = rtt << (TCP_RTTVAR_SHIFT - 1);
    }

    tcb->rtt      = 0;
    tcb->rxtshift = 0;

    tcb->rxtcur = tcp_range_set(tcpRexmtVal(tcb), tcb->rttmin, TCP_REXMTMAX_TV);

    return 0;
}

/**
 * Update the congestion window value in the TCB structure. When cwnd < then
 * ssthresh then we are in slow start. If greater then or equal to ssthresh
 * then we are in congestion avoidance.
 *
 * RFC2581: pg 4
 * During slow start, a TCP increments cwnd by at most SMSS bytes for
 * each ACK received that acknowledges new data. Slow start ends when
 * cwnd exceeds ssthresh (or, optionally, when it reaches it, as noted
 * above) or when congestion is observed.
 *
 * During congestion avoidance, cwnd is incremented by 1 full-sized
 * segment per round-trip time (RTT). Congestion avoidance continues
 * until congestion is detected. One formula commonly used to update
 * cwnd during congestion avoidance is given in equation 2:
 *       cwnd += SMSS*SMSS/cwnd (2)
 */
static void
tcp_update_cwnd(struct tcb_entry *tcb)
{
    uint32_t cwnd = tcb->snd_cwnd;
    uint32_t incr = tcb->max_mss;

    /*
     * When cwnd is <= to ssthresh, we are in slow-start else
     * congestion avoidance.
     */
    if (cwnd > tcb->snd_ssthresh)
        incr = incr * incr / cwnd; /* cwnd += SMSS*SMSS/cwnd (2) */

    /* Increase the cwnd by SMSS value unless in congestion avoidance */
    tcb->snd_cwnd = CNE_MIN((int)(cwnd + incr), TCP_MAXWIN << tcb->snd_scale);
}

/**
 * Update the segment information values in the TCB structure.
 */
static void
tcb_segment_update(struct seg_entry *seg, struct tcb_entry *tcb)
{
    /* RFC1122 - p94
     *
     * (f) Check ACK field, SYN-RECEIVED state, p. 72: When the
     *     connection enters ESTABLISHED state, the variables
     *     listed in (c) must be set.
     *
     * SND.WND  = SEG.WND;
     * SND.WL1  = SEG.SEQ;
     * SND.WL2  = SEG.ACK;
     */
    tcb->snd_wnd = seg->wnd; /* window is scaled already */
    tcb->snd_wl1 = seg->seq;
    tcb->snd_wl2 = seg->ack;

    if (tcb->snd_wnd > tcb->max_sndwnd)
        tcb->max_sndwnd = tcb->snd_wnd;

    /* Force output to update window */
    tcb->tflags |= TCBF_NEED_OUTPUT;
}

/**
 * Handle the Syn Received state of the given segment or TCB.
 */
static int
do_segment_others(struct seg_entry *seg)
{
    struct tcb_entry *tcb = seg->pcb->tcb;
    struct chnl *ch       = seg->pcb->ch;
    int32_t trim;
    bool acceptable;

    /* RFC793 - p70
     *
     * First, check sequence number
     *
     * SYN-RECEIVED STATE
     * ESTABLISHED  STATE
     * FIN-WAIT-1   STATE
     * FIN-WAIT-2   STATE
     * CLOSE-WAIT   STATE
     * CLOSING      STATE
     * LAST-ACK     STATE
     * TIME-WAIT    STATE
     */
    acceptable = tcp_do_segment(seg);

    /*
     * If an incoming segment is not acceptable, an acknowledgment should
     * be send in reply (unless the RST bit is set, if so drop the segment
     * and return).
     *      <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
     * After sending the acknowledgment, drop the unacceptable segment and
     * return.
     */
    if (acceptable == false) {
        CNE_WARN("Segment not acceptable\n");
        return tcp_drop_after_ack(seg);
    }

    /*
     * In the following it is assumed that the segment is the idealized
     * segment that begins at RCV.NXT and does not exceed the window.
     * One could tailor actual segments to fit this assumption by
     * trimming off any portions that lie outside the window (including
     * SYN and FIN), and only processing further if the segment then
     * begins at RCV.NXT. Segments with higher beginning sequence
     * numbers should be held for later processing.
     */
    trim = seg->seq - (tcb->rcv_nxt + tcb->rcv_wnd);

    /*
     * If trim is greater then zero, we have a case where the seq number
     * is after the window and (seq + len) is before the window.
     *
     * In the tcp_do_segment() routine we accept packets with ACK, URG or RST
     * when the window is closed.
     */
    if (trim > 0) {
        CNE_WARN("Seq before window\n");
        goto drop;
    }

    trim += seg->len;

    if (trim > 0) {
        if (trim >= seg->len) {
        drop:
            /*
             * When the window is closed only take segments at the window edge,
             * but remember to ACK the segment.
             *
             * The assumption is that (tcb->rcv_wnd == 0) as we can not get to
             * this point without RCV.WND being non-zero.
             */
            if (seg->seq == tcb->rcv_nxt)
                tcb->tflags |= TCBF_ACK_NOW;
            else
                return tcp_drop_after_ack(seg);
        }

        /*
         * Trim the segments to fit the window to match the idealized
         * segment that begins at RCV.NXT and does not exceed the window.
         */
        pktmbuf_prepend(seg->mbuf, trim);

        /* Reset the FIN bit if it was set, as we trimmed the last byte off. */
        seg->flags &= ~(TCP_PSH | TCP_FIN);
    }

    /* RFC793 - p70
     *
     * Second, if the RST bit is set
     *
     * If this connection was initiated with a passive OPEN (i.e.,
     * came from the LISTEN state), then return this connection to
     * LISTEN state and return. The user need not be informed. If
     * this connection was initiated with an active OPEN (i.e., came
     * from SYN-SENT state) then the connection was refused, signal
     * the user "connection refused". In either case, all segments
     * on the retransmission queue should be removed. And in the
     * active OPEN case, enter the CLOSED state and delete the TCB,
     * and return.
     *
     * SYN-RECEIVED STATE
     *   If the RST bit is set
     *     If this connection was initiated with a passive OPEN (i.e.,
     *     came from the LISTEN state), then return this connection to
     *     LISTEN state and return. The user need not be informed. If
     *     this connection was initiated with an active OPEN (i.e., came
     *     from SYN-SENT state) then the connection was refused, signal
     *     the user "connection refused". In either case, all segments
     *     on the retransmission queue should be removed. And in the
     *     active OPEN case, enter the CLOSED state and delete the TCB,
     *     and return.
     * ESTABLISHED
     * FIN-WAIT-1
     * FIN-WAIT-2
     * CLOSE-WAIT
     *   If the RST bit is set then, any outstanding RECEIVEs and SEND
     *   should receive "reset" responses. All segment queues should be
     *   flushed. Users should also receive an unsolicited general
     *   "connection reset" signal. Enter the CLOSED state, delete the
     *   TCB, and return.
     * CLOSING STATE
     * LAST-ACK STATE
     * TIME-WAIT
     *   If the RST bit is set then, enter the CLOSED state, delete the
     *   TCB, and return.
     */
    if (is_set(seg->flags, TCP_RST)) {
        CNE_WARN("RST is set ( %s)\n", tcp_print_flags(seg->flags));

        INC_TCP_STAT(connect_resets);

        /* Handle moving a connection back to the Listen state, if passive */
        if (is_set(tcb->tflags, TCBF_PASSIVE_OPEN)) {
            /*
             * SYN_RCVD state remove from half open queue of the parent, if
             * started from a passive open.
             */
            if (tcb->ppcb && tcb->ppcb->tcb && tcb->ppcb->tcb->half_open_q) {
                uint32_t idx = vec_find_index(tcb->ppcb->tcb->half_open_q, seg->pcb);

                vec_at_index(tcb->ppcb->tcb->half_open_q, idx) = NULL;
            }

            tcp_do_state_change(seg->pcb, TCPS_LISTEN);

            return TCP_INPUT_NEXT_PKT_DROP;
        }

        tcp_do_drop_connection(seg->pcb, ECONNRESET);
        return TCP_INPUT_NEXT_PKT_DROP;
    }
    /*
     * NOT Done: Third check security and precedence
     */

    /*
     * RFC 1323 PAWS: If a timestamp value and less then ts_recent,
     * drop it.
     *
     * The following must be true.
     * - The RST bit can not be set and
     * - TCP has received a valid timestamp from the peer (SEG.TSval) and
     * - the previously received timestamp (TS.Recent) is valid and
     * - the received timestamp in the segment ts_val is less then the
     *   previously received timestamp from this peer.
     */
    if ((seg->ts_val > 0) && (tcb->ts_recent > 0) && tstampLT(seg->ts_val, tcb->ts_recent)) {
        /* Check if the ts_recent is 24 days old */
        if ((stk_get_timer_ticks() - tcb->ts_recent_age) > TCP_PAWS_IDLE)
            /*
             * Invalidate ts_val, which will be placed in the next
             * echo reply (via ts_recent) of the timestamp option.
             */
            seg->ts_val = 0;
        else {
            CNE_WARN("TimeStamp failed\n");
            return tcp_drop_after_ack(seg);
        }
    }

    /* RFC793 - p71
     *
     * Fourth, check the SYN bit
     *
     * If the SYN is in the window it is an error, send a reset, any
     * outstanding RECEIVEs and SEND should receive "reset" responses,
     * all segment queues should be flushed, the user should also
     * receive an unsolicited general "connection reset" signal, enter
     * the CLOSED state, delete the TCB, and return.
     *
     * If the SYN is not in the window this step would not be reached
     * and an ack would have been sent in the first step (sequence
     * number check).
     */
    if (is_set(seg->flags, TCP_SYN)) {
        /* RFC1122 - p94
         *
         * (e) Check SYN bit, p. 71: "In SYN-RECEIVED state and if
         *     the connection was initiated with a passive OPEN, then
         *     return this connection to the LISTEN state and return.
         *     Otherwise...".
         */
        if ((tcb->state == TCPS_SYN_RCVD) && is_set(tcb->tflags, TCBF_PASSIVE_OPEN)) {
            tcp_do_state_change(seg->pcb, TCPS_LISTEN);
            CNE_WARN("Moved to LISTEN\n");
        } else {
            tcp_drop_with_reset(tcb->netif, seg, seg->pcb);
            tcp_do_state_change(seg->pcb, TCPS_CLOSED);
            CNE_WARN("Moved to CLOSED\n");
        }

        return TCP_INPUT_NEXT_PKT_DROP;
    }

    /* RFC73 - p72
     *
     * Fifth, check the ACK bit
     *
     * if the ACK bit is off drop the segment and return
     *   If the ACK bit is set ...
     */
    if (is_clr(seg->flags, TCP_ACK)) {
        CNE_WARN("ACK is NOT set Stop Processing\n");
        return TCP_INPUT_NEXT_PKT_DROP;
    }

    /* Did we get our FIN acked and did we send a FIN ? */
    tcb->tflags |= (((seg->ack - tcb->snd_una) > ch->ch_snd.cb_cc) && (tcb->tflags & TCBF_SENT_FIN))
                       ? TCBF_OUR_FIN_ACKED
                       : 0;

    switch (tcb->state) {
    case TCPS_SYN_RCVD:
        /* RFC793 - p72
         *
         * If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
         * and continue processing.
         */
        if (seqGT(tcb->snd_una, seg->ack) || seqGT(seg->ack, tcb->snd_max)) {
            /* RFC793 - p72
             *
             * If the segment acknowledgment is not acceptable, form a
             * reset segment,
             *     <SEQ=SEG.ACK><CTL=RST>
             * and send it.
             */
            tcp_drop_with_reset(tcb->netif, seg, seg->pcb);
            CNE_WARN("SYN_RCVD\n");
            return TCP_INPUT_NEXT_PKT_DROP;
        } else
            tcp_do_state_change(seg->pcb, TCPS_ESTABLISHED);

        /* Update the snd_wl1 with the current seq minus 1 */
        tcb->snd_wl1 = seg->seq - 1;

        /* FALLTHRU */
        /*
         * FIN-WAIT-1 STATE
         * In addition to the processing for the ESTABLISHED state, if
         * our FIN is now acknowledged then enter FIN-WAIT-2 and continue
         * processing in that state.
         */
    case TCPS_FIN_WAIT_1:

        /* FALLTHRU */
        /*
         * FIN-WAIT-2 STATE
         * In addition to the processing for the ESTABLISHED state, if
         * the retransmission queue is empty, the users CLOSE can be
         * acknowledged ("ok") but do not delete the TCB.
         */
    case TCPS_FIN_WAIT_2:

        /* FALLTHRU */

        /*
         * CLOSE-WAIT STATE
         * Do the same processing as for the ESTABLISHED state.
         */
    case TCPS_CLOSE_WAIT:

        /* FALLTHRU */

        /*
         * CLOSING STATE
         * In addition to the processing for the ESTABLISHED state, if
         * the ACK acknowledges our FIN then enter the TIME-WAIT state,
         * otherwise ignore the segment.
         */
    case TCPS_CLOSING:

        /* FALLTHRU */

        /*
         * ESTABLISHED State
         *
         * If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
         * Any segments on the retransmission queue which are thereby
         * entirely acknowledged are removed. Users should receive
         * positive acknowledgments for buffers which have been SENT and
         * fully acknowledged (i.e., SEND buffer should be returned with
         * "ok" response). If the ACK is a duplicate
         * (SEG.ACK < SND.UNA), it can be ignored. If the ACK acks
         * something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
         * drop the segment, and return.
         *
         * RFC1122 - p94
         *
         * (g) Check ACK field, ESTABLISHED state, p. 72: The ACK is a
         *     duplicate if SEG.ACK =< SND.UNA (the = was omitted).
         *     Similarly, the window should be updated if:
         *     SND.UNA =< SEG.ACK =< SND.NXT.
         */
    case TCPS_ESTABLISHED:
        /*
         * If the ACK is a duplicate (SEG.ACK =< SND.UNA), ignore it or
         * process as a fast retransmit.
         */
        if (seqLEQ(seg->ack, tcb->snd_una)) {
            if ((seg->len == 0) && (seg->wnd == tcb->snd_wnd)) {
                if ((tcb->timers[TCPT_REXMT] == 0) || (seg->ack != tcb->snd_una))
                    tcb->dupacks = 0;

                /* RFC2581: pg 6
                 * 1. When the third duplicate ACK is received, set ssthresh to
                 *    no more than the value given in equation 3.
                 *
                 *     ssthresh = max (FlightSize / 2, 2*SMSS) (3)
                 */
                else if (++tcb->dupacks == TCP_RETRANSMIT_THRESHOLD) {
                    uint32_t onxt = tcb->snd_max;
                    uint32_t win  = CNE_MIN(tcb->snd_wnd, tcb->snd_cwnd) / 2 / tcb->max_mss;

                    if (win < 2)
                        win = 2;
                    /* Equation (3): ssthresh = max (FlightSize / 2,
                      2*SMSS) */
                    tcb->snd_ssthresh       = win * tcb->max_mss;
                    tcb->timers[TCPT_REXMT] = 0;
                    tcb->rtt                = 0;
                    tcb->snd_nxt            = seg->ack;
                    tcb->snd_cwnd           = tcb->max_mss;

                    tcp_output(tcb);
                    /*
                     * 2. Retransmit the lost segment and set cwnd to
                     *ssthresh
                     *    plus 3*SMSS. This artificially "inflates" the
                     *    congestion window by the number of segments
                     *(three)
                     *    that have left the network and which the receiver
                     *    has buffered.
                     */
                    CNE_WARN("Hit dupacks threshold, Set need output and Fast rexmt\n");
                    tcb->snd_cwnd = tcb->snd_ssthresh + (TCP_RETRANSMIT_THRESHOLD * tcb->max_mss);
                    if (seqGT(onxt, tcb->snd_nxt))
                        tcb->snd_nxt = onxt;
                }
                /* RFC2581: pg 7
                 * 3. For each additional duplicate ACK received, increment
                 *cwnd
                 *    by SMSS. This artificially inflates the congestion window
                 *    in order to reflect the additional segment that has left
                 *    the network.
                 */
                else if (tcb->dupacks > TCP_RETRANSMIT_THRESHOLD) {
                    CNE_WARN("Retransmit Threshold hit %d\n", tcb->dupacks);
                    tcb->snd_cwnd += tcb->max_mss;
                    tcp_output(tcb);
                    return TCP_INPUT_NEXT_PKT_DROP;
                }
            } else {
                tcb->dupacks = 0;
                tcp_update_acked_data(seg, tcb);
            }
            break;
        }

        /*
         * If the ACK acks something not yet sent (SEG.ACK > SND.MAX)
         * then send an ACK, drop the segment and return.
         */
        if (seqGT(seg->ack, tcb->snd_max)) {
            CNE_WARN("Ack unsent data SEG.ACK %u > %u SND.MAX, Drop\n", seg->ack, tcb->snd_max);
            return tcp_drop_after_ack(seg);
        }

        /*
         * RFC2581: pg7
         * 4. Transmit a segment, if allowed by the new value of cwnd and the
         *    receiver's advertised window.
         *
         * 5. When the next ACK arrives that acknowledges new data, set cwnd
         *    to ssthresh (the value set in step 1). This is termed "deflating"
         *    the window.
         *
         *    This ACK should be the acknowledgment elicited by the
         *    retransmission from step 1, one RTT after the retransmission
         *    (though it may arrive sooner in the presence of significant
         *    out-of-order delivery of data segments at the receiver).
         *    Additionally, this ACK should acknowledge all the intermediate
         *    segments sent between the lost segment and the receipt of the
         *    third duplicate ACK, if none of these were lost.
         */
        if (tcb->dupacks > 0) {
            CNE_WARN("Dup ACKs %d\n", tcb->dupacks);

            if (tcb->dupacks >= TCP_RETRANSMIT_THRESHOLD)
                tcb->snd_cwnd = tcb->snd_ssthresh;

            tcb->dupacks = 0;
            if (seqGT(seg->ack, tcb->snd_max))
                return TCP_INPUT_NEXT_PKT_DROP;
        }

        /*
         * Remove the acknowledged segments from the
         * retransmission queue.
         */
        tcp_update_acked_data(seg, tcb);

        /* FALLTHRU */
    default:
        break;

        /*
         * The only thing that can arrive in this state is a
         * acknowledgment of our fin.  If our FIN is now acknowledged,
         * delete the TCB, enter the  CLOSED state, and return.
         */
    case TCPS_LAST_ACK:
        if (is_set(tcb->tflags, TCBF_OUR_FIN_ACKED)) {
            tcp_do_state_change(seg->pcb, TCPS_CLOSED);
            CNE_WARN("After FIN acked\n");
            return TCP_INPUT_NEXT_PKT_DROP;
        }

        break;

        /*
         * In TIME_WAIT state the only thing that should arrive
         * is a retransmission of the remote FIN.  Acknowledge
         * it and restart the finack timer.
         */
    case TCPS_TIME_WAIT:

        /* When FIN is not set then we drop the segment */
        if (is_clr(seg->flags, TCP_FIN)) {
            CNE_NOTICE("FIN set in TIME_WAIT\n");
            return TCP_INPUT_NEXT_PKT_DROP;
        }

        /* Retransmission of FIN bit then ACK it. */
        tcp_do_state_change(seg->pcb, TCPS_TIME_WAIT);
        CNE_WARN("After move to TIME_WAIT\n");
        return tcp_drop_after_ack(seg);
    }

    /*
     * If SND.UNA =< SEG.ACK =< SND.MAX, the send window should be
     * updated. If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
     * SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
     * SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
     *
     * Note that SND.WND is an offset from SND.UNA, that SND.WL1
     * records the sequence number of the last segment used to
     * update SND.WND, and that SND.WL2 records the acknowledgment
     * number of the last segment used to update SND.WND. The check
     * here prevents using old segments to update the window.
     */
    if (is_set(seg->flags, TCP_ACK) &&
        ((seqLT(tcb->snd_wl1, seg->seq) || (tcb->snd_wl1 == seg->seq)) &&
         ((seqLT(tcb->snd_wl2, seg->ack) || (tcb->snd_wl2 == seg->ack)) &&
          seg->wnd > tcb->snd_wnd))) {

        tcb_segment_update(seg, tcb);
    }

    /* Process the retransmit timer value, use timestamp if present. */
    if (is_set(seg->sflags, SEG_TS_PRESENT) && (seg->ts_ecr != 0))
        tcp_calculate_RTT(tcb, (stk_get_timer_ticks() - seg->ts_ecr) + 1);
    else if ((tcb->rtt != 0) && seqGT(seg->ack, tcb->rttseq))
        tcp_calculate_RTT(tcb, (stk_get_timer_ticks() - tcb->rtt) + 1);

    /*
     * When the ACK equals the Max ACK then clear the retransmit timer or
     * reset the retransmit timer to the current RTO value.
     */
    if (seg->ack == tcb->snd_max)
        tcb->timers[TCPT_REXMT] = 0;
    else if (tcb->timers[TCPT_PERSIST] == 0)
        tcb->timers[TCPT_REXMT] = tcb->rxtcur;

    /* Update the congestion window for this connection. */
    tcp_update_cwnd(tcb);

    /* Sixth, check the URG bit */
    if (is_set(seg->flags, TCP_URG)) {
        CNE_WARN("URG is set\n");

        switch (tcb->state) {
            /*
             * If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP),
             * and signal the user that the remote side has urgent
             * data if the urgent pointer (RCV.UP) is in advance of
             * the data consumed. If the user has already been
             * signaled (or is still in the "urgent mode") for this
             * continuous sequence of urgent data, do not signal the
             * user again.
             */
        case TCPS_ESTABLISHED:
        case TCPS_FIN_WAIT_1:
        case TCPS_FIN_WAIT_2:
            tcb->rcv_urp = CNE_MAX(tcb->rcv_urp, seg->urp);
            break;

            /*
             * This should not occur, since a FIN has been received
             * from the remote side. Ignore the URG.
             */
        case TCPS_CLOSE_WAIT:
        case TCPS_CLOSING:
        case TCPS_LAST_ACK:
        case TCPS_TIME_WAIT:
            break;

        default:
            break;
        }
    }

    /* seventh, process the segment text,
     *
     * ESTABLISHED STATE
     * FIN-WAIT-1 STATE
     * FIN-WAIT-2 STATE
     *
     * Once in the ESTABLISHED state, it is possible to deliver segment
     * text to user RECEIVE buffers. Text from segments can be moved
     * into buffers until either the buffer is full or the segment is
     * empty. If the segment empties and carries an PUSH flag, then
     * the user is informed, when the buffer is returned, that a PUSH
     * has been received.
     *
     * When the TCP takes responsibility for delivering the data to the
     * user it must also acknowledge the receipt of the data.
     *
     */
    if (TCPS_HAVE_RCVD_FIN(tcb->state) == 0)
        do_process_data(seg);

    /*
     * Once the TCP takes responsibility for the data it advances
     * RCV.NXT over the data accepted, and adjusts RCV.WND as
     * apporopriate to the current buffer availability. The total of
     * RCV.NXT and RCV.WND should not be reduced.
     *
     * Please note the window management suggestions in section 3.7.
     *
     * do_process_data() will handle sending the ACK.
     *
     * If we have already received a FIN from the remote side, ignore
     * the segment text (if any). (This should not occur.)
     */

    /* Eight, check the FIN bit */
    if (is_set(seg->flags, TCP_FIN)) {
        /*
         * Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
         * since the SEG.SEQ cannot be validated; drop the segment and
         * return.
         */
        if (tcb->state < TCPS_SYN_RCVD) {
            CNE_WARN("state < SYN_RCVD, Stop\n");
            return TCP_INPUT_NEXT_PKT_DROP;
        }

        /*
         * If the FIN bit is set, signal the user "connection closing" and
         * return any pending RECEIVEs with same message, advance RCV.NXT
         * over the FIN, and send an acknowledgment for the FIN. Note that
         * FIN implies PUSH for any segment text not yet delivered to the
         * user.
         */
        if (TCPS_HAVE_RCVD_FIN(tcb->state)) {
            tcb->rcv_nxt++;

            /* Send ACK for the FIN */
            tcb->tflags |= TCBF_ACK_NOW;
        }

        switch (tcb->state) {
        /*
         * Enter the CLOSE-WAIT state.
         */
        /* case TCPS_SYN_RCVD: Not required, but listed in RFC 793*/
        case TCPS_ESTABLISHED:
            tcp_do_state_change(tcb->pcb, TCPS_CLOSE_WAIT);
            break;

        /*
         * If our FIN has been ACKed (perhaps in this segment), then
         * enter TIME-WAIT, start the time-wait timer, turn off the other
         * timers; otherwise enter the CLOSING state.
         */
        case TCPS_FIN_WAIT_1:
            /* Handle the simultaneous closing condition */
            tcp_do_state_change(tcb->pcb, (tcb->snd_nxt == seg->ack)
                                              ?
                                              /* Restart the 2MSL timer */ TCPS_TIME_WAIT
                                              :
                                              /* Simultaneous closing */ TCPS_CLOSING);
            break;

        /*
         * Enter the TIME-WAIT state. Start the time-wait timer, turn
         * off the other timers.
         */
        case TCPS_FIN_WAIT_2:
            tcp_do_state_change(tcb->pcb, TCPS_TIME_WAIT);
            tcb->timers[TCPT_2MSL] = 2 * TCP_MSL_TV;
            break;

        /* FALLTHRU */

        /*
         * Remain in the TIME-WAIT state. Restart the 2 MSL time-wait
         * timeout.
         */
        case TCPS_TIME_WAIT:
            tcb->timers[TCPT_2MSL] = 2 * TCP_MSL_TV;
            break;

        /*
         * Remain in the current state for the following.
         *
         * TCPS_CLOSE_WAIT:
         * TCPS_CLOSING:
         * TCPS_LAST_ACK:
         * TCPS_CLOSED:
         * TCPS_SYN_SENT:
         * TCPS_LISTEN:
         */
        default:
            break;
        }
    }

    return 0;
}

/**
 * Do the delivery of a segmemt and call the correct handler for the given state.
 */
static inline int
do_segment_arrives(struct seg_entry *seg)
{
    struct tcb_entry *tcb = seg->pcb->tcb;
    int32_t win;
    int rc;

    /*
     * Calculate amount of space in receive window, and then do TCP input
     * processing. Receive window is amount of space in rcv queue,
     * but not less than advertised window.
     */
    win          = cb_space(&seg->pcb->ch->ch_rcv);
    tcb->rcv_wnd = CNE_MAX(win, (int32_t)(tcb->rcv_adv - tcb->rcv_nxt));

    switch (seg->pcb->tcb->state) {
    /* Handle passive open data.        p65-p66 */
    case TCPS_LISTEN:
        rc = do_segment_listen(seg);
        break;

    /* Handle active open data/         p66-p68 */
    case TCPS_SYN_SENT:
        rc = do_segment_syn_sent(seg);
        break;

    /* Otherwise.                       p69-p76 */
    default:
        rc = do_segment_others(seg);
        break;
    }
    return rc;
}

/**
 * Update the acked data and remove all of the acked data from the
 * retransmit queue.
 */
static void
tcp_update_acked_data(struct seg_entry *seg, struct tcb_entry *tcb)
{
    struct chnl *ch;
    uint32_t acked;

    if (!tcb || !seg) {
        CNE_ERR("seg %p or tcb %p is NULL\n", seg, tcb);
        return;
    }

    if (!seg->pcb) {
        CNE_ERR("seg->pcb %p is NULL\n", seg->pcb);
        return;
    }
    ch = seg->pcb->ch;

    if (!ch) { /* possible passive open, no channel assigned */
        CNE_NOTICE("Possible passive open segment\n");
        return;
    }

    /* Figure out the number of bytes acked, could be zero if SYN was acked. */
    acked = seg->ack - tcb->snd_una;

    /*
     * If we are acking more data then what is in the send buffer we have seen
     * the FIN bit. The FIN seen flag should have been set already.
     */
    acked = (acked > ch->ch_snd.cb_cc) ? ch->ch_snd.cb_cc : acked;

    /* cb_cc could be zero and acking the FIN, don't do extra work. */
    if (acked) {
        tcb->snd_wnd -= acked;
        cnet_drop_acked_data(&ch->ch_snd, acked);
    }

    /* wakeup the writers if we have space >= low water mark */
    if (cb_space(&ch->ch_snd) >= ch->ch_snd.cb_lowat) {
        /* Allow the users to put more data in send buffer */
        ch_wwakeup(ch);
    }

    /* Update the send unacked variable to the current acked value */
    tcb->snd_una = seg->ack;

    /* When snd_nxt becomes less than snd_una, update snd_nxt. */
    if (seqLT(tcb->snd_nxt, tcb->snd_una)) {
        CNE_WARN("Update snd_nxt to snd_una\n");
        tcb->snd_nxt = tcb->snd_una;
    }

    switch (tcb->state) {
    /*
     * In FIN_WAIT_1 STATE in addition to the processing
     * for the ESTABLISHED state if our FIN is now acknowledged
     * then enter FIN_WAIT_2.
     */
    case TCPS_FIN_WAIT_1:
        if (is_set(tcb->tflags, TCBF_OUR_FIN_ACKED)) {
            /*
             * If we can't receive any more
             * data, then closing user can proceed.
             * Starting the timer is contrary to the
             * specification, but if we don't get a FIN
             * we'll hang forever.
             */
            ch->ch_state |= _ISDISCONNECTED;
            tcp_do_state_change(seg->pcb, TCPS_FIN_WAIT_2);
        }

        break;

    /*
     * In CLOSING STATE in addition to the processing for
     * the ESTABLISHED state if the ACK acknowledges our FIN
     * then enter the TIME-WAIT state, otherwise ignore
     * the segment.
     */
    case TCPS_CLOSING:
        if (is_set(tcb->tflags, TCBF_OUR_FIN_ACKED))
            tcp_do_state_change(seg->pcb, TCPS_TIME_WAIT);

        break;
    }
}

#define ENABLE_HEADER_PREDICTION
#ifdef ENABLE_HEADER_PREDICTION
static int
tcp_header_prediction(struct seg_entry *seg, struct tcb_entry *tcb)
{
    struct chnl *ch = seg->pcb->ch;

    /*
     * When ACK falls within the segment's sequence number and the
     * timestamp is present, grab the timestamp and update timestamp age.
     */
    if (is_set(seg->sflags, SEG_TS_PRESENT) && tstampLEQ(seg->ts_val, tcb->ts_recent) &&
        seqLT(tcb->last_ack_sent, seg->seq)) {
        tcb->ts_recent_age = stk_get_timer_ticks();
        tcb->ts_recent     = seg->ts_val;
    }

    /* Handle the ACK prediction or when length is zero. */
    if (!seg->len) {
        /*
         * The ack must be greater then unacknowledged data and the ACK
         * is less then the MAX sent, with the congestion window being
         * greater then or equal to the current expected window size.
         */
        if (seqGT(seg->ack, tcb->snd_una) && seqLEQ(seg->ack, tcb->snd_max) &&
            (tcb->snd_cwnd >= tcb->snd_wnd)) {

            INC_TCP_STAT(ack_predicted);

            /* Process the retransmit timer, use timestamp if present. */
            if (is_set(seg->sflags, SEG_TS_PRESENT))
                tcp_calculate_RTT(tcb, stk_get_timer_ticks() - seg->ts_ecr + 1);
            else if (tcb->rtt && seqGT(seg->ack, tcb->rttseq))
                tcp_calculate_RTT(tcb, tcb->rtt);

            cnet_drop_acked_data(&ch->ch_snd, (seg->ack - tcb->snd_una));

            tcb->snd_una = seg->ack;

            if (tcb->snd_una == tcb->snd_max)
                tcb->timers[TCPT_REXMT] = 0;
            else if (tcb->timers[TCPT_PERSIST] == 0)
                tcb->timers[TCPT_REXMT] = tcb->rxtcur;

            /* Allow the users to put more data in send buffer */
            if (cb_space(&ch->ch_snd) >= ch->ch_snd.cb_lowat)
                ch_wwakeup(ch);

            /* When we have more data to send then call output routine */
            if (ch->ch_snd.cb_cc > 0)
                tcp_do_output(tcb);

            return TCP_INPUT_NEXT_PKT_DROP;
        }
    }
    /* Handle the data prediction.
     *
     * When ack is the expected ack, the reassemble queue is empty and
     * the receive buffer is able to accept the data.
     */
    else if ((seg->ack == tcb->snd_una) && vec_len(tcb->reassemble) == 0 &&
             (seg->len <= cb_space(&ch->ch_rcv))) {

        INC_TCP_STAT(data_predicted);

        _process_data(seg, tcb);

        if (is_clr(tcb->tflags, TCBF_DELAYED_ACK))
            tcb->tflags |= TCBF_DELAYED_ACK;
        else {
            tcb->tflags |= TCBF_ACK_NOW;
            tcp_output(tcb);
        }

        return TCP_INPUT_NEXT_PKT_DROP;
    }
    return TCP_INPUT_NEXT_PKT_DROP;
}
#endif

static inline void
tcp_strip_ip_options(pktmbuf_t *mbuf)
{
    struct cne_ipv4_hdr *ip;
    int opt_len = (mbuf->l3_len - sizeof(struct cne_ipv4_hdr));

    if (opt_len == 0)
        return;

    ip = pktmbuf_mtod_offset(mbuf, struct cne_ipv4_hdr *, -mbuf->l3_len);

    pktmbuf_trim(mbuf, opt_len);

    /* remove the IP options */
    memcpy(&ip[1], (char *)&ip[1] - opt_len, pktmbuf_data_len(mbuf) - mbuf->l3_len);
}

/**
 * Process the incoming packet bytes using page 65 of RFC793. The routine is
 * called from the lower layers to process all TCP type packets.
 */
int
cnet_tcp_input(struct pcb_entry *pcb, pktmbuf_t *mbuf)
{
    struct cne_ipv4_hdr *ip;
    struct cne_tcp_hdr *tcp;
    uint8_t *opts = NULL;
    int rc        = TCP_INPUT_NEXT_PKT_DROP;
    struct seg_entry *seg;
    uint16_t tlen;
    struct tcb_entry *tcb;
    struct cnet_metadata *md;
    uint8_t tcp_syn_fin_cnt[4] = {0, 1, 1, 2};

    if (!(this_cnet->flags & CNET_TCP_ENABLED))
        return rc;

    INC_TCP_STAT(rcvtotal);

    if (mempool_get(this_stk->seg_objs, (void **)&seg) != 0)
        return rc;

    seg->mbuf = mbuf;

    /* packet offset has been adjusted to tcp header in tcp input node */
    tcp = pktmbuf_mtod(mbuf, struct cne_tcp_hdr *);

    /* Grab the IP header pointer */
    ip = pktmbuf_mtod_offset(mbuf, struct cne_ipv4_hdr *, -mbuf->l3_len);

    /* remove IP options if found */
    tcp_strip_ip_options(mbuf);

    /* Verify the packet has enough space in the packet. */
    if (pktmbuf_data_len(mbuf) < sizeof(struct cne_tcp_hdr)) {
        INC_TCP_STAT(rcvshort);
        CNE_WARN("Packet too short %d\n", pktmbuf_data_len(mbuf));
        goto free_seg;
    }

    /* Total length of IP payload plus IP header and options */
    tlen = be16toh(ip->total_length);

    /* Calculate the TCP offset value in bytes. */
    seg->offset = (tcp->data_off & 0xF0) >> 2;

    /* Verify the TCP data and header offset is valid */
    if ((seg->offset < sizeof(struct cne_tcp_hdr)) || (seg->offset > tlen)) {
        INC_TCP_STAT(rcvbadoff);
        CNE_WARN("packet too short for TCP offset %d, tlen %d\n", seg->offset, tlen);
        goto free_seg;
    }

    /* Build the Current Segment information structure. */
    seg->ack   = be32toh(tcp->recv_ack);
    seg->seq   = be32toh(tcp->sent_seq);
    seg->wnd   = (uint32_t)be16toh(tcp->rx_win); /* Not Scaled yet! */
    seg->lport = mbuf->lport;
    seg->urp   = be16toh(tcp->tcp_urp);
    seg->flags = tcp->tcp_flags & TCP_MASK;
    seg->iplen = tlen;
    seg->ip    = (void *)ip;

    tcp_flags_dump("Received flags", seg->flags);

    CNE_INFO("Packet received seq %u, ack %u\n", seg->ack, seg->ack);

    tlen -= (seg->offset + mbuf->l3_len); /* Real TCP length */
    seg->len = tlen + tcp_syn_fin_cnt[seg->flags & SYN_FIN];

    /* Set opts to point at the options, if we have any options. */
    if (seg->offset > sizeof(struct cne_tcp_hdr))
        opts = (uint8_t *)&tcp[1];

    md = cnet_mbuf_metadata(mbuf);

    /*
     * Segment Arrives - Starting p65-p76 - RFC793
     */

    /* Locate the PCB/TCB for this segment, if not found drop with RST */
    seg->pcb = mbuf->userptr;

    /* If TCB is closed send RST.      p65     */
    if (!seg->pcb || !(tcb = seg->pcb->tcb)) {
        /*
         * If the state is CLOSED (i.e., TCB does not exist) then
         *
         *   all data in the incoming segment is discarded.  An incoming
         *   segment containing a RST is discarded.  An incoming segment
         *   not containing a RST causes a RST to be sent in response.
         *   The acknowledgment and sequence field values are selected
         *   to make the reset sequence acceptable to the TCP that sent
         *   the offending segment.
         *
         * If the ACK bit is off, sequence number zero is used,
         * 	<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
         *
         * If the ACK bit is on,
         *      <SEQ=SEG.ACK><CTL=RST>
         *
         * Return.
         */
        CNE_WARN("PCB is not found or TCB is Closed\n");

        tcp_drop_with_reset(pcb->netif, seg, seg->pcb);

        /* Drop the PCB pointer from the segment, maybe NULL already */
        seg->pcb = NULL;
        goto free_seg;
    }
    if (tcb->state == TCPS_CLOSED)
        goto free_seg;

    /* Process the packet for the given TCP state */
    tcb->idle              = 0;
    tcb->timers[TCPT_KEEP] = tcb->tcp->keep_idle;

    /* Scale the window value if not a SYN segment */
    if (is_clr(seg->flags, TCP_SYN))
        seg->wnd = seg->wnd << tcb->snd_scale;

    /* Do the option handling now, before we do anything like passive open */
    if (opts) {
        if (tcp_do_options(seg, opts)) {
            CNE_WARN("tcp_do_options() failed\n");
            goto free_seg;
        }
    }

    if (!seg->pcb->ch->ch_ch && (tcb->state == TCPS_ESTABLISHED)) {
        struct pcb_entry *p;

        /* find a local sister channel if available */
        p = cnet_pcb_locate(&this_stk->tcp->tcp_hd, &md->laddr, &md->faddr);
        /* Cross link the channels */
        if (p)
            seg->pcb->ch->ch_ch = p->ch;
    }

#ifdef ENABLE_HEADER_PREDICTION
    /*
     * TCP Header prediction.
     *
     * This code follows the code in TCP/IP Illustrated Volume II by Stevens.
     *
     * Make sure we are in the established state and we only have any ACK
     * present in the tcp flags. Also the next seq what we expect along
     * with window we expect.
     */
    if ((tcb->state == TCPS_ESTABLISHED) && ((seg->flags & HDR_PREDIC) == TCP_ACK) &&
        (is_clr(seg->sflags, SEG_TS_PRESENT) || tstampGEQ(seg->ts_val, tcb->ts_recent)) &&
        (seg->seq == tcb->rcv_nxt) && (seg->wnd && (seg->wnd == tcb->snd_wnd)) &&
        (tcb->snd_nxt == tcb->snd_max)) {
        if (tcp_header_prediction(seg, tcb)) {
            rc = TCP_INPUT_NEXT_CHNL_RECV;
            goto free_seg;
        }
    }
#endif

    pktmbuf_adj_offset(mbuf, mbuf->l4_len);

    /* Process the segment information and handle the TCP protocol */
    rc = do_segment_arrives(seg);

    /*
     * After segment processing, do we need to send a packet?
     * Must update the tcb as the pcb pointer may have changed
     */
    if (rc == TCP_INPUT_NEXT_CHECK_OUTPUT) {
        /* Get new TCB if passive open */
        tcb = seg->pcb->tcb;

        /* old Listen PCB maybe replaced with new pcb */
        if (is_set(tcb->tflags, (TCBF_NEED_OUTPUT | TCBF_ACK_NOW)) || seg->pcb->ch->ch_snd.cb_cc)
            tcp_do_output(tcb);
        rc = TCP_INPUT_NEXT_CHNL_RECV;
    }

free_seg:
    if (seg)
        mempool_put(this_stk->seg_objs, seg);
    return rc;
}

/**
 * Process the fast timeout for TCP, which processes a fast retransmit.
 */
static inline void
tcp_fast_retransmit_timo(stk_t *stk)
{
    struct pcb_hd *hd = &stk->tcp->tcp_hd;
    struct pcb_entry *p;

    if (!hd)
        return;

    /* TCP fast timer to process retransmits. */
    vec_foreach_ptr (p, hd->vec) {
        struct tcb_entry *t = p->tcb;
        if (t && is_set(t->tflags, TCBF_NEED_FAST_REXMT)) {
            t->total_retrans++;
            t->tflags &= ~TCBF_NEED_FAST_REXMT;
            tcp_do_output(t);
        }
    }
}

/**
 * Process the fast timeout for TCP, which is used for delayed ACKs.
 */
static inline void
tcp_fast_timo(void *arg)
{
    stk_t *stk        = (stk_t *)arg;
    struct pcb_hd *hd = &stk->tcp->tcp_hd;
    struct pcb_entry *p;

    if (!hd) {
        CNE_WARN("tcp_hd is NULL\n");
        return;
    }

    /* TCP fast timer to process Delayed ACKs. */
    vec_foreach_ptr (p, hd->vec) {
        struct tcb_entry *t = p->tcb;

        if (t && is_set(t->tflags, TCBF_DELAYED_ACK)) {
            t->tflags &= ~TCBF_DELAYED_ACK;
            t->tflags |= TCBF_ACK_NOW;

            INC_TCP_STAT(delayed_ACK);

            /* ACK flag is cleared in tcp output */
            tcp_do_output(t);
        }
    }
}

/**
 * Process the TCP timers for the slow timeouts or the state machine for
 * the timers and TCP.
 */
static bool
tcp_process_timer(struct pcb_entry *p, int32_t tmr)
{
    struct tcb_entry *t = p->tcb; /* tcb pointer will be valid from the caller */
    stk_t *stk          = this_stk;
    int32_t rexmt;
    uint32_t win;
    bool state = false;

    switch (tmr) {
    case TCPT_2MSL:
        if ((t->state != TCPS_TIME_WAIT) && (t->idle <= stk->tcp->max_idle))
            t->timers[tmr] = stk->tcp->keep_intvl;
        else {
            tcp_do_state_change(p, TCPS_CLOSED);
            state = true;
        }

        break;

    case TCPT_PERSIST:
        /* When we reach max persist timeouts, then drop connection */
        if (t->rxtshift == TCP_MAXRXTSHIFT)
            tcp_do_drop_connection(t->pcb, 0);
        else {
            /* Cleared in tcp send segment */
            p->tcb->tflags |= TCBF_FORCE_TX;
            tcp_do_output(t);

            tcp_set_persist(t);
        }

        break;

    case TCPT_KEEP:
        if (t->state < TCPS_ESTABLISHED)
            goto dropit;

        if (is_set(p->opt_flag, SO_KEEPALIVE) && (t->state <= TCPS_CLOSE_WAIT)) {
            pktmbuf_t *mbuf;

            if (t->idle >= (stk->tcp->keep_idle + stk->tcp->max_idle))
                goto dropit;

            /* Used for Keepalive probe */
            mbuf = pktmbuf_alloc(NULL);

            if (!mbuf)
                break;

            mbuf->userptr = p;

            /* Point to tcp struct */
            pktmbuf_adj_offset(mbuf, sizeof(struct cne_ipv4_hdr));

            tcp_do_response(t->netif, p, mbuf, t->snd_nxt - 1, t->rcv_nxt - 1, TCP_ACK);

            t->timers[tmr] = stk->tcp->keep_intvl;
        } else
            t->timers[tmr] = stk->tcp->keep_idle;

        break;
    dropit:
        tcp_do_state_change(p, TCPS_CLOSED);
        state = true;
        break;

    case TCPT_REXMT:
        if (++t->rxtshift > TCP_MAXRXTSHIFT) {
            t->rxtshift = TCP_MAXRXTSHIFT;

            /* Drop connection */
            tcp_do_drop_connection(t->pcb, ETIMEDOUT);
            break;
        }

        INC_TCP_STAT(segments_rexmit);

        rexmt = tcpRexmtVal(t) * ((t->state == TCPS_SYN_SENT) ? tcp_syn_backoff[t->rxtshift]
                                                              : tcp_backoff[t->rxtshift]);

        t->rxtcur = tcp_range_set(rexmt, t->rttmin, TCP_REXMTMAX_TV);

        /* Restart the retransmit timer */
        t->timers[TCPT_REXMT] = t->rxtcur;

        /* Reset snd_nxt to force a retransmit of data */
        t->snd_nxt = t->snd_una;
        t->rtt     = 0;

        win = CNE_MIN(t->snd_wnd, t->snd_cwnd) / 2 / t->max_mss;

        if (win < 2)
            win = 2;

        t->snd_cwnd     = t->max_mss;
        t->snd_ssthresh = win * t->max_mss;
        t->dupacks      = 0;

        /* Set the ACK now bit to force a retranmit. */
        t->tflags |= TCBF_ACK_NOW;
        tcp_do_output(p->tcb);
        break;

    default:
        break;
    }

    return state;
}

/**
 * Process the slow timeouts for the TCP state machine.
 */
static inline void
tcp_slow_timo(stk_t *stk)
{
    struct pcb_hd *hd = &stk->tcp->tcp_hd;
    struct pcb_entry *p;
    int32_t j;

    stk->tcp->max_idle = stk->tcp->keep_cnt * stk->tcp->keep_intvl;

    /* TCP slow timer */
    vec_foreach_ptr (p, hd->vec) {
        struct tcb_entry *t = p->tcb;

        if (!t)
            continue;

        if (t->state == TCPS_CLOSED)
            continue;

        for (j = 0; j < TCP_NTIMERS; j++) {
            if ((t->timers[j] > 0) && (--t->timers[j] == 0))
                if (tcp_process_timer(p, j)) {
                    t = NULL;
                    break;
                }
        }

        /* measure the current idle time */
        if (t)
            t->idle++;
    }

    stk->tcp->snd_ISS += (TCP_ISSINCR / TCP_SLOWHZ); /* Increment iss */
    stk->tcp_now++;
}

/**
 * Timeout every XXms to be able to have a fast and slow timer of 200ms/500ms.
 */
void
__tcp_process_timers(void)
{
    stk_t *stk = this_stk;

    if (!(stk->ticks % (TCP_REXMT_TIMEOUT_MS / MS_PER_TICK)))
        tcp_fast_retransmit_timo(stk);

    if (!(stk->ticks % (TCP_FAST_TIMEOUT_MS / MS_PER_TICK)))
        tcp_fast_timo(stk);

    if (!(stk->ticks % (TCP_SLOW_TIMEOUT_MS / MS_PER_TICK)))
        tcp_slow_timo(stk);
}

/**
 * Add the MSS option and other options for the send packet.
 */
static int32_t
tcp_send_options(struct tcb_entry *tcb, uint8_t *opts, uint8_t flags_n)
{
    uint8_t *p     = opts;
    int32_t optlen = 0;

    if (is_set(flags_n, TCP_SYN)) {
        /*
         * Update the next send sequence number to the initial send sequence
         * number if this is the first packet in handshake.
         */
        tcb->snd_nxt = tcb->snd_iss;

        /* Add the MSS to the options */
        *p++   = TCP_OPT_MSS;
        *p++   = TCP_OPT_MSS_LEN;
        *p++   = (uint8_t)(tcb->max_mss >> 8);
        *p++   = (uint8_t)tcb->max_mss;
        optlen = 4;

        /*
         * Add the Window scaling option if:
         *     requesting a scaling and got a window scaling option from peer or
         *     reguesting a scaling and this is the first SYN.
         * The SYN bit must be set and we need to
         * test the ACK bit to be off for the initial SYN.
         */
        if (is_set(tcb->tflags, TCBF_REQ_SCALE) &&
            (is_clr(flags_n, TCP_ACK) || is_set(tcb->tflags, TCBF_RCVD_SCALE))) {
            *p++ = TCP_OPT_WSOPT;
            *p++ = TCP_OPT_WSOPT_LEN;
            *p++ = (uint8_t)tcb->req_recv_scale;
            *p++ = TCP_OPT_NOP;
            optlen += 4;
        }
    }

    if (is_set(tcb->tflags, TCBF_REQ_TSTAMP) && is_clr(flags_n, TCP_RST) &&
        (((flags_n & SYN_ACK) == TCP_SYN) || is_set(tcb->tflags, TCBF_RCVD_TSTAMP))) {
        uint32_t tcp_now = stk_get_timer_ticks();
        uint32_t *lp     = (uint32_t *)p;

        *lp++ = htobe32((TCP_OPT_NOP << 24) | (TCP_OPT_NOP << 16) | (TCP_OPT_TSTAMP << 8) |
                        TCP_OPT_TSTAMP_LEN);
        *lp++ = htobe32(tcp_now);
        *lp++ = htobe32(tcb->ts_recent);
        optlen += 12;
    }

    return optlen; /* Length of options */
}

/**
 * Abort a TCP connection by sending a RST bit in a TCP header, with the given
 * PCB information. If the <pcb> and pcb->tcb are null return without any error.
 *
 * The routine will attempt to wait for a packet pointer if one is not available
 * when the packet allocation routine is called. If the call to allocate a packet
 * buffer fails the connection is closed without sending the RST segment. The
 * only reason a packet can not be allocated is because of a fatal error in the
 * allocation routine, which should never happen.
 */
void
tcp_abort(struct pcb_entry *pcb)
{
    struct tcb_entry *tcb;

    /*
     * In normal calls pcb and pcb->tcb can not be null, but because it is a
     * global function it could be called with a null pointer.
     */
    if ((pcb == NULL) || (pcb->tcb == NULL))
        return;

    tcb = pcb->tcb;

    /* RFC792 pg 62
     *
     * ABORT Call
     * .
     * .
     * SYN-RECEIVED STATE
     * ESTABLISHED STATE
     * FIN-WAIT-1 STATE
     * FIN-WAIT-2 STATE
     * CLOSE-WAIT STATE
     *
     * Send a reset segment:
     *      <SEQ=SND.NXT><CTL=RST>
     *
     * All queued SENDs and RECEIVEs should be given "connection reset"
     * notification; all segments queued for transmission (except for the
     * RST formed above) or retransmission should be flushed, delete the
     * TCB, enter CLOSED state, and return.
     */
    if (((tcb->state >= TCPS_SYN_RCVD) && (tcb->state <= TCPS_FIN_WAIT_1)) ||
        (tcb->state == TCPS_FIN_WAIT_2)) {
        pktmbuf_t *mbuf;

        /* Wait for a packet buffer, if one is not available */
        if (pktdev_buf_alloc(pcb->netif->lpid, &mbuf, 1) != 1) {
            pktmbuf_adj_offset(mbuf, sizeof(struct cne_ipv4_hdr));

            tcp_do_response(tcb->netif, pcb, mbuf, tcb->snd_nxt, tcb->rcv_nxt, TCP_RST);

            INC_TCP_STAT(resets_sent);
        }
    }

    tcp_do_state_change(pcb, TCPS_CLOSED);
}

/**
 * Do a TCP connect startup/open or start the three way handshake in TCP.
 */
int
cnet_tcp_connect(struct pcb_entry *pcb)
{
    struct tcb_entry *tcb;

    if ((pcb == NULL) || ((tcb = pcb->tcb) == NULL))
        return -1;

    if (tcb->state >= TCPS_SYN_SENT)
        return -1;

    pcb->ch->ch_state |= _ISCONNECTING;

    tcb->state             = TCPS_SYN_SENT;
    tcb->timers[TCPT_KEEP] = TCP_KEEP_INIT_TV;

    /* Set the new send ISS value. */
    tcp_send_seq_set(tcb, 7);

    INC_TCP_STAT(active_connects);

    tcb->tflags |= TCBF_ACK_NOW;

    return tcp_output(tcb);
}

/**
 * Close the TCP connect pointed to by the given <pcb> pointer. The pcb pointer
 * must be valid when calling the routine. The routine will return false when
 * the connect has already been closed, the TCB was in the listen state or
 * tcp output routine returned with -1. Otherwise, the routine will return
 * true if the connection was moved toward the closed state via FIN wait or
 * last ack.
 *
 * RETURNS: true if the connection is closing or false if already closed.
 */
int
tcp_close(struct pcb_entry *pcb)
{
    /* The pcb->tcb must be valid or return false */
    if (pcb->tcb == NULL)
        return false;

    if (pcb->tcb->state == TCPS_CLOSED)
        return false;

    switch (pcb->tcb->state) {
    case TCPS_SYN_RCVD: /* FALLTHRU */
    case TCPS_ESTABLISHED:
        tcp_do_state_change(pcb, TCPS_FIN_WAIT_1);
        break;

    case TCPS_CLOSE_WAIT:
        tcp_do_state_change(pcb, TCPS_LAST_ACK);
        break;

    default:            /* FALLTHRU */
    case TCPS_SYN_SENT: /* FALLTHRU */
    case TCPS_LISTEN:
        tcp_do_state_change(pcb, TCPS_CLOSED);
        return false;
    }

    /* Force the other side to close his connection. */
    pcb->tcb->tflags |= TCBF_ACK_NOW;
    return (tcp_output(pcb->tcb) == -1) ? true : false;
}

void
cnet_tcp_dump(const char *msg, struct cne_tcp_hdr *tcp)
{
    cne_printf(">>>> TCP Header (%s) <<<<\n", (msg) ? msg : "");
    cne_printf("  TCP_Flags ( %s)\n", tcp_print_flags(tcp->tcp_flags & TCP_MASK));
    cne_printf("  Src Port : %d  Dst Port: %d ", be16toh(tcp->src_port), be16toh(tcp->dst_port));
    cne_printf("Seq %u, Ack %u\n", be32toh(tcp->sent_seq), be32toh(tcp->recv_ack));
    cne_printf("  HLEN %d (%d bytes) ", (tcp->data_off >> 4), (tcp->data_off >> 2));
    cne_printf("RX Win %u, cksum %04x, URP %u\n", be16toh(tcp->rx_win), be16toh(tcp->cksum),
               be16toh(tcp->tcp_urp));
    cne_printf("<<<<<\n");
}

void
cnet_tcb_list(stk_t *stk, struct tcb_entry *tcb)
{
    struct tcb_entry *t;

    if (!stk)
        stk = this_stk;

    cne_printf("[yellow]TCB Information [skyblue]%s[]\n", stk->name);
    TAILQ_FOREACH (t, &stk->tcbs, entry) {
        if (tcb && (tcb != t))
            continue;
        cne_printf("TCB %p\n", t);
        cne_printf("   State: <%s>\n", tcb_in_states[t->state]);
        cne_printf(
            "   Snd: UNA %u nxt %u urp %u iss %u wl1 %u wl2 %u up %u\n   max %u wnd %u sst %u "
            "cwnd %u sndwnd %u\n",
            t->snd_una, t->snd_nxt, t->snd_urp, t->snd_iss, t->snd_wl1, t->snd_wl2, t->snd_up,
            t->snd_max, t->snd_wnd, t->snd_ssthresh, t->snd_cwnd, t->max_sndwnd);
        cne_printf("   Rcv: wnd %u nxt %u urp %u irs %u adv %u bsize %u sst %u\n", t->rcv_wnd,
                   t->rcv_nxt, t->rcv_urp, t->rcv_irs, t->rcv_adv, t->rcv_bsize, t->rcv_ssthresh);
        cne_printf("   Flags: %s\n", tcb_print_flags(t->tflags));
    }
}

/**
 * Main entry point to initialize the TCP protocol.
 */
int
tcp_init(int32_t n_tcb_entries, bool wscale, bool t_stamp)
{
    stk_t *stk             = this_stk;
    struct mempool_cfg cfg = {0};
    struct protosw_entry *psw;

    stk->tcp = calloc(1, sizeof(struct tcp_entry));
    if (stk->tcp == NULL)
        goto err_exit;

    cfg.objcnt    = n_tcb_entries;
    cfg.objsz     = sizeof(struct tcb_entry);
    cfg.cache_sz  = (n_tcb_entries / 8);
    stk->tcb_objs = mempool_create(&cfg);
    if (stk->tcb_objs == NULL)
        goto err_exit;

    stk->gflags |= (TCP_TIMEOUT_ENABLED | (wscale ? RFC1323_SCALE_ENABLED : 0));
    stk->gflags |= (t_stamp ? RFC1323_TSTAMP_ENABLED : 0);

    stk->tcp->rcv_size    = MAX_TCP_RCV_SIZE;
    stk->tcp->snd_size    = MAX_TCP_SND_SIZE;
    stk->tcp->keep_idle   = TCP_KEEP_IDLE_TV;
    stk->tcp->keep_intvl  = TCP_KEEPINTVL_TV;
    stk->tcp->keep_cnt    = TCP_KEEPCNT_TV;
    stk->tcp->max_idle    = TCP_KEEP_IDLE_TV;
    stk->tcp->default_MSS = TCP_NORMAL_MSS;
    stk->tcp->default_RTT = TCP_SRTTDFLT_TV; /* RFC6298 states - 1 sec */
    stk->tcp->snd_ISS     = (uint32_t)rand();
    stk->tcp_now          = (uint32_t)cne_rdtsc();

    stk->tcp->tcp_hd.vec = vec_alloc(stk->tcp->tcp_hd.vec, TCP_VEC_PCB_COUNT);
    CNE_ASSERT(stk->tcp->tcp_hd.vec != NULL);
    stk->tcp->tcp_hd.lport = _IPPORT_RESERVED;

    cfg.objcnt    = TCP_SEGMENT_COUNT;
    cfg.objsz     = sizeof(struct seg_entry);
    cfg.cache_sz  = 64;
    stk->seg_objs = mempool_create(&cfg);
    if (stk->seg_objs == NULL)
        goto err_exit;

    psw = cnet_protosw_add("TCP", AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CNE_ASSERT(psw != NULL);

    cnet_ipproto_set(IPPROTO_TCP, psw);

    return 0;

err_exit:
    if (stk->tcp == NULL)
        CNE_ERR("Allocation failed for TCP structure\n");
    else if (stk->tcb_objs == NULL)
        CNE_ERR("TCB allocation failed for %d tcb_entries of %'ld bytes\n", n_tcb_entries,
                sizeof(struct tcb_entry));
    else if (stk->seg_objs == NULL)
        CNE_ERR("Segment allocation failed for %d tcb_entries of %'ld bytes\n", TCP_SEGMENT_COUNT,
                sizeof(struct seg_entry));
    else
        CNE_ERR("TCP proto input set failed or Timer registation\n");
    (void)tcp_destroy(stk);
    return -1;
}

static int
tcp_create(void *stk __cne_unused)
{
    return tcp_init(CNET_NUM_TCBS, 1, 1);
}

static int
tcp_destroy(void *_stk __cne_unused)
{
    stk_t *stk = _stk;

    mempool_destroy(stk->tcb_objs);
    mempool_destroy(stk->seg_objs);
    free(stk->tcp);

    return 0;
}

CNE_INIT_PRIO(cnet_tcp_constructor, STACK)
{
    cnet_add_instance("tcp", CNET_TCP_PRIO, tcp_create, tcp_destroy);
}
