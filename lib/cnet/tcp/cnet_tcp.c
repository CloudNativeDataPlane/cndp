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
#include <cnet_meta.h>             // for cnet_metadata
#include <cnet_tcp_chnl.h>         // for cnet_drop_acked_data, cnet_tcp_chnl_scal...
#include <endian.h>                // for be16toh, htobe32, htobe16, be32toh
#include <errno.h>                 // for errno, ECONNREFUSED, ECONNRESET, ETIMEDOUT
#include <netinet/in.h>            // for ntohs, IPPROTO_TCP, IN_CLASSD, ntohl
#include <pthread.h>               // for pthread_cond_signal, pthread_cond_wait
#include <stdlib.h>                // for free, calloc, rand
#include <string.h>                // for strcat, memcpy, memset
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>

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
#include <cnet_node_names.h>
#include <tcp_input_priv.h>
#include <tcp_output_priv.h>
#include <cne_mutex_helper.h>

/* static TCP backoff shift values */
static int32_t tcp_syn_backoff[TCP_MAXRXTSHIFT + 1] = {1, 1, 1, 1, 1, 2, 4, 8, 16, 32, 64, 64, 64};
static int32_t tcp_backoff[TCP_MAXRXTSHIFT + 1] = {1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64};
static uint8_t tcp_output_flags[]               = TCP_OUTPUT_FLAGS;

/* forward declares */
static int tcp_destroy(void *_stk);
static int tcb_cleanup(struct tcb_entry *tcb);
static void tcp_update_acked_data(struct seg_entry *seg, struct tcb_entry *tcb);
static int32_t tcp_send_options(struct tcb_entry *tcb, uint8_t *sp, uint8_t flags_n);
static int tcp_init(int32_t n_tcb_entries, bool wscale, bool t_stamp);

const char *tcb_in_states[] = TCP_INPUT_STATES;

#define TCP_FLAGS_MAX_SIZE 128
#define TCB_FLAGS_MAX_SIZE 256
static char tcp_flags[TCP_FLAGS_MAX_SIZE + 1], tcb_flags[TCB_FLAGS_MAX_SIZE + 1];

#define CNET_TCP_FAST_REXMIT 1

static inline struct seg_entry *
alloc_seg(void)
{
    struct seg_entry *seg = NULL;

    if (mempool_get(this_stk->seg_objs, (void **)&seg) != 0)
        CNE_NULL_RET("mempool of segments is empty\n");

    return seg;
}

static inline void
free_seg(struct seg_entry *seg)
{
    if (seg) {
        memset(seg, 0, sizeof(struct seg_entry));
        mempool_put(this_stk->seg_objs, (void *)seg);
    }
}

void *
tcp_q_pop(struct tcp_q *tq)
{
    struct pcb_entry *pcb = NULL;

    if (stk_lock()) {
        if (atomic_load(&tq->cnt)) {
            pcb = TAILQ_FIRST(&tq->head);
            if (pcb) {
                TAILQ_REMOVE(&tq->head, pcb, next);
                atomic_fetch_sub(&tq->cnt, 1);
            }
        }
        stk_unlock();
    }

    return pcb;
}

/* Return 1 on full or 0 if pushed */
static int
tcp_q_add(struct tcp_q *tq, void *val)
{
    struct pcb_entry *pcb = val;

    if (stk_lock()) {
        TAILQ_INSERT_TAIL(&tq->head, pcb, next);
        atomic_fetch_add(&tq->cnt, 1);
        stk_unlock();
    }

    return 0;
}

static int
tcp_q_remove(struct tcp_q *tq, void *val)
{
    struct pcb_entry *pcb = val;

    if (stk_lock()) {
        if (atomic_load(&tq->cnt)) {
            TAILQ_REMOVE(&tq->head, pcb, next);
            atomic_fetch_sub(&tq->cnt, 1);
        }
        stk_unlock();
    }

    return 0;
}

/*
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

    if (is_set(flags, TCP_FIN))
        strcat(tcp_flags, "FIN ");

    if (is_set(flags, TCP_PSH))
        strcat(tcp_flags, "PSH ");

    if (is_set(flags, TCP_ACK))
        strcat(tcp_flags, "ACK ");

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
    for (i = 0; i < (int)cne_countof(list); i++) {
        if (flags & (1 << (31 - i))) {
            strlcat(tcb_flags, list[i], TCB_FLAGS_MAX_SIZE);
            strlcat(tcb_flags, " ", TCB_FLAGS_MAX_SIZE);
        }
    }
    return tcb_flags;
}

void
cnet_tcp_dump(const char *msg, struct cne_tcp_hdr *tcp)
{
    cne_printf("%s [cyan]TCP Header[] @ %p\n", (msg) ? msg : "", tcp);
    cne_printf("   [cyan]TCP_Flags ( [orange]%s[cyan])[] ",
               tcp_print_flags(tcp->tcp_flags & TCP_MASK));
    cne_printf("[cyan]Src Port : [orange]%5d  [cyan]Dst Port: [orange]%5d[]\n",
               be16toh(tcp->src_port), be16toh(tcp->dst_port));
    cne_printf("   [cyan]Seq [orange]%10u[cyan], Ack [orange]%10u[] ", be32toh(tcp->sent_seq),
               be32toh(tcp->recv_ack));
    cne_printf("[cyan]HLEN [orange]%3d [cyan]bytes ", (tcp->data_off >> 2));
    cne_printf("RX Win [orange]%5u[cyan], cksum [orange]%04x[cyan], URP [orange]%3u[]\n",
               be16toh(tcp->rx_win), be16toh(tcp->cksum), be16toh(tcp->tcp_urp));
}

/*
 * Set the congestion window for slow-start given the valid <tcb>, by looking at
 * the tcb->pcb->faddr and determine the connection is for a local subnet. When
 * the connection is on the local subnet, the code will select a larger
 * congestion window value else it picks the senders max segment size.
 */
static inline void
tcp_set_CWND(struct tcb_entry *tcb)
{
    /*
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

/*
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

/*
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

    /* If the TCB is already allocated then return the tcb pointer. */
    if ((tcb = pcb->tcb) != NULL)
        return tcb;

    if ((tcb = tcb_alloc()) == NULL)
        CNE_ERR_GOTO(err, "TCB allocate failed\n");

    tcb->reassemble = vec_alloc(tcb->reassemble, CNET_TCP_REASSEMBLE_COUNT);
    if (!tcb->reassemble)
        CNE_ERR_GOTO(err, "tcb->backlog allocate failed\n");

    TAILQ_INIT(&tcb->backlog_q.head);
    TAILQ_INIT(&tcb->half_open_q.head);

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

    tcb->state = TCPS_CLOSED;
    return tcb;
err:
    tcb_free(tcb);
    return NULL;
}

/*
 * Form the TCP header and send the given segment of data.
 *
 */
static int
tcp_send_segment(struct tcb_entry *tcb, struct seg_entry *seg)
{
    struct pcb_entry *pcb = tcb->pcb;
    struct chnl *ch       = pcb->ch;
    pktmbuf_t *mbuf       = seg->mbuf;
    stk_t *stk            = this_stk;
    struct cnet_metadata *md;
    struct cne_tcp_hdr *tcp;

    seg->mbuf = NULL;

    if (!mbuf)
        CNE_ERR_RET("mbuf is NULL\n");

    /* Add the TCP options to the data packet */
    memcpy(pktmbuf_prepend(mbuf, seg->optlen), &seg->opts[0], seg->optlen);

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
    if (pcb->key.laddr.cin_addr.s_addr == 0) {
        struct netif *nif;
        int32_t k;

        nif = cnet_netif_match_subnet(&pcb->key.faddr.cin_addr);
        if (!nif) {
            char ip[INET6_ADDRSTRLEN + 4] = {0};

            pktmbuf_free(mbuf);
            CNE_ERR_RET("No netif match %s\n",
                        inet_ntop4(ip, sizeof(ip), &pcb->key.faddr.cin_addr, NULL));
        }
        /* Find the correct subnet IP address for the given request */
        if ((k = cnet_ipv4_compare(nif, (void *)&pcb->key.faddr.cin_addr.s_addr)) == -1) {
            char ip[INET6_ADDRSTRLEN + 4] = {0};

            pktmbuf_free(mbuf);
            CNE_ERR_RET("cnet_ipv4_compare(%s) failed\n",
                        inet_ntop4(ip, sizeof(ip),
                                   (struct in_addr *)&pcb->key.faddr.cin_addr.s_addr, NULL));
        }

        tcb->netif = nif;

        /* Use the interface attached to the route for the source address */
        pcb->key.laddr.cin_addr.s_addr = htobe32(nif->ip4_addrs[k].ip.s_addr);
    }

    /* Clear the send Ack Now bit, if an ACK is present. */
    if (is_set(seg->flags, TCP_ACK))
        tcb->tflags &= ~(TCBF_ACK_NOW | TCBF_DELAYED_ACK);

    /* Always clear the force tx and need output flags. */
    tcb->tflags &= ~TCBF_FORCE_TX;

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

    md = pktmbuf_metadata(mbuf);

    if ((tcp->tcp_flags & TCP_URG) == 0 && tcp->tcp_urp)
        CNE_WARN("[orange]URG pointer set without URG flag\n");

    md->faddr.cin_addr.s_addr = ch->ch_pcb->key.faddr.cin_addr.s_addr;
    md->laddr.cin_addr.s_addr = ch->ch_pcb->key.laddr.cin_addr.s_addr;

    if (unlikely(stk->tcp_tx_node == NULL)) {
        stk->tcp_tx_node = cne_graph_get_node_by_name(stk->graph, TCP_OUTPUT_NODE_NAME);
        if (!stk->tcp_tx_node)
            CNE_ERR_RET("Unable to find '%s' node\n", TCP_OUTPUT_NODE_NAME);
    }

    cne_node_enqueue_x1(stk->graph, stk->tcp_tx_node, TCP_OUTPUT_NEXT_IP4_OUTPUT, mbuf);

    return 0;
}

/*
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

    if (!stk_lock())
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

    stk_unlock();
    return total;
}

/*
 * Determine if a segment of data or just a TCP header needs to be sent via
 * the tcb_send_segment routine.
 */
static int
tcp_output(struct tcb_entry *tcb)
{
    struct chnl *ch;
    bool idle, sendalot;

    if (!tcb)
        CNE_ERR_RET("TCB pointer is NULL\n");
    if (!tcb->pcb)
        CNE_ERR_RET("PCB pointer is NULL\n");
    if (!tcb->pcb->ch)
        CNE_ERR_RET("Chnl pointer is NULL\n");

    ch = tcb->pcb->ch;

    idle = (tcb->snd_max == tcb->snd_una);

    CNE_DEBUG("\n");
    CNE_DEBUG("[magenta]Do TCP output[]\n");

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
        struct seg_entry tx_seg;
        struct seg_entry *seg = &tx_seg;
        uint32_t off;
        int32_t len;
        uint32_t win;
        seq_t prev_rcv_adv;

        /* Send a packet we must clear the segment structure each time */
        memset(seg, 0, sizeof(struct seg_entry));

        do {
            sendalot = false; /* Preset the flag to false */

            /* The offset from snd_nxt to snd_una currently */
            off = tcb->snd_nxt - tcb->snd_una;
            CNE_DEBUG("snd_nxt [orange]%d[] snd_una [orange]%d[] off [orange]%d[]\n", tcb->snd_nxt,
                      tcb->snd_una, off);

            /* Set the window size to send window or congestion window size */
            win = CNE_MIN(tcb->snd_wnd, tcb->snd_cwnd);

            /* Set the TCP output flags based on the current state of the TCB */
            seg->flags = tcp_output_flags[tcb->state];

            if (is_set(tcb->tflags, TCBF_FORCE_TX)) {
                /* When win is zero then must be a zero window probe */
                if (win == 0) {
                    /*
                     * Force a zero window update.
                     *
                     * When the offset is less then cb_cc then we have
                     * data to send but the window is zero.
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
            CNE_DEBUG("cb_cc [cyan]%d[], win [cyan]%d[], off [cyan]%d[], len [orange]%d[] vec "
                      "[orange]%d[]\n",
                      ch->ch_snd.cb_cc, win, off, len, vec_len(ch->ch_snd.cb_vec));

            if (is_set(seg->flags, TCP_SYN)) {

                /* make sure we do not send a SYN with a FIN bit. */
                len = 0;
                seg->flags &= ~TCP_FIN;
            }

            if (len < 0) {
                CNE_DEBUG("Data length is [orange]%d < 0[]\n", len);

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
                CNE_DEBUG("len [cyan]%d[] > [cyan]%d[] max_mss, vec_len([orange]%d[])\n", len,
                          tcb->max_mss, vec_len(ch->ch_snd.cb_vec));
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
                /* The length equals max_mss then we are not in Silly Window Syndrome do send. */
                if (len == tcb->max_mss) {
                    CNE_DEBUG("Not in SWS, len [cyan]%d[] == [cyan]%d[] max_mss\n", len,
                              tcb->max_mss);
                    break;
                }

                /*
                 * When we have credit we can send something clear NAGLE flag and
                 * go to send.
                 */
                if (idle || (tcb->tflags & TCBF_NAGLE_CREDIT) ||
                    (tcb->pcb->opt_flag & TCP_NODELAY_FLAG)) {
                    tcb->tflags &= ~TCBF_NAGLE_CREDIT;
                    CNE_DEBUG("Nagle Credit or NoDelay flag or idle %d\n", idle);
                    break;
                }

                /*
                 * We are forcing a transmit or length is 1/2 the max window
                 * or snd_nxt is less then snd_max do a send.
                 */
                if (is_set(tcb->tflags, TCBF_FORCE_TX)) {
                    CNE_DEBUG("Force Tx\n");
                    break;
                }

                if (len >= (int64_t)(tcb->max_sndwnd / 2)) {
                    CNE_DEBUG("len %d >= %d sndwnd\n", len, (tcb->max_sndwnd / 2));
                    break;
                }

                if (seqLT(tcb->snd_nxt, tcb->snd_max)) {
                    CNE_DEBUG("snd_nxt %u < %u snd_max\n", tcb->snd_nxt, tcb->snd_max);
                    break;
                }
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
                CNE_DEBUG("Set [orange]Persist[]\n");
                tcp_set_persist(tcb);
            }
            CNE_DEBUG("[orange]No Data to send[]\n");
            goto leave;
        } while (/*CONSTCOND*/ 0);

        /* Create the options and obtain the options length */
        seg->optlen = tcp_send_options(tcb, seg->opts, seg->flags);

        if (len > (tcb->max_mss - seg->optlen)) {
            len      = tcb->max_mss - seg->optlen;
            sendalot = true;

            /* Turn off the FIN if it is set */
            seg->flags &= ~TCP_FIN;
        }

        if (pktdev_buf_alloc(seg->lport, &seg->mbuf, 1) <= 0) {
            CNE_WARN("pktmbuf allocation from lport %d failed id %d\n", seg->lport, cne_id());
            return -1;
        }

        seg->mbuf->userptr = tcb->pcb;

        /* move the starting offset to account for headers */
        pktmbuf_data_off(seg->mbuf) += sizeof(struct cne_tcp_hdr) + seg->optlen +
                                       sizeof(struct cne_ipv4_hdr) + sizeof(struct ether_addr);

        /* Make sure the headers are zero */
        memset(pktmbuf_mtod(seg->mbuf, char *), 0,
               sizeof(struct cne_tcp_hdr) + seg->optlen + sizeof(struct cne_ipv4_hdr) +
                   sizeof(struct ether_addr));

        if (len) {
            len = tcp_mbuf_copydata(&ch->ch_snd, off, len, pktmbuf_mtod(seg->mbuf, char *));

            pktmbuf_append(seg->mbuf, len); /* Update length */
            CNE_DEBUG("Add [orange]%4d[] bytes to the packet buffer\n", len);
        }

        /* Make sure if sending a FIN does not advertise a new sequence number */
        if (is_set(seg->flags, TCP_FIN) && is_set(tcb->tflags, TCBF_SENT_FIN) &&
            (tcb->snd_nxt == tcb->snd_max)) {
            CNE_DEBUG("[cyan]Do not advertise a new sequence number[]\n");
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

        if (tcb->rcv_scale == 0)
            tcb->rcv_scale = tcb->req_recv_scale;

        /*
         * Calculate receive window and don't shrink the window to small
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
            CNE_DEBUG("Set win to %u (adv %u - %u nxt)\n", (uint32_t)(tcb->rcv_adv - tcb->rcv_nxt),
                      tcb->rcv_adv, tcb->rcv_nxt);
        }

        seg->wnd = win >> tcb->rcv_scale;
        CNE_DEBUG("Window size [cyan]%u, scaled win %u, %u[]\n", win, seg->wnd, tcb->rcv_scale);

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
            CNE_ERR_RET("TCP send segment returned error\n");
        }

        CNE_DEBUG("Send a lot is [orange]%s[]\n", sendalot ? "true" : "false");
    } while (sendalot);

leave:
    CNE_DEBUG("[orange]Leaving[]\n");
    return 0;
}

/*
 * Call the tcp output routine and examine the return status and place the
 * error code in struct chnl.ch_error variable, if present.
 */
void
cnet_tcp_output(struct tcb_entry *tcb)
{
    /*
     * When an error is detected try and set the ch_error value to be
     * retrieved by the SO_ERROR channel option later.
     */
    if (tcp_output(tcb) < 0) {
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

/*
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
tcp_do_response(struct netif *netif __cne_unused, struct pcb_entry *pcb, pktmbuf_t *mbuf,
                uint32_t seq, uint32_t ack, uint8_t flags)
{
    stk_t *stk = this_stk;
    struct cne_tcp_hdr *tcp;
    struct cnet_metadata *md;
    char opts[64];
    int optlen;

    if (!pcb)
        CNE_RET("*** PCB is not set\n");
    if (!netif)
        CNE_RET("*** Netif is not set\n");

    /* Wait for a packet buffer, if one is not available */
    if (mbuf == NULL) {
        if (pktdev_buf_alloc(netif->lpid, &mbuf, 1) == 0)
            CNE_RET("Unable to allocate packet buffer\n");
    } else
        pktmbuf_reset(mbuf);

    /* Create the options and obtain the options length */
    optlen = tcp_send_options(pcb->tcb, opts, flags);

    /* move the starting offset to account for headers */
    pktmbuf_data_off(mbuf) += sizeof(struct cne_tcp_hdr) + optlen + sizeof(struct cne_ipv4_hdr) +
                              sizeof(struct ether_addr);
    mbuf->userptr = pcb;

    /* Add the TCP options to the data packet */
    memcpy(pktmbuf_prepend(mbuf, optlen), opts, optlen);

    tcp = (struct cne_tcp_hdr *)pktmbuf_prepend(mbuf, sizeof(struct cne_tcp_hdr));
    if (!tcp)
        CNE_RET("failed to get TCP structure pointer\n");
    mbuf->l4_len = sizeof(struct cne_tcp_hdr) + optlen;

    memset(tcp, 0, sizeof(struct cne_tcp_hdr) + optlen);

    md = pktmbuf_metadata(mbuf);
    if (!md)
        CNE_RET("failed to get metadata structure pointer\n");

    CIN_CADDR(&md->faddr) = CIN_CADDR(&pcb->key.faddr);
    CIN_CADDR(&md->laddr) = CIN_CADDR(&pcb->key.laddr);
    CIN_PORT(&md->faddr)  = CIN_PORT(&pcb->key.faddr);
    CIN_PORT(&md->laddr)  = CIN_PORT(&pcb->key.laddr);

    tcp->src_port = CIN_PORT(&md->laddr);
    tcp->dst_port = CIN_PORT(&md->faddr);

    tcp->sent_seq = htobe32(seq);
    tcp->recv_ack = htobe32(ack);

    tcp->data_off  = ((sizeof(struct cne_tcp_hdr) + optlen) >> 2) << 4;
    tcp->tcp_flags = flags;

    memcpy(&tcp[1], opts, optlen);

    /*
     * When channel and TCB are valid and not a RST, then get the current
     * receive space as the window value.
     */
    if (pcb && pcb->ch && pcb->tcb && is_clr(flags, TCP_RST)) {
        uint32_t win = cb_space(&pcb->ch->ch_rcv);

        if (win > (uint32_t)(TCP_MAXWIN << pcb->tcb->rcv_scale))
            win = (uint32_t)(TCP_MAXWIN << pcb->tcb->rcv_scale);

        tcp->rx_win = htobe16((uint16_t)(win >> pcb->tcb->rcv_scale));
    }

    if (unlikely(stk->tcp_tx_node == NULL)) {
        stk->tcp_tx_node = cne_graph_get_node_by_name(stk->graph, TCP_OUTPUT_NODE_NAME);
        if (!stk->tcp_tx_node)
            CNE_RET("Unable to find '%s' node\n", TCP_OUTPUT_NODE_NAME);
    }

    cne_node_enqueue_x1(stk->graph, stk->tcp_tx_node, TCP_OUTPUT_NEXT_IP4_OUTPUT, mbuf);
}

/*
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

    CNE_DEBUG("Drop with [orange]Reset[]\n");
    /* Steal the input mbuf */
    mbuf      = seg->mbuf;
    seg->mbuf = NULL;

    /* Need to make sure we handle IP Multicast addresses and RST packets */
    if (is_set(seg->flags, TCP_RST) || IN_CLASSD(ip->dst_addr) ||
        (mbuf->ol_flags & CNE_MBUF_IS_MCAST)) {
        pktmbuf_free(mbuf);
    } else {
        /* Only send the RST if the ACK bit is set on the incoming segment */
        if (is_set(seg->flags, TCP_ACK)) {
            /* Send segment with <SEQ=SEG.ACK><CTL=RST> */
            CNE_DEBUG("SEND segment with [orange]<SEQ=SEG.ACK><CTL=RST>[]\n");
            tcp_do_response(netif, pcb, mbuf, seg->ack, 0, TCP_RST);
        } else { /* When ACK is not set, then send a RST/ACK pair */
            if (is_set(seg->flags, TCP_SYN))
                seg->len++; /* SEG.LEN++ */

            /* Send segment with <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK> */
            CNE_DEBUG("SEND segment with [orange]<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>[]\n");
            seg->seq = 0;
            tcp_do_response(netif, pcb, mbuf, seg->seq, seg->seq + seg->len, RST_ACK);
        }
    }
}

/*
 * Send an ACK and allow the segment to be dropped.
 */
static inline int
tcp_drop_after_ack(struct seg_entry *seg)
{
    /* Do not response if we have a incoming RST */
    if (is_clr(seg->flags, TCP_RST)) {
        seg->pcb->tcb->tflags |= TCBF_ACK_NOW;
        CNE_DEBUG("ACK data\n");
        cnet_tcp_output(seg->pcb->tcb);
    } else
        CNE_DEBUG("RST found drop packet\n");

    return TCP_INPUT_NEXT_PKT_DROP;
}

/*
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
                seg->sflags |= SEG_SACK_PERMIT;
            break;

        case TCP_OPT_TSTAMP:
            if ((opts[1] + opts) > opt_end)
                CNE_ERR_RET("Option Length Invalid opts %u\n", *opts);

            if (opts[1] != TCP_OPT_TSTAMP_LEN) {
                CNE_DEBUG("opts[1] %d != %u\n", opts[1], TCP_OPT_TSTAMP_LEN);
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
            CNE_ERR("Unknown Options %d\n", opts[0]);
            break;
        }

        if (opts[1] == 0) /* Malformed option length */
            return -1;

        opts += opts[1];
    }

    return 0;
}

/*
 * Move the TCP connection to the next state and do any processing required
 * for the new state.
 */
static void
tcp_do_state_change(struct pcb_entry *pcb, int32_t new_state)
{
    struct tcb_entry *tcb = pcb->tcb;
    const char *curr_state;

    if (!tcb)
        return;

    curr_state = tcb_in_states[tcb->state];
    CNE_SET_USED(curr_state);

    switch (new_state) {
    case TCPS_CLOSED:
        INC_TCP_STAT(TCPS_CLOSED);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_CLOSED]);

        /*
         * When tcb_cleanup() is called and returns OK and the channel pointer
         * is valid then cleanup the rest of the connection. When the channel
         * pointer is NULL then a close was done on the channel before we got
         * to the closed state.
         */
        if ((tcb_cleanup(tcb) == 0) && pcb->ch) {
            chnl_state_set(pcb->ch, _ISDISCONNECTED);
            chnl_cant_snd_rcv_more(pcb->ch, _CANTSENDMORE | _CANTRECVMORE);
        }
        /* TCB pointer is now invalid so return */
        return;

    case TCPS_CLOSE_WAIT:
        INC_TCP_STAT(TCPS_CLOSE_WAIT);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_CLOSE_WAIT]);

        /*
         * Do not clear the _ISCONNECTED flags as we still need to read all
         * of the data off the channel first.
         */
        chnl_state_set(pcb->ch, _ISDISCONNECTING);
        chnl_cant_snd_rcv_more(pcb->ch, _CANTRECVMORE);
        break;

    case TCPS_LISTEN:
        INC_TCP_STAT(TCPS_LISTEN);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_LISTEN]);
        break;

    case TCPS_FIN_WAIT_2:
        INC_TCP_STAT(TCPS_FIN_WAIT_2);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_FIN_WAIT_2]);
        break;

    case TCPS_CLOSING:
        INC_TCP_STAT(TCPS_CLOSING);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_CLOSED]);
        break;

    case TCPS_LAST_ACK:
        INC_TCP_STAT(TCPS_LAST_ACK);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_LAST_ACK]);
        break;

    case TCPS_SYN_RCVD:
        INC_TCP_STAT(TCPS_SYN_RCVD);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_SYN_RCVD]);

        /* Start up the TIMER for SYN_RCVD state */
        tcb->timers[TCPT_KEEP] = TCP_KEEP_INIT_TV;
        break;

    case TCPS_ESTABLISHED:
        INC_TCP_STAT(TCPS_ESTABLISHED);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_ESTABLISHED]);

        /* Clear connecting state and set to connected */
        chnl_state_set(pcb->ch, _ISCONNECTED);

        /* Add the new pcb to the listen TCB or parent */
        if (tcb->ppcb) {
            struct tcb_entry *ptcb = tcb->ppcb->tcb;

            /*
             * Take connection off the half open queue and put on
             * backlog. Ignored if not found, because we do not
             * care if the entry was not on the half open queue.
             */
            if (tcp_q_remove(&ptcb->half_open_q, pcb) == 0) {
                if (tcp_q_add(&ptcb->backlog_q, pcb)) {
                    cnet_tcp_abort(pcb);
                    CNE_ERR("Failed to enqueue PCB to backlog queue\n");
                }
                pcb->ch->ch_callback(CHNL_TCP_ACCEPT_TYPE, tcb->ppcb->ch->ch_cd);
            }
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
        INC_TCP_STAT(TCPS_FIN_WAIT_1);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_FIN_WAIT_1]);

        chnl_state_set(pcb->ch, _ISDISCONNECTING);
        /*
         * Do errno callback, remove timers, clear keepalive and set
         * the TIME_WAIT timeout.
         */
        tcb_kill_timers(tcb);
        tcb->timers[TCPT_2MSL] = 2 * TCP_MSL_TV;
        break;

    case TCPS_TIME_WAIT:
        INC_TCP_STAT(TCPS_TIME_WAIT);

        CNE_DEBUG("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state,
                  tcb_in_states[TCPS_TIME_WAIT]);

        /*
         * Do errno callback, remove timers, clear keepalive and set
         * the TIME_WAIT timeout.
         */
        tcb_kill_timers(tcb);
        tcb->timers[TCPT_2MSL] = 2 * TCP_MSL_TV;
        break;

    default:
        CNE_ERR("Changing from [orange]%s[] --> [orange]%s[]\n", curr_state, "Unknown");
        break;
    }

    tcb->state = new_state;
}

/*
 * Process the given segment <seg> by validating the segment is acceptability.
 */
static bool
tcp_do_segment(struct seg_entry *seg)
{
    struct tcb_entry *tcb = seg->pcb->tcb;
    int32_t test_case     = 0, seglen;
    seq_t lwin, lseq;
    uint8_t tflags;
    bool acceptable = false;

    /* Adjust the length base on SYN and/or FIN bits */
    tflags = seg->flags;
    seglen = seg->len;
    seglen += ((tflags & SYN_FIN) == SYN_FIN) ? 2 : (tflags & SYN_FIN) ? 1 : 0;

    CNE_DEBUG("seglen %d, RCV.WND %u\n", seglen, tcb->rcv_wnd);

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
     */
    if (tcb->rcv_wnd == 0)
        goto skip_test;

    /*
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
     * seglen >0 we set bit 1 and if RCV.WND >0 we set bit 0 to create a
     * value between 0-3 and then switch on the value to determine which test
     * to conduct.
     */
    test_case = ((seglen > 0) ? 2 : 0) | ((tcb->rcv_wnd > 0) ? 1 : 0);
    CNE_DEBUG("Acceptability test case [orange]%d[]\n", test_case);

    /* Local values for (RCV.NXT + RCV.WND) and (SEG.SEQ + SEG.LEN - 1) */
    lwin = (tcb->rcv_nxt + tcb->rcv_wnd);
    lseq = (seg->seq + seglen - 1);

    switch (test_case) {
    /* seglen == 0, RCV.WND == 0 */
    case 0:
        acceptable = (seg->seq == tcb->rcv_nxt);
        break;

    /* seglen == 0, RCV.WND   >0 */
    case 1:
        acceptable = (seqLEQ(tcb->rcv_nxt, seg->seq) && seqLT(seg->seq, lwin));
        if (!acceptable) {
            CNE_DEBUG("seqLEQ(tcb->rcv_nxt, seg->seq) [orange]%d[] && [orange]%d[] "
                      "seqLT(seg->seq, lwin)\n",
                      seqLEQ(tcb->rcv_nxt, seg->seq), seqLT(seg->seq, lwin));
            CNE_DEBUG("  rcv_nxt: %u\n", tcb->rcv_nxt);
            CNE_DEBUG("  seq    : %u\n", seg->seq);
            CNE_DEBUG("  lwin   : %u\n", lwin);
        }
        break;

    /* seglen   >0, RCV.WND == 0 */
    case 2:
        acceptable = false;
        break;

    /* seglen   >0, RCV.WND   >0 */
    case 3:
        acceptable = ((seqLEQ(tcb->rcv_nxt, seg->seq) && seqLT(seg->seq, lwin)) ||
                      (seqLEQ(tcb->rcv_nxt, lseq) && seqLT(lseq, lwin)));
        if (!acceptable) {
            CNE_DEBUG("  seqLEQ(tcb->rcv_nxt, seg->seq) [orange]%d[] && [orange]%d[] "
                      "seqLT(seg->seq, lwin) ||\n",
                      seqLEQ(tcb->rcv_nxt, seg->seq), seqLT(seg->seq, lwin));
            CNE_DEBUG(
                "      seqLEQ(tcb->rcv_nxt, lseq) [orange]%d[] && [orange]%d[] seqLT(lseq, lwin)\n",
                seqLEQ(tcb->rcv_nxt, lseq), seqLT(lseq, lwin));
            CNE_DEBUG("  rcv_nxt: %u\n", tcb->rcv_nxt);
            CNE_DEBUG("  seq    : %u\n", seg->seq);
            CNE_DEBUG("  lwin   : %u\n", lwin);
            CNE_DEBUG("  lseq   : %u\n", lseq);
        }
        break;
    }

skip_test:
    CNE_DEBUG("Segment is [orange]<%s acceptable>[]\n", acceptable ? "" : "Not");

    /*
     * If the RCV.WND is zero, no segments will be acceptable, but special
     * allowance should be make to accept valid ACKs, URGs and RSTs.
     */
    if ((tcb->rcv_wnd == 0) && is_set(tflags, (TCP_ACK | TCP_URG | TCP_RST))) {
        CNE_DEBUG("Allow ACK, URG or RST segments, force acceptable\n");
        acceptable = true;
    }

    return acceptable;
}

/*
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

        /* Need to look into supporting SACK_PERMIT support */
    }

    /* Compute proper scaling value from buffer space */
    cnet_tcp_chnl_scale_set(tcb, ch);
}

/*
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

    CNE_DEBUG("Passive Open checks\n");
    /*
     * If SYN is not set then exit, but if a text-bearing segment it will be
     * processed on return.
     */
    if (is_clr(seg->flags, TCP_SYN))
        CNE_NULL_RET("SYN flag not set\n");

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
        tcp_drop_with_reset(seg->pcb->netif, seg, NULL);
        CNE_NULL_RET("Segment has ACK bit set\n");
    }

    /* Clear the SYN bit to make sure it is not processed again in SYN_SENT */
    seg->flags &= ~TCP_SYN;

    tcb = ppcb->tcb; /* use tcb pointer for the next test */

    md = pktmbuf_metadata(seg->mbuf);
    if (!md)
        CNE_NULL_RET("pktmbuf metadata is NULL\n");

    /*
     * Check the queue limit and see if we can continue, if not drop the SYN
     * request without sending a RST.
     *
     * BSD uses ((q_limit * 3)/2)+1,
     * where  0 <= q_limit <= CNET_TCP_BACKLOG_COUNT as the
     * standard limit formula. For a backlog of 0 at least 1 is allowed.
     */
    int qcnt = tcb->half_open_q.cnt + tcb->backlog_q.cnt;
    if (qcnt > ((3 * tcb->qLimit) / 2))
        CNE_NULL_RET("Half or backlog queue full\n");

    /* Allocate a new PCB/TCB/Chnl for an unbound channel */
    nch = __chnl_create(ppcb->ch->ch_proto->domain, ppcb->ch->ch_proto->type,
                        ppcb->ch->ch_proto->proto, ppcb);
    if (!nch) {
        tcp_drop_with_reset(tcb->netif, seg, NULL);
        CNE_NULL_RET("chnl create failed, netif %p\n", tcb->netif);
    }

    nch->ch_pcb->netif = cnet_netif_from_index(seg->mbuf->lport);
    if (!nch->ch_pcb->netif)
        CNE_WARN("Unable to locate netif structure\n");
    CNE_DEBUG("Netif @ [orange]%p[]\n", nch->ch_pcb->netif);

    /* Add the pkt information to the new pcb */
    in_caddr_copy(&nch->ch_pcb->key.faddr, &md->faddr);
    in_caddr_copy(&nch->ch_pcb->key.laddr, &md->laddr);

    /* Retain part of the options */
    nch->ch_options  = ppcb->ch->ch_options & ((1 << SO_DONTROUTE) | (1 << SO_KEEPALIVE));
    nch->ch_callback = ppcb->ch->ch_callback;

    /*
     * Allocate a new PCB and TCB structure to hold the new connection
     * leaving the old PCB/TCB alone to be used for other listen connections.
     */
    nch->ch_pcb->ch = nch;

    tcb = cnet_tcb_new(nch->ch_pcb);
    if (!tcb) {
        chnl_cleanup(nch);
        tcp_drop_with_reset(ppcb->tcb->netif, seg, NULL);
        CNE_NULL_RET("TCB allocation failed\n");
    }

    tcp_do_process_options(tcb, seg, nch);

    /* Setup this TCB as having a parent PCB */
    tcb->ppcb = ppcb;

    if (tcp_q_add(&ppcb->tcb->half_open_q, tcb->pcb))
        CNE_WARN("Unable to enqueue to half_open queue\n");

    /* Update and set the segment values */
    tcb->rcv_irs = seg->seq;
    tcb->rcv_nxt = tcb->rcv_adv = tcb->rcv_irs + 1;

    /* The window value has not been scaled yet, because the SYN is set */
    tcb->snd_wnd = seg->wnd << tcb->snd_scale;

    tcp_do_state_change(nch->ch_pcb, TCPS_SYN_RCVD); /* Move to SYN_RCVD */
    tcb->timers[TCPT_KEEP] = TCP_KEEP_INIT_TV;

    /* Tell the new TCB to send a SYN_ACK */
    tcb->tflags |= TCBF_ACK_NOW;
    CNE_DEBUG("TCP [cyan]Passive Open[]\n");

    INC_TCP_STAT(passive_open);

    return nch->ch_pcb;
}

/*
 * Drop the current TCP connection and use the <err_code> as the reason for
 * closing the connection.
 */
static inline void
tcp_do_drop_connection(struct pcb_entry *pcb, int32_t err_code)
{
    if (!TCPS_HAVE_RCVD_SYN(pcb->tcb->state))
        INC_TCP_STAT(no_syn_rcvd);

    if (pcb->ch != NULL)
        pcb->ch->ch_error = err_code;

    tcp_do_state_change(pcb, TCPS_CLOSED);
}

/*
 * Cleanup a TCB and free all values in the TCB that need freeing. The pcb
 * is removed from the parent half open or backlog queues. If this is a parent
 * to other pcbs then close them too.
 */
static int
tcb_cleanup(struct tcb_entry *tcb)
{
    struct pcb_entry *p, *tp;

    if (!tcb || tcb->state == TCPS_FREE || tcb->state == TCPS_CLOSED)
        return TCP_INPUT_NEXT_PKT_DROP;

    tcb->state = TCPS_CLOSED;

    tcb_kill_timers(tcb); /* Stop all of the timers */

    /* Mark the pcb as closed, to make sure a connection is not created */
    if ((p = tcb->pcb) != NULL) {
        tcb->pcb  = NULL;
        p->tcb    = NULL;
        p->closed = 1;
        chnl_cleanup(p->ch);

        /* Check the listening PCB or parent */
        if (tcb->ppcb && tcb->ppcb->tcb) {
            struct tcb_entry *t = tcb->ppcb->tcb;

            /* TCB may be on the parents backlog or half open queue */
            if (t && tcp_q_remove(&t->backlog_q, p) == 0)
                cnet_pcb_free(p);
            else if (t && tcp_q_remove(&t->half_open_q, p) == 0)
                cnet_pcb_free(p);
        }
    }

    /* Remove connections from the backlog queue */
    TAILQ_FOREACH_SAFE (p, &tcb->backlog_q.head, next, tp) {
        if (tcp_q_remove(&tcb->backlog_q, p) == 0) {
            tcp_do_state_change(p, TCPS_CLOSED);
            cnet_pcb_free(p);
        }
    }

    /* Drop any half open connections */
    TAILQ_FOREACH_SAFE (p, &tcb->half_open_q.head, next, tp) {
        if (tcp_q_remove(&tcb->half_open_q, p) == 0) {
            tcp_do_state_change(p, TCPS_CLOSED);
            cnet_pcb_free(p);
        }
    }

    CNE_DEBUG("Half Open queue is clean, reassemble %p, %d\n", tcb->reassemble,
              vec_len(tcb->reassemble));

    pktmbuf_free_bulk(tcb->reassemble, vec_len(tcb->reassemble));

    /* TCB should be disconnected and ready to be freed */
    vec_free(tcb->reassemble);

    tcb_free(tcb);

    return 0;
}

/*
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

        if (tcb && tcb->netif) {
            CNE_DEBUG("Second check for an ACK\n");
            tcp_drop_with_reset(tcb->netif, seg, NULL);
        }
        return TCP_INPUT_NEXT_PKT_DROP;
    }

    CNE_DEBUG("\n");
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
     *   the foreign channel was not fully specified), then the
     *   unspecified fields should be filled in now.
     */

    /* Handle passive opens.                    p65-p66 */
    if (is_set(seg->pcb->tcb->tflags, TCBF_PASSIVE_OPEN)) {
        struct pcb_entry *pcb;

        CNE_DEBUG("Do [orange]Passive Open[]\n");
        if ((pcb = do_passive_open(seg)) == NULL) {
            CNE_WARN("Passive Open failed, Stop Processing\n");
            return TCP_INPUT_NEXT_PKT_DROP;
        }

        /* New PCB for segment as the previous was in the listen state */
        seg->pcb = pcb;
    }
    CNE_DEBUG("Exit with check output and drop\n");
    return TCP_CHECK_OUTPUT_AND_DROP;
}

/*
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

static inline int
_process_data(struct seg_entry *seg, struct tcb_entry *tcb __cne_unused)
{
    int rc = TCP_INPUT_NEXT_PKT_DROP;

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
        int len = pktmbuf_data_len(seg->mbuf);

        if (len) {
            /* Update the rcv_nxt with the number of bytes consumed */
            tcb->rcv_nxt += len;

            /* chnl_recv will enqueue the mbufs to the receive queue */

            seg->mbuf = NULL; /* Consumed the packet */
            rc        = TCP_INPUT_NEXT_CHNL_RECV;
        }
    }
    return rc;
}

/*
 * Process the segment data from the received packet and attach to the TCB.
 */
static int
do_process_data(struct seg_entry *seg)
{
    struct tcb_entry *tcb = seg->pcb->tcb;
    int rc                = TCP_INPUT_NEXT_PKT_DROP;

    if (!seg->len)
        return rc;

    /* Does the segment contain data if so then ack the data, if required */
    if ((seg->seq == tcb->rcv_nxt) && vec_len(tcb->reassemble) == 0 &&
        (tcb->state == TCPS_ESTABLISHED)) {

        rc = _process_data(seg, tcb);

        if (is_clr(tcb->tflags, TCBF_DELAYED_ACK))
            tcb->tflags |= TCBF_DELAYED_ACK;
        else {
            tcb->tflags |= TCBF_ACK_NOW;
            cnet_tcp_output(tcb);
        }
    } else {
        /* TODO: set return value for the reassembled segment */
        seg->flags = tcp_reassemble(seg);

        tcb->tflags |= TCBF_ACK_NOW;
        cnet_tcp_output(tcb);
    }
    return rc;
}

/*
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
            INC_TCP_STAT(invalid_ack);

            CNE_DEBUG("Invalid ACK, SEG.ACK =< SEG.ISS or SEG.ACK > SND.NXT send a reset\n");

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
        INC_TCP_STAT(tcp_rst);

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
            tcp_do_state_change(seg->pcb, TCPS_ESTABLISHED);

            tcb->snd_wnd = seg->wnd << tcb->snd_scale;
            tcb->snd_wl1 = seg->seq - 1;

            tcp_set_CWND(tcb);
        } else
            tcp_do_state_change(seg->pcb, TCPS_SYN_RCVD);

        /* Force an ACK to be sent */
        seg->pcb->tcb->tflags |= TCBF_ACK_NOW;

        return do_process_data(seg);
    }

    return TCP_INPUT_NEXT_PKT_DROP;
}

/*
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

/*
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

/*
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
    tcb->tflags |= TCBF_FORCE_TX;
}

/*
 * Handle the Syn Received state of the given segment or TCB.
 */
static int
do_segment_others(struct seg_entry *seg)
{
    struct tcb_entry *tcb = seg->pcb->tcb;
    struct chnl *ch       = seg->pcb->ch;
    int32_t trim, rc = TCP_INPUT_NEXT_PKT_DROP;
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
    if (acceptable == false)
        return tcp_drop_after_ack(seg);

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
    if (trim > 0)
        CNE_ERR_GOTO(drop, "Seq before window\n");

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
    CNE_DEBUG("Check [orange]RST[] flag\n");
    if (is_set(seg->flags, TCP_RST)) {
        CNE_DEBUG("RST is set ( %s)\n", tcp_print_flags(seg->flags));

        INC_TCP_STAT(tcp_rst);

        /* Handle moving a connection back to the Listen state, if passive */
        if (is_set(tcb->tflags, TCBF_PASSIVE_OPEN)) {
            /*
             * SYN_RCVD state remove from half open queue of the parent, if
             * started from a passive open.
             */
            if (tcb->ppcb && tcb->ppcb->tcb) {
                if (tcp_q_remove(&tcb->ppcb->tcb->half_open_q, seg->pcb))
                    CNE_WARN("PCB not found on half open queue\n");
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
    CNE_DEBUG("Check [orange]RFC 1323 PAWS[]\n");
    if ((seg->ts_val > 0) && (tcb->ts_recent > 0) && tstampLT(seg->ts_val, tcb->ts_recent)) {
        /* Check if the ts_recent is 24 days old */
        if ((stk_get_timer_ticks() - tcb->ts_recent_age) > TCP_PAWS_IDLE)
            /*
             * Invalidate ts_val, which will be placed in the next
             * echo reply (via ts_recent) of the timestamp option.
             */
            seg->ts_val = 0;
        else {
            CNE_ERR("TimeStamp failed\n");
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
    CNE_DEBUG("Check RFC 793 [orange]SYN[] bit\n");
    if (is_set(seg->flags, TCP_SYN)) {
        /* RFC1122 - p94
         *
         * (e) Check SYN bit, p. 71: "In SYN-RECEIVED state and if
         *     the connection was initiated with a passive OPEN, then
         *     return this connection to the LISTEN state and return.
         *     Otherwise...".
         */
        if ((tcb->state == TCPS_SYN_RCVD) && is_set(tcb->tflags, TCBF_PASSIVE_OPEN))
            tcp_do_state_change(seg->pcb, TCPS_LISTEN);
        else {
            CNE_DEBUG(
                "Changing state to [orange]Closed[], [orange]not SYN_RCVD and PASSIVE_OPEN[]\n");
            tcp_drop_with_reset(tcb->netif, seg, seg->pcb);
            tcp_do_state_change(seg->pcb, TCPS_CLOSED);
        }

        return TCP_INPUT_NEXT_PKT_DROP;
    }

    /* RFC793 - p72
     *
     * Fifth, check the ACK bit
     *
     * if the ACK bit is off drop the segment and return
     *   If the ACK bit is set ...
     */
    CNE_DEBUG("Check RFC 793 [orange]ACK[] bit\n");
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
            CNE_DEBUG("If the segment acknowledgment is not acceptable,form a reset segment with "
                      "<SEQ=SEG.ACK><CTL=RST>\n");
            tcp_drop_with_reset(tcb->netif, seg, seg->pcb);
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
                    /* Equation (3): ssthresh = max (FlightSize / 2, 2*SMSS) */
                    tcb->snd_ssthresh       = win * tcb->max_mss;
                    tcb->timers[TCPT_REXMT] = 0;
                    tcb->rtt                = 0;
                    tcb->snd_nxt            = seg->ack;
                    tcb->snd_cwnd           = tcb->max_mss;

                    cnet_tcp_output(tcb);
                    /*
                     * 2. Retransmit the lost segment and set cwnd to ssthresh
                     *    plus 3*SMSS. This artificially "inflates" the
                     *    congestion window by the number of segments (three)
                     *    that have left the network and which the receiver
                     *    has buffered.
                     */
                    CNE_WARN("Hit dupacks threshold %d\n", tcb->dupacks);
                    tcb->snd_cwnd = tcb->snd_ssthresh + (TCP_RETRANSMIT_THRESHOLD * tcb->max_mss);
                    if (seqGT(onxt, tcb->snd_nxt))
                        tcb->snd_nxt = onxt;
                }
                /* RFC2581: pg 7
                 * 3. For each additional duplicate ACK received, increment cwnd
                 *    by SMSS. This artificially inflates the congestion window
                 *    in order to reflect the additional segment that has left
                 *    the network.
                 */
                else if (tcb->dupacks > TCP_RETRANSMIT_THRESHOLD) {
                    CNE_WARN("Retransmit Threshold hit %d\n", tcb->dupacks);
                    tcb->snd_cwnd += tcb->max_mss;
                    cnet_tcp_output(tcb);
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
            CNE_DEBUG("Dup ACKs %d\n", tcb->dupacks);

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
            if (tcb->pcb && tcb->pcb->ch)
                tcb->pcb->ch->ch_callback(CHNL_TCP_CLOSE_TYPE, tcb->pcb->ch->ch_cd);

            tcp_do_state_change(seg->pcb, TCPS_CLOSED);
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
            CNE_DEBUG("FIN set in TIME_WAIT\n");
            return TCP_INPUT_NEXT_PKT_DROP;
        }

        /* Retransmission of FIN bit then ACK it. */
        tcp_do_state_change(seg->pcb, TCPS_TIME_WAIT);
        CNE_DEBUG("After move to TIME_WAIT\n");
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
    CNE_DEBUG("Check RFC 793 [orange]URG[] bit\n");
    if (is_set(seg->flags, TCP_URG)) {
        CNE_DEBUG("URG is set\n");

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
    CNE_DEBUG("Check TCB State ([orange]%s[])\n", tcb_in_states[tcb->state]);
    if (TCPS_HAVE_RCVD_FIN(tcb->state) == 0)
        rc = do_process_data(seg);

    /*
     * Once the TCP takes responsibility for the data it advances
     * RCV.NXT over the data accepted, and adjusts RCV.WND as
     * appropriate to the current buffer availability. The total of
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
        CNE_DEBUG("Found [orange]FIN[] bit\n");
        /*
         * Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
         * since the SEG.SEQ cannot be validated; drop the segment and
         * return.
         */
        if (tcb->state < TCPS_SYN_RCVD) {
            CNE_WARN("state [orange]%s[] < SYN_RCVD, Stop\n", tcb_in_states[tcb->state]);
            return TCP_INPUT_NEXT_PKT_DROP;
        }

        /*
         * If the FIN bit is set, signal the user "connection closing" and
         * return any pending RECEIVEs with same message, advance RCV.NXT
         * over the FIN, and send an acknowledgment for the FIN. Note that
         * FIN implies PUSH for any segment text not yet delivered to the
         * user.
         */
        tcb->rcv_nxt++;

        if (TCPS_HAVE_RCVD_FIN(tcb->state)) {
            /* Send ACK for the FIN */
            tcb->tflags |= TCBF_ACK_NOW;
            CNE_DEBUG("Send [orange]ACK[] for [orange]FIN[]\n");
        }

        switch (tcb->state) {
        /*
         * Enter the CLOSE-WAIT state.
         */
        /* case TCPS_SYN_RCVD: Not required, but listed in RFC 793*/
        case TCPS_ESTABLISHED:
            CNE_DEBUG("[orange]FIN[] bit set in [orange]Established[] state\n");
            tcp_do_state_change(tcb->pcb, TCPS_CLOSE_WAIT);
            tcp_do_response(tcb->netif, tcb->pcb, NULL, tcb->snd_nxt, tcb->rcv_nxt, TCP_ACK);
            tcp_do_state_change(tcb->pcb, TCPS_LAST_ACK);
            break;

        /*
         * If our FIN has been ACKed (perhaps in this segment), then
         * enter TIME-WAIT, start the time-wait timer, turn off the other
         * timers; otherwise enter the CLOSING state.
         */
        case TCPS_FIN_WAIT_1:
            CNE_DEBUG("FIN bit set in [orange]FIN Wait 1[]\n");
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
            CNE_DEBUG("FIN bit set in [orange]FIN Wait 2[]\n");
            tcp_do_state_change(tcb->pcb, TCPS_TIME_WAIT);
            tcb->timers[TCPT_2MSL] = 2 * TCP_MSL_TV;
            break;

        /*
         * Remain in the TIME-WAIT state. Restart the 2 MSL time-wait
         * timeout.
         */
        case TCPS_TIME_WAIT:
            CNE_DEBUG("FIN bit set in [orange]Time Wait[]\n");
            tcb->timers[TCPT_2MSL] = 2 * TCP_MSL_TV;
            break;

        /*
         * Remain in the current state for the following.
         */
        case TCPS_CLOSE_WAIT:
        case TCPS_CLOSING:
        case TCPS_LAST_ACK:
        case TCPS_CLOSED:
        case TCPS_SYN_SENT:
        case TCPS_LISTEN:
            break;
        default:
            CNE_WARN("Default case TCP State [orange]%s[]\n", tcb_in_states[tcb->state]);
            break;
        }
        CNE_DEBUG("Done checking [orange]FIN[] bit\n");
    }

    return rc;
}

/*
 * Do the delivery of a segment and call the correct handler for the given state.
 */
static inline int
do_segment_arrives(struct seg_entry *seg)
{
    struct tcb_entry *tcb = seg->pcb->tcb;
    int32_t win;

    /*
     * Calculate amount of space in receive window, and then do TCP input
     * processing. Receive window is amount of space in rcv queue,
     * but not less than advertised window.
     */
    win = cb_space(&seg->pcb->ch->ch_rcv);
    CNE_DEBUG("window size [cyan]%d[]\n", win);
    tcb->rcv_wnd = CNE_MAX(win, (int32_t)(tcb->rcv_adv - tcb->rcv_nxt));

    if (tcb->state == TCPS_LISTEN) /* Handle passive open data. p65-p66 */
        return do_segment_listen(seg);
    else if (tcb->state == TCPS_SYN_SENT) /* Handle active open data. p66-p68 */
        return do_segment_syn_sent(seg);

    /* Otherwise. p69-p76 */
    return do_segment_others(seg);
}

/*
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
        CNE_DEBUG("Possible passive open segment\n");
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
        /* TODO: Allow the users to put more data in send buffer */
    }

    /* Update the send unacked variable to the current acked value */
    tcb->snd_una = seg->ack;

    /* When snd_nxt becomes less than snd_una, update snd_nxt. */
    if (seqLT(tcb->snd_nxt, tcb->snd_una)) {
        CNE_DEBUG("Update snd_nxt to snd_una\n");
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
            chnl_state_set(ch, _ISDISCONNECTED);
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

    default:
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
            if (cb_space(&ch->ch_snd) >= ch->ch_snd.cb_lowat) {
                /* TODO: implement support for enabling write to add more data */
            }

            /* When we have more data to send then call output routine */
            if (ch->ch_snd.cb_cc > 0)
                cnet_tcp_output(tcb);

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
        int rc = TCP_INPUT_NEXT_PKT_DROP;

        INC_TCP_STAT(data_predicted);

        rc = _process_data(seg, tcb);

        if (is_clr(tcb->tflags, TCBF_DELAYED_ACK))
            tcb->tflags |= TCBF_DELAYED_ACK;
        else {
            tcb->tflags |= TCBF_ACK_NOW;
            cnet_tcp_output(tcb);
        }

        return rc;
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

/*
 * Process the incoming packet bytes using page 65 of RFC793. The routine is
 * called from the lower layers to process all TCP type packets.
 */
int
cnet_tcp_input(struct pcb_entry *pcb, pktmbuf_t *mbuf)
{
    struct cne_ipv4_hdr *ip;
    struct cne_tcp_hdr *tcp;
    uint8_t *opts         = NULL;
    int rc                = TCP_INPUT_NEXT_PKT_DROP;
    struct seg_entry *seg = NULL;
    uint16_t tlen;
    struct tcb_entry *tcb      = NULL;
    uint8_t tcp_syn_fin_cnt[4] = {0, 1, 1, 2};

    if (!(this_cnet->flags & CNET_TCP_ENABLED))
        CNE_ERR_GOTO(free_seg, "TCP is not enabled\n");

    INC_TCP_STAT(rx_total);

    CNE_DEBUG("[yellow]>>> [magenta]Process TCP input[]\n");

    if (!pcb)
        goto free_seg;

    /* Grab a new seg structure */
    if ((seg = alloc_seg()) == NULL)
        goto free_seg;

    seg->mbuf = mbuf;
    seg->pcb  = pcb;

    /* Grab the IP and TCP header pointers */
    ip = pktmbuf_mtod(mbuf, struct cne_ipv4_hdr *);

    /* packet offset has been adjusted to tcp header in tcp input graph node */
    tcp = pktmbuf_adjust(mbuf, struct cne_tcp_hdr *, mbuf->l3_len);
    if (!tcp)
        CNE_ERR_GOTO(free_seg, "tcp pointer is invalid\n");

    TCP_DUMP(tcp);

    /* remove IP options if found */
    tcp_strip_ip_options(mbuf);

    /* Verify the packet has enough space in the packet. */
    if (pktmbuf_data_len(mbuf) < sizeof(struct cne_tcp_hdr)) {
        INC_TCP_STAT(rx_short);
        CNE_ERR_GOTO(free_seg, "Packet too short %d\n", pktmbuf_data_len(mbuf));
    }

    /* Total length of IP payload plus IP header and options */
    tlen = be16toh(ip->total_length);

    /* Calculate the TCP header + options value in bytes. */
    seg->offset = (tcp->data_off & 0xF0) >> 2;

    pktmbuf_adj_offset(mbuf, seg->offset); /* Skip L4 Header */

    /* Verify the TCP data and header offset is valid */
    if ((seg->offset < sizeof(struct cne_tcp_hdr)) || (seg->offset > tlen)) {
        INC_TCP_STAT(rx_badoff);
        CNE_ERR_GOTO(free_seg, "packet invalid for TCP offset %d, tlen %d\n", seg->offset, tlen);
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

    tlen -= (seg->offset + mbuf->l3_len); /* Real TCP length */
    seg->len = tlen + tcp_syn_fin_cnt[seg->flags & SYN_FIN];

    /* Set opts to point at the options, if we have any options. */
    if (seg->offset > sizeof(struct cne_tcp_hdr))
        opts = (uint8_t *)&tcp[1];

    /*
     * Segment Arrives - Starting p65-p76 - RFC793
     */

    /* If TCB is closed send RST.      p65     */
    if ((tcb = seg->pcb->tcb) == NULL) {
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
        CNE_WARN("[orange]PCB or TCB is NULL[]\n");
        tcp_drop_with_reset(pcb->netif, seg, seg->pcb);

        /* Drop the PCB pointer from the segment, maybe NULL already */
        seg->pcb = NULL;
        CNE_ERR_GOTO(free_seg, "[orange]PCB is not found[]\n");
    }
    if (tcb->state == TCPS_CLOSED)
        CNE_ERR_GOTO(free_seg, "[orange]TCB is Closed[]\n");

    /* Process the packet for the given TCP state */
    tcb->idle              = 0;
    tcb->timers[TCPT_KEEP] = tcb->tcp->keep_idle;

    /* Scale the window value if not a SYN segment */
    if (is_clr(seg->flags, TCP_SYN))
        seg->wnd = seg->wnd << tcb->snd_scale;

    /* Do the option handling now, before we do anything like passive open */
    if (opts) {
        if (tcp_do_options(seg, opts))
            CNE_ERR_GOTO(free_seg, "tcp_do_options() failed\n");
        CNE_DEBUG("Flags: [orange]%s[]\n", tcb_print_flags(seg->pcb->tcb->tflags));
    }

#ifdef ENABLE_HEADER_PREDICTION
    /*
     * TCP Header prediction.
     *
     * This code follows the code in TCP/IP Illustrated Volume II by Stevens.
     *
     * Make sure we are in the established state and we only have an ACK
     * present in the tcp flags. Also with the next seq what we expect along
     * with window we expect.
     */
    if ((tcb->state == TCPS_ESTABLISHED) && ((seg->flags & HDR_PREDIC) == TCP_ACK) &&
        (is_clr(seg->sflags, SEG_TS_PRESENT) || tstampGEQ(seg->ts_val, tcb->ts_recent)) &&
        (seg->seq == tcb->rcv_nxt) && (seg->wnd && (seg->wnd == tcb->snd_wnd)) &&
        (tcb->snd_nxt == tcb->snd_max)) {
        if (tcp_header_prediction(seg, tcb)) {
            CNE_DEBUG("Header prediction [orange]Good[]\n");
            rc = TCP_INPUT_NEXT_CHNL_RECV;
            goto free_seg;
        }
    }
#endif

    /* Process the segment information and handle the TCP protocol */
    rc = do_segment_arrives(seg);
    CNE_DEBUG("segment has arrived returned [cyan]%d[]\n    ( [orange]%s[])\n", rc,
              tcb_print_flags(tcb->tflags));

    /*
     * After segment processing, do we need to send a packet?
     * Must update the tcb as the pcb pointer may have changed
     */
    if (rc == TCP_CHECK_OUTPUT_AND_DROP) {
        /* Get new TCB if passive open */
        tcb = seg->pcb->tcb;
        CNE_DEBUG("Check output and drop\n     TCB flags ( [orange]%s[])\n",
                  tcb_print_flags(tcb->tflags));

        /* old Listen PCB maybe replaced with new pcb */
        if (is_set(tcb->tflags, TCBF_ACK_NOW) || seg->pcb->ch->ch_snd.cb_cc)
            cnet_tcp_output(tcb);

        rc = TCP_INPUT_NEXT_PKT_DROP;
    }

    if (seg->pcb && seg->pcb->tcb && seg->pcb->tcb->state != TCPS_SYN_RCVD)
        cnet_tcp_output(seg->pcb->tcb);

free_seg:
    free_seg(seg);
    CNE_DEBUG("Leave\n\n");
    return rc;
}

/*
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
            cnet_tcp_output(t);
        }
    }
}

/*
 * Process the fast timeout for TCP, which is used for delayed ACKs.
 */
static inline void
tcp_fast_timo(void *arg)
{
    stk_t *stk        = (stk_t *)arg;
    struct pcb_hd *hd = &stk->tcp->tcp_hd;
    struct pcb_entry *p;

    if (!hd)
        CNE_RET("tcp_hd is NULL\n");

    /* TCP fast timer to process Delayed ACKs. */
    vec_foreach_ptr (p, hd->vec) {
        struct tcb_entry *t = p->tcb;

        if (t && is_set(t->tflags, TCBF_DELAYED_ACK)) {
            t->tflags &= ~TCBF_DELAYED_ACK;
            t->tflags |= TCBF_ACK_NOW;

            INC_TCP_STAT(delayed_ack);

            /* ACK flag is cleared in tcp output */
            cnet_tcp_output(t);
        }
    }
}

/*
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
            cnet_tcp_output(t);

            tcp_set_persist(t);
        }

        break;

    case TCPT_KEEP:
        if (t->state < TCPS_ESTABLISHED) {
            CNE_DEBUG("TCB state %s < TCPS_ESTABLISHED\n", tcb_in_states[t->state]);
            goto dropit;
        }

        if (is_set(p->opt_flag, SO_KEEPALIVE) && (t->state <= TCPS_CLOSE_WAIT)) {
            if (t->idle >= (stk->tcp->keep_idle + stk->tcp->max_idle)) {
                CNE_DEBUG("Idle %d < %d\n", t->idle, stk->tcp->keep_idle + stk->tcp->max_idle);
                goto dropit;
            }

            CNE_DEBUG("[orange]Keepalive!![]\n");
            tcp_do_response(t->netif, p, NULL, t->snd_nxt - 1, t->rcv_nxt - 1, TCP_ACK);

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

        INC_TCP_STAT(tcp_rexmit);

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

        /* Set the ACK now bit to force a retransmit. */
        t->tflags |= TCBF_ACK_NOW;
        cnet_tcp_output(p->tcb);
        break;

    default:
        break;
    }

    return state;
}

/*
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

        if (t->state == TCPS_CLOSED || t->state == TCPS_LISTEN)
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

/*
 * Timeout every XXms to be able to have a fast and slow timer of 200ms/500ms.
 */
static void
_process_timers(struct cne_timer *tim __cne_unused, void *arg)
{
    stk_t *stk = arg;

    if (!(stk->ticks % (TCP_REXMT_TIMEOUT_MS / MS_PER_TICK)))
        tcp_fast_retransmit_timo(stk);

    if (!(stk->ticks % (TCP_FAST_TIMEOUT_MS / MS_PER_TICK)))
        tcp_fast_timo(stk);

    if (!(stk->ticks % (TCP_SLOW_TIMEOUT_MS / MS_PER_TICK)))
        tcp_slow_timo(stk);
}

/*
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

        CNE_DEBUG("[cyan]SYN[] is set\n    TCB flags ( [orange]%s[])\n",
                  tcb_print_flags(tcb->tflags));

        /* Add the MSS to the options */
        *p++   = TCP_OPT_MSS;
        *p++   = TCP_OPT_MSS_LEN;
        *p++   = (uint8_t)(tcb->max_mss >> 8);
        *p++   = (uint8_t)tcb->max_mss;
        optlen = 4;

        /*
         * Add the Window scaling option if:
         *     requesting a scaling and got a window scaling option from peer or
         *     requesting a scaling and this is the first SYN.
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

    CNE_DEBUG("tcb state [orange]%s[]\n", tcb_print_flags(tcb->tflags));
    CNE_DEBUG("TCP flags [orange]%s[]\n", tcp_print_flags(flags_n));

    if (is_set(tcb->tflags, TCBF_REQ_TSTAMP) && is_clr(flags_n, TCP_RST) &&
        (((flags_n & SYN_ACK) == TCP_SYN) || is_set(tcb->tflags, TCBF_RCVD_TSTAMP))) {
        uint32_t tcp_now = stk_get_timer_ticks();
        uint32_t *lp     = (uint32_t *)p;

        *lp++ = htobe32((TCP_OPT_NOP << 24) | (TCP_OPT_NOP << 16) | (TCP_OPT_TSTAMP << 8) |
                        TCP_OPT_TSTAMP_LEN);
        *lp++ = htobe32(tcp_now);
        *lp++ = htobe32(tcb->ts_recent);
        optlen += 12;
    } else
        CNE_DEBUG("TCP options not added\n");

    return optlen; /* Length of options */
}

/*
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
cnet_tcp_abort(struct pcb_entry *pcb)
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

        CNE_DEBUG("[orange]Abort[]\n");
        tcp_do_response(tcb->netif, pcb, NULL, tcb->snd_nxt, tcb->rcv_nxt, TCP_RST);

        INC_TCP_STAT(resets_sent);
    }

    tcp_do_state_change(pcb, TCPS_CLOSED);
}

/*
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

    chnl_state_set(pcb->ch, _ISCONNECTING);

    tcb->state             = TCPS_SYN_SENT;
    tcb->timers[TCPT_KEEP] = TCP_KEEP_INIT_TV;

    /* Set the new send ISS value. */
    tcp_send_seq_set(tcb, 7);

    INC_TCP_STAT(tcp_connect);

    tcb->tflags |= TCBF_ACK_NOW;

    cnet_tcp_output(tcb);

    if (pcb->ch->ch_error) {
        int err = pcb->ch->ch_error;

        pcb->ch->ch_error = 0;
        return err;
    }
    return 0;
}

/*
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
cnet_tcp_close(struct pcb_entry *pcb)
{
    /* The pcb->tcb must be valid or return false */
    if (!pcb || !pcb->tcb)
        return false;

    if (pcb->tcb->state == TCPS_CLOSED || pcb->tcb->state == TCPS_FREE)
        return false;

    switch (pcb->tcb->state) {
    case TCPS_SYN_RCVD: /* FALLTHRU */
    case TCPS_ESTABLISHED:
        tcp_do_state_change(pcb, TCPS_FIN_WAIT_1);
        break;

    case TCPS_CLOSE_WAIT:
        tcp_do_state_change(pcb, TCPS_LAST_ACK);
        break;

    case TCPS_SYN_SENT: /* FALLTHRU */
    case TCPS_LISTEN:   /* FALLTHRU */
    default:
        tcp_do_state_change(pcb, TCPS_CLOSED);
        return false;
    }

    /* Force the other side to close his connection. */
    pcb->tcb->tflags |= TCBF_ACK_NOW;
    return (tcp_output(pcb->tcb) == -1) ? true : false;
}

void
cnet_tcb_list(stk_t *stk, struct tcb_entry *tcb)
{
    struct tcb_entry *t;

    if (!stk)
        stk = this_stk;

    cne_printf("[yellow]%s: [skyblue]TCB Information[]\n", stk->name);
    for (int i = 0; i < CNET_NUM_TCBS; i++) {
        if (bit_test(stk->tcbs, i) == 0)
            continue;

        t = mempool_obj_at_index(stk->tcb_objs, i);
        if (!t || (tcb && (tcb != t)))
            continue;

        cne_printf("[orange]TCB[] @ %p\n", t);
        cne_printf("   State: <[orange]%s[]>\n", tcb_in_states[t->state]);
        cne_printf(
            "   Snd: UNA %u nxt %u urp %u iss %u wl1 %u wl2 %u up %u\n   max %u wnd %u sst %u "
            "cwnd %u sndwnd %u\n",
            t->snd_una, t->snd_nxt, t->snd_urp, t->snd_iss, t->snd_wl1, t->snd_wl2, t->snd_up,
            t->snd_max, t->snd_wnd, t->snd_ssthresh, t->snd_cwnd, t->max_sndwnd);
        cne_printf("   Rcv: wnd %u nxt %u urp %u irs %u adv %u bsize %u sst %u\n", t->rcv_wnd,
                   t->rcv_nxt, t->rcv_urp, t->rcv_irs, t->rcv_adv, t->rcv_bsize, t->rcv_ssthresh);
        cne_printf("   Flags: [orange]%s[]\n", tcb_print_flags(t->tflags));
    }
}

void
cnet_tcb_dump(void)
{
    stk_t *stk;
    struct cnet *cnet = this_cnet;

    vec_foreach_ptr (stk, cnet->stks)
        cnet_tcb_list(stk, NULL);
}

/*
 * Main entry point to initialize the TCP protocol.
 */
static int
tcp_init(int32_t n_tcb_entries, bool wscale, bool t_stamp)
{
    stk_t *stk                = this_stk;
    struct mempool_cfg cfg    = {0};
    struct protosw_entry *psw = NULL;

    stk->tcp_stats = calloc(1, sizeof(tcp_stats_t));
    if (!stk->tcp_stats)
        goto err_exit;

    stk->tcp = calloc(1, sizeof(struct tcp_entry));
    if (stk->tcp == NULL)
        goto err_exit;

    stk->tcbs = bit_alloc(CNET_NUM_TCBS);
    if (!stk->tcbs)
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
    stk->tcp->tcp_hd.local_port = _IPPORT_RESERVED;

    cfg.objcnt    = CNET_NUM_TCBS;
    cfg.objsz     = sizeof(struct seg_entry);
    cfg.cache_sz  = 64;
    stk->seg_objs = mempool_create(&cfg);
    if (stk->seg_objs == NULL)
        goto err_exit;

    psw = cnet_protosw_add("TCP", AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!psw)
        goto err_exit;

    cnet_ipproto_set(IPPROTO_TCP, psw);

    cne_timer_init(&stk->tcp_timer);

    if (cne_timer_reset(&stk->tcp_timer, (cne_get_timer_hz() / 1000) * 10, PERIODICAL, cne_id(),
                        _process_timers, (void *)stk) < 0)
        CNE_ERR_GOTO(cleanup, "Unable to start TCP timer for instance %s\n", stk->name);

    return 0;

err_exit:
    if (!stk->tcp_stats)
        CNE_ERR("Allocation failed for TCP stats structure\n");
    else if (!stk->tcp)
        CNE_ERR("Allocation failed for TCP structure\n");
    else if (!stk->tcbs)
        CNE_ERR("Allocation failed for TCB structures\n");
    else if (!stk->tcb_objs)
        CNE_ERR("TCB allocation failed for %d tcb_entries of %'ld bytes\n", n_tcb_entries,
                sizeof(struct tcb_entry));
    else if (!stk->seg_objs)
        CNE_ERR("Segment allocation failed for %d tcb_entries of %'ld bytes\n", CNET_NUM_TCBS,
                sizeof(struct seg_entry));
    else if (!psw)
        CNE_ERR("TCP proto input set failed or Timer registration\n");
cleanup:
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

    free(stk->tcp_stats);
    free(stk->tcp);
    free(stk->tcbs);

    mempool_destroy(stk->tcb_objs);
    mempool_destroy(stk->seg_objs);

    if (cne_timer_stop(&stk->tcp_timer) < 0)
        CNE_ERR("Unable to stop TCP timer for instance %s\n", stk->name);

    return 0;
}

CNE_INIT_PRIO(cnet_tcp_constructor, STACK)
{
    cnet_add_instance("tcp", CNET_TCP_PRIO, tcp_create, tcp_destroy);
}
