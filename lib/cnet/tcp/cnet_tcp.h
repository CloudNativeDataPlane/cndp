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

#ifndef __CNET_TCP_H
#define __CNET_TCP_H

/**
 * @file
 * CNET TCP protocol routines and constants.
 */

#include "cnet_const.h"        // for bool_t
#include "cnet_pcb.h"          // for pcb_hd

#include <net/cne_tcp.h>
#include <stdint.h>        // for uint32_t, uint16_t, int32_t, int16_t, uint8_t
#include <stdio.h>         // for NULL
#include <stdbool.h>
#include <sys/queue.h>        // for TAILQ_ENTRY, TAILQ_INSERT_TAIL, TAILQ_REMOVE

#include "cne_log.h"           // for CNE_LOG, CNE_LOG_DEBUG
#include "cnet_const.h"        // for bool_t
#include "cnet_pcb.h"          // for pcb_entry (ptr only), pcb_hd
#include "cnet_stk.h"          // for per_thread_stk, stk_entry, this_stk
#include "cnet_tcp.h"          // for tcb_entry (ptr only)
#include "mempool.h"           // for mempool_get, mempool_put
#include "pktmbuf.h"           // for pktmbuf_t
#ifdef __cplusplus
extern "C" {
#endif

#define CNET_TCP_REASSEMBLE_COUNT 256
#define CNET_TCP_BACKLOG_COUNT    128
#define CNET_TCP_HALF_OPEN_COUNT  128

/* Basic TCP packet header
 *
 *                        TCP Header Format
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |          Source Port          |       Destination Port        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                        Sequence Number                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Acknowledgment Number                      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Data |           |U|A|P|R|S|F|                               |
 *   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 *   |       |           |G|K|H|T|N|N|                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Checksum            |         Urgent Pointer        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Options                    |    Padding    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                             data                              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct cne_tcp_hdr;
struct cne_vec;

typedef uint32_t seq_t; /* TCP Sequence type */

/* Timestamp modulo math test macros */
static inline int
tstampLT(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) < 0;
}

static inline int
tstampLEQ(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) <= 0;
}

static inline int
tstampGEQ(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) >= 0;
}

/* Number of milli-seconds for 24 days */
#define TCP_PAWS_IDLE (24 * 24 * 60 * 60 * 1000)

/* TCP states (numeric values match those in RFC2452) */
typedef enum {
    TCPS_FREE = 0,
    TCPS_CLOSED,      /**< TCB is Closed */
    TCPS_LISTEN,      /**< TCB is listening */
    TCPS_SYN_SENT,    /**< Sent SYN segment */
    TCPS_SYN_RCVD,    /**< Received SYN segment */
    TCPS_ESTABLISHED, /**< Connection is established */
    TCPS_CLOSE_WAIT,  /**< Connection is in close wait state */
    TCPS_FIN_WAIT_1,  /**< Connection is in FIN wait 1 state */
    TCPS_CLOSING,     /**< Connection is closing */
    TCPS_LAST_ACK,    /**< Connection is in Last ACK state */
    TCPS_FIN_WAIT_2,  /**< Connection is in FIN wait 2 state */
    TCPS_TIME_WAIT    /**< Connection is in time wait state */
} tcb_state_t;

#define TCP_INPUT_STATES                                                                        \
    {                                                                                           \
        "Free", "Closed", "Listen", "SYN Sent", "SYN Rcvd", "Established", "CloseWait", "Fin1", \
            "Closing", "LastAck", "Fin2", "TimeWait", "DeleteTCB"                               \
    }

#define TCPS_HAVE_RCVD_SYN(s) ((s) >= TCPS_SYN_RCVD)
#define TCPS_HAVE_ESTABLISHED (s)((s) >= TCPS_ESTABLISHED)
#define TCPS_HAVE_RCVD_FIN(s) ((s) >= TCPS_TIME_WAIT)

/* tcp_hdr.flags TCP Header flags and seg_entry.flags */
enum {
    TCP_FIN    = 0x01,
    TCP_SYN    = 0x02,
    TCP_RST    = 0x04,
    TCP_PSH    = 0x08,
    TCP_ACK    = 0x10,
    TCP_URG    = 0x20,
    TCP_MASK   = 0x3F,
    SYN_FIN    = (TCP_SYN | TCP_FIN),
    RST_ACK    = (TCP_RST | TCP_ACK),
    FIN_ACK    = (TCP_FIN | TCP_ACK),
    SYN_ACK    = (TCP_SYN | TCP_ACK),
    SYN_RST    = (TCP_SYN | TCP_RST),
    HDR_PREDIC = (TCP_SYN | TCP_FIN | TCP_RST | TCP_URG | TCP_ACK)
};

/* Keep in bit order with above enums */
#define TCP_FLAGS                                \
    {                                            \
        "FIN", "SYN", "RST", "PSH", "ACK", "URG" \
    }

// clang-format off
/* State of the flags for all possible states in TCP */
#define TCP_OUTPUT_FLAGS                \
    {                                   \
        0,       /* TCPS_FREE        */ \
        RST_ACK, /* TCPS_CLOSED      */ \
        0,       /* TCPS_LISTEN      */ \
        TCP_SYN, /* TCPS_SYN_SENT    */ \
        SYN_ACK, /* TCPS_SYN_RCVD    */ \
        TCP_ACK, /* TCPS_ESTABLISHED */ \
        TCP_ACK, /* TCPS_CLOSE_WAIT  */ \
        FIN_ACK, /* TCPS_FIN_WAIT_1  */ \
        TCP_ACK, /* TCPS_CLOSING     */ \
        FIN_ACK, /* TCPS_LAST_ACK    */ \
        TCP_ACK, /* TCPS_FIN_WAIT_2  */ \
        TCP_ACK  /* TCPS_TIME_WAIT   */ \
    }
// clang-format on

/* TCP Output Events to drive the output Finite State Machine. */
enum { SEND_EVENT, PERSIST_EVENT, RETRANSMIT_EVENT, DELETE_EVENT };

#define TCP_OUTPUT_EVENTS                     \
    {                                         \
        "Send", "Persist", "Rexmit", "Delete" \
    }

/* TCP Option values */
enum {
    TCP_OPT_EOL = 0,   /**< End of Line flag */
    TCP_OPT_NOP,       /**< Noop type option */
    TCP_OPT_MSS,       /**< MSS option type */
    TCP_OPT_WSOPT,     /**< Window Scaling option */
    TCP_OPT_SACK_OK,   /**< SACK OK option */
    TCP_OPT_SACK,      /**< SACK option */
    TCP_OPT_TSTAMP = 8 /**< Timestamp option */
};

/* A few option lengths */
#define TCP_OPT_SACK_LEN   2
#define TCP_OPT_MSS_LEN    4
#define TCP_OPT_WSOPT_LEN  3
#define TCP_OPT_TSTAMP_LEN 10
#define TCP_MAX_OPTIONS    32

/* Few default values */
#ifdef TCP_MSS
#undef TCP_MSS
#endif
#define TCP_MIN_MSS          64           /**< Minimum segment size */
#define TCP_MSS              536          /**< Default Segment size (576 - 40) */
#define TCP_NORMAL_MSS       1460         /**< Normal TCP MSS value */
#define TCP_MAX_MSS          (16384 - 64) /**< Max TCP segment size */
#define TCP_MSS_OVERHEAD     52           /**< Size of Header(IPv4/v6/TCP) overhead */
#define TCP_DEFAULT_HDR_SIZE 20           /**< Default/minimum TCP header */
#undef TCP_MAXWIN
#ifndef ETHER_MAX_MTU
#define ETHER_MAX_MTU 65535
#endif
#define TCP_MAXWIN       ETHER_MAX_MTU /**< Max unscaled Window value */
#define TCP_MAX_WINSHIFT 14            /**< Max Window index value */
#define TCP_INITIAL_CWND 4380          /**< Max congestion window */
#define TCP_VEC_SIZE     1024          /**< TCP Vector size */

/* The following values are define in 500ms ticks slow timeout */
#define TCP_MSL_TV       60    /**< 30 Seconds Max Segment Lifetime */
#define TCP_MIN_TV       2     /**< 1 Second  retransmit timer. */
#define TCP_REXMTMAX_TV  128   /**< 64 Second retransmit timer. */
#define TCP_PERSMIN_TV   10    /**< 5 Second minimum persist timer. */
#define TCP_PERSMAX_TV   120   /**< 60 Seconds Max persist timer. */
#define TCP_KEEP_INIT_TV 150   /**< 75 Seconds connection established */
#define TCP_KEEP_IDLE_TV 14400 /**< 7200 Seconds idle time (first) */
#define TCP_KEEPINTVL_TV 150   /**< 75 Seconds between probes */
#define TCP_KEEPCNT_TV   8
#define TCP_SRTTBASE_TV  0 /**< special value */
#define TCP_SRTTDFLT_TV  2 /**< default RTT (1 seconds) */
#define TCP_KEEPCNT_TV   8 /**< Max number keepalive probes. */

#define TCP_RTT_SCALE    8 /**< multiplier   srtt = srtt x 8 */
#define TCP_RTT_SHIFT    3 /**< shift        srtt = srtt << 3 */
#define TCP_RTTVAR_SCALE 4 /**< multiplier   rttvar = rttvar x 4 */
#define TCP_RTTVAR_SHIFT 2 /**< shift        rttvar = rttvar << 2 */

#define TCP_ISSINCR 0x01000000 /**< Initial SYN Start increment */
#define TCP_SLOWHZ  2          /**< Slow hertz */

/* Number of ms per timeout */
#define TCP_REXMT_TIMEOUT_MS 100UL
#define TCP_FAST_TIMEOUT_MS  200UL
#define TCP_SLOW_TIMEOUT_MS  500UL

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 *
 * This macro assumes that the value of TCP_RTTVAR_SCALE
 * is the same as the multiplier for rttvar.
 */
#define tcpRexmtVal(_t) ((((_t)->srtt >> TCP_RTT_SHIFT) + (_t)->rttvar) / 500)

#define seqLT(a, b)  ((int)((a) - (b)) < 0)
#define seqLEQ(a, b) ((int)((a) - (b)) <= 0)
#define seqGT(a, b)  ((int)((a) - (b)) > 0)
#define seqGEQ(a, b) ((int)((a) - (b)) >= 0)
#define seqEQ(a, b)  ((int)((a) - (b)) == 0)
#define seqNE(a, b)  ((int)((a) - (b)) != 0)

#define TCP_MAXRXTSHIFT          12 /**< Max retransmissions */
#define TCP_RETRANSMIT_THRESHOLD 3

#define MAX_TCP_RCV_SIZE (128 * 1024)
#define MAX_TCP_SND_SIZE MAX_TCP_RCV_SIZE

/* Macro to deal with cne_mbuf pointer in TCP header */
#define reassPkt(_t) (*(pktmbuf_t **)&((_t)->tcp.src_port))

/* Index into the tcb.timers array */
enum {
    TCPT_REXMT = 0, /**< Retransmit timer index */
    TCPT_PERSIST,   /**< Persist timer index */
    TCPT_KEEP,      /**< Keepalive or Connection Established timer */
    TCPT_2MSL,      /**< 2 x Max Segment Life or FIN Wait 2 timer */
    TCP_NTIMERS     /**< Number of timers in tcb_t.timers */
};

/* Current Segment information in host order. */
struct seg_entry {
    TAILQ_ENTRY(seg_entry) entry;
    pktmbuf_t *mbuf;               /**< Current Packet pointer */
    struct pcb_entry *pcb;         /**< PCB attached to this segment */
    uint8_t flags;                 /**< Current TCP flags tcp_hd.flags */
    uint8_t offset;                /**< Current Segment offset in bytes */
    uint16_t mss;                  /**< MSS option value when present */
    uint16_t urp;                  /**< Current Segment urgent pointer */
    uint16_t len;                  /**< Current Segment length */
    uint16_t iplen;                /**< Total length of the IP Data */
    uint16_t sflags;               /**< Segment flags */
    uint16_t lport;                /**< lport id */
    uint32_t wnd;                  /**< Current Segment Window */
    seq_t seq;                     /**< Current Segment sequence */
    seq_t ack;                     /**< Current Segment acknowledge */
    uint32_t ts_val;               /**< Timestamp value */
    uint32_t ts_ecr;               /**< Timestamp ecr */
    void *ip;                      /**< IPv4/v6 header start. */
    uint8_t req_scale;             /**< Requested send scale */
    uint8_t optlen;                /**< TCP Options length */
    uint8_t opts[TCP_MAX_OPTIONS]; /**< TCP Option bytes */
};

/* seg_entry.sflags bit definitions */
enum {
    SEG_TS_PRESENT  = 0x8000, /**< Timestamp is present */
    SEG_MSS_PRESENT = 0x4000, /**< MSS option is present */
    SEG_WS_PRESENT  = 0x2000, /**< Window Scale present */
    SEG_SACK_PERMIT = 0x1000  /**< SACK permission flag, which is not supported at this time. */
};

enum {
    TCP_FAST_TIMER = 1, /**< Fast TCP timer (200ms) */
    TCP_SLOW_TIMER = 2, /**< Slow TCP timer (500ms) */
};

struct stk_s;
struct tcp_entry;
struct netif;

struct tcp_q {
    TAILQ_HEAD(, pcb_entry) head; /**< Head of the PCB backlog queue */
    atomic_uint_least32_t cnt;    /**< Number of entries in the list */
};

/* TCP Transmission Control Block */
struct tcb_entry {
    TAILQ_ENTRY(tcb_entry) entry; /**< Pointer to the next free tcb_entry structure */

    pktmbuf_t **reassemble;
    struct tcp_q backlog_q;   /**< Backlog queue of connections */
    struct tcp_q half_open_q; /**< Half open queue of connections */

    struct netif *netif;    /**< netif pointer */
    struct tcp_entry *tcp;  /**< Pointer to the TCP entry */
    struct pcb_entry *pcb;  /**< Pointer to PCB structure */
    struct pcb_entry *ppcb; /**< Pointer to Parent PCB */

    uint32_t tflags;   /**< TCP Flags, lower bits are output flags */
    uint32_t persist;  /**< Persist value */
    tcb_state_t state; /**< TCP Input State */
    uint16_t max_mss;  /**< Maximum Segment Size */

    int16_t timers[TCP_NTIMERS] __cne_aligned(8); /**< TCP timers */
    int32_t qLimit;                               /**< backlog limit for (3 * qLimit)/2 */

    /* RFC1323 variables */
    uint8_t snd_scale;      /**< Send Window scale */
    uint8_t rcv_scale;      /**< Receive Window scale */
    uint8_t req_recv_scale; /**< pending window scaling for receive */
    uint8_t req_send_scale; /**< pending window scaling for transmitter */
    uint32_t ts_recent;     /**< timestamp echo data */
    uint32_t ts_recent_age; /**< when last updated */
    seq_t last_ack_sent;    /**< last ACK Sent time */

    /* Send segment information */
    seq_t snd_una;         /**< Send unacked bytes */
    seq_t snd_nxt;         /**< Send next sequence */
    seq_t snd_up;          /**< Urgent pointer */
    seq_t snd_wl1;         /**< Segment Sequence number used for last window update */
    seq_t snd_wl2;         /**< segment acknowledgment number used for last window update */
    seq_t snd_iss;         /**< Initial Send Sequence number */
    seq_t snd_max;         /**< Max sequence seen */
    uint32_t snd_wnd;      /**< Send window */
    uint32_t snd_ssthresh; /**< Slow Start threshold (octets) */
    uint32_t snd_cwnd;     /**< Size of current send window */
    uint32_t max_sndwnd;   /**< Max Send window seen */

    /* Receive Segment information */
    seq_t rcv_wnd;      /**< Receive Window */
    seq_t rcv_nxt;      /**< Receive Next */
    seq_t rcv_irs;      /**< Initial Receive Sequence number */
    seq_t rcv_adv;      /**< Advertised window */
    int32_t rcv_bsize;  /**< Receive Buffer size */
    seq_t rcv_ssthresh; /**< Receive Slow Start threshold */
    uint16_t snd_urp;   /**< Send Urgent pointer */
    uint16_t rcv_urp;   /**< Receive Urgent pointer */

    /* Retransmission timeout values */
    seq_t rttseq;        /**< Round Trip Time Sequence number */
    seq_t total_retrans; /**< Total retransmits */
    int16_t rtt;         /**< RTT in milli-seconds */
    int16_t srtt;        /**< Smoothed Round Trip Time in microseconds */
    int16_t rttvar;      /**< Smoothed mean deviation estimator in ticks */
    int16_t dupacks;     /**< Received ACKs */
    int16_t rxtcur;      /**< Retransmission timeout */
    uint16_t rttmin;     /**< Minimum value for retransmission timeout */
    int16_t rxtshift;    /**< index into tcp_backoff[] array */
    uint16_t idle;       /**< TCP Idle counter */
};

/* tcb_entry.tflags values */
// clang-format off
enum {
    TCBF_PASSIVE_OPEN    = 0x10000000, /**< Passive open */
    TCBF_FORCE_TX        = 0x20000000, /**< Do an ACK now from persist */
    TCBF_DELAYED_ACK     = 0x40000000, /**< DELAYED ACK */
    TCBF_FREE_BIT_1      = 0x80000000,

    TCBF_RFC1122_URG     = 0x01000000, /**< RFC1122 Urgent */
    TCBF_BOUND           = 0x02000000, /**< TCB is Bound */
    TCBF_FREE_BIT_2      = 0x04000000,
    TCBF_FREE_BIT_3      = 0x08000000,

    TCBF_REQ_TSTAMP      = 0x00100000, /**< Requested Timestamp option */
    TCBF_RCVD_SCALE      = 0x00200000, /**< Window Scaling received */
    TCBF_REQ_SCALE       = 0x00400000, /**< Requested Window Scaling */
    TCBF_SEND_URG        = 0x00800000, /**< Send urgent data */

    TCBF_ACK_NOW         = 0x00010000, /**< ACK Now */
    TCBF_SENT_FIN        = 0x00020000, /**< FIN has been sent */
    TCBF_SACK_PERMIT     = 0x00040000, /**< SACK Permit is not supported, look at SEG_SACK_PERMIT */
    TCBF_RCVD_TSTAMP     = 0x00080000, /**< Received Timestamp in SYN */

    TCBF_NODELAY         = 0x00001000, /**< don't delay packets */
    TCBF_NAGLE_CREDIT    = 0x00002000, /**< Nagle credit flag */
    TCBF_OUR_FIN_ACKED   = 0x00004000, /**< Our FIN has been acked */
    TCBF_FREE_BIT_4      = 0x00008000,

    TCBF_FREE_BIT_5      = 0x00000100,
    TCBF_NEED_FAST_REXMT = 0x00000200, /**< Need a fast Retransmit */
    TCBF_NOPUSH          = 0x00000400, /**< no push */
    TCBF_NOOPT           = 0x00000800, /**< don't use TCP options */
};

#define TCB_FLAGS           \
    {                       \
        "Free_1",           \
        "DELAYED_ACK",      \
        "FORCE_TX",         \
        "PASSIVE_OPEN",     \
                            \
        "Free_3",           \
        "Free_2",           \
        "BOUND",            \
        "RFC1122_URG",      \
                            \
        "SEND_URG",         \
        "REQ_SCALE",        \
        "RCVD_SCALE",       \
        "REQ_TSTAMP",       \
                            \
        "RCVD_TSTAMP",      \
        "SACK_PERMIT",      \
        "SENT_FIN",         \
        "ACK_NOW",          \
                            \
        "Free_4",           \
        "OUR_FIN_ACKED",    \
        "NAGLE_CREDIT",     \
        "NO_DELAY",         \
                            \
        "NOOPT",            \
        "NOPUSH",           \
        "NeedFastRexmt",    \
        "Free_5",           \
        NULL                \
    }
// clang-format on

extern const char *tcb_in_states[];

struct chnl;

struct tcp_entry {
    TAILQ_ENTRY(tcb_entry) entry;
    uint32_t rcv_size;  /**< TCP Receive Size */
    uint32_t snd_size;  /**< TCP Send Size */
    uint32_t snd_ISS;   /**< TCP Send ISS value */
    int32_t keep_intvl; /**< TCP Keep Interval */
    int32_t keep_idle;  /**< TCP Keep Idle */
    int32_t keep_cnt;   /**< TCP Keep Count */
    int32_t max_idle;   /**< TCP Max Idle */
    uint16_t pad0;
    uint16_t default_MSS; /**< Default MSS value */
    int32_t default_RTT;  /**< Default Round Trip Time */
    struct pcb_hd tcp_hd; /**< PCB header information */
};

/**
 * TCP counters.
 */
typedef struct tcp_stats {
    uint64_t S_TCPS_CLOSED; /**< TCP State counters */
    uint64_t S_TCPS_LISTEN;
    uint64_t S_TCPS_SYN_SENT;
    uint64_t S_TCPS_SYN_RCVD;
    uint64_t S_TCPS_ESTABLISHED;
    uint64_t S_TCPS_CLOSE_WAIT;
    uint64_t S_TCPS_FIN_WAIT_1;
    uint64_t S_TCPS_CLOSING;
    uint64_t S_TCPS_LAST_ACK;
    uint64_t S_TCPS_FIN_WAIT_2;
    uint64_t S_TCPS_TIME_WAIT;

    uint64_t S_no_syn_rcvd;    /**< TCP No SYN Rcvd Count */
    uint64_t S_invalid_ack;    /**< TCP invalid Acknowledgement Count */
    uint64_t S_passive_open;   /**< TCP Passive Open Count */
    uint64_t S_tcp_rst;        /**< TCP connection reset Count */
    uint64_t S_ack_predicted;  /**< TCP ACK prediction Count */
    uint64_t S_data_predicted; /**< TCP Data prediction Count */
    uint64_t S_rx_total;       /**< TCP received count */
    uint64_t S_rx_short;       /**< TCP received short count */
    uint64_t S_rx_badoff;      /**< TCP received bad offset count */
    uint64_t S_delayed_ack;    /**< TCP delayed ACK count */
    uint64_t S_tcp_rexmit;     /**< TCP retransmission count */
    uint64_t S_resets_sent;    /**< TCP resets count */
    uint64_t S_tcp_connect;    /**< TCP connections count */
} tcp_stats_t;

#define INC_TCP_STAT(x)               \
    do {                              \
        this_stk->tcp_stats->S_##x++; \
    } while (/*CONSTCOND*/ 0)

static inline void
tcp_send_seq_set(struct tcb_entry *tcb, int x)
{
    struct tcp_entry *tcp = tcb->tcp;

    tcb->snd_iss = tcp->snd_ISS;
    tcp->snd_ISS += (TCP_ISSINCR / x);
    tcb->snd_una = tcb->snd_nxt = tcb->snd_max = tcb->snd_iss;
}

static inline uint16_t
tcp_range_set(int val, int tvmin, int tvmax)
{
    return (uint16_t)((val < tvmin) ? tvmin : (val > tvmax) ? tvmax : val);
}

static inline void
tcb_kill_timers(struct tcb_entry *tcb)
{
    uint64_t *p = (uint64_t *)(uintptr_t)tcb->timers;

    p[0] = 0;
}

/**
 * Allocate a new TCB control block from the free list of TCB structures.
 */
static inline struct tcb_entry *
tcb_alloc(void)
{
    struct tcb_entry *tcb = NULL;
    stk_t *stk            = this_stk;

    if (mempool_get(stk->tcb_objs, (void *)&tcb) < 0)
        return NULL;

    if (stk_lock()) {
        int idx = mempool_obj_index(stk->tcb_objs, tcb);

        if (idx < 0) {
            mempool_put(stk->tcb_objs, (void *)tcb);
            stk_unlock();
            CNE_NULL_RET("TCB pointer is invalid\n");
        }
        bit_set(stk->tcbs, idx);
        stk_unlock();
    }

    return tcb;
}

static inline void
tcb_free(struct tcb_entry *tcb)
{
    stk_t *stk = this_stk;

    if (tcb) {
        if (stk_lock()) {
            int idx = mempool_obj_index(stk->tcb_objs, tcb);

            if (idx < 0) {
                CNE_ERR("invalid TCB pointer\n");
                return;
            }
            bit_clear(stk->tcbs, idx);
            memset(tcb, 0, sizeof(struct tcb_entry));
            stk_unlock();
        }

        mempool_put(stk->tcb_objs, tcb);
    }
}

static inline void
tcp_flags_dump(const char *msg, uint8_t flags)
{
    const char *flag_names[] = TCP_FLAGS;

    if (msg)
        cne_printf("[magenta]%s[]: ", msg);
    for (int i = 0; i < cne_countof(flag_names); i++) {
        if (flags & (1 << i))
            cne_printf("[orange]%s[] ", flag_names[i]);
    }
    cne_printf("\n");
}

#if CNET_TCP_DUMP_ENABLED
#define TCP_DUMP(tcp)                                                                 \
    do {                                                                              \
        cne_printf("[cyan]([orange]%s[cyan]:[orange]%d[cyan]) ", __func__, __LINE__); \
        cnet_tcp_dump(NULL, tcp);                                                     \
    } while (0)
#else
#define TCP_DUMP(tcp) \
    do {              \
    } while (0)
#endif

/**
 * The TCP input routine
 *
 * @param pcb
 *   The PCB pointer for this connection
 * @param mbuf
 *   The mbuf to process in TCP input
 * @return
 *   0 on success or -1 on error.
 */
CNDP_API int cnet_tcp_input(struct pcb_entry *pcb, pktmbuf_t *mbuf);

/**
 * The TCP output routine.
 *
 * @param tcb
 *   The TCB to process output packets from.
 */
CNDP_API void cnet_tcp_output(struct tcb_entry *tcb);

/**
 * The TCP connect function gives the PCB to use for the connection
 *
 * @param pcb
 *   The PCB pointer in which to do the connection request.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cnet_tcp_connect(struct pcb_entry *pcb);

/**
 * Create a new TCB for the given PCB pointer.
 *
 * @param pcb
 *   The PCB to create the TCB from.
 * @return
 *   TCB pointer or NULL on failure.
 */
CNDP_API struct tcb_entry *cnet_tcb_new(struct pcb_entry *pcb);

/**
 * Abort the TCP connection
 *
 * @param pcb
 *   The PCB pointer in which to start the abort sequence.
 */
CNDP_API void cnet_tcp_abort(struct pcb_entry *pcb);

/**
 * Close the TCP connection for the given PCB
 *
 * @param pcb
 *   The PCB in which to start the connect close sequence
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_tcp_close(struct pcb_entry *pcb);

/**
 * Remove an entry from the queue
 * @internal
 *
 * @param tq
 *   The tcp_q structure pointer
 * @return
 *   NULL on error or pointer removed.
 */
void *tcp_q_pop(struct tcp_q *tq);

/**
 * Dump out the TCP header and information
 *
 * @param msg
 *   A caller supplied message or NULL if none
 * @param tcp
 *   The TCP header to dump
 */
CNDP_API void cnet_tcp_dump(const char *msg, struct cne_tcp_hdr *tcp);

/**
 * List out all of the active TCB structures
 *
 * @param stk
 *   The stack instance to dump the TCB from
 * @param tcb
 *   The TCB structure to dump or NULL for all TCB structures.
 */
CNDP_API void cnet_tcb_list(stk_t *stk, struct tcb_entry *tcb);

/**
 * Dump out all TCBs in all stack instances.
 */
CNDP_API void cnet_tcb_dump(void);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_TCP_H */
