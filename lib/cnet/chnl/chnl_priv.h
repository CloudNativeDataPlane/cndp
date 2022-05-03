/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CHNL_PRIV_H
#define __CHNL_PRIV_H

/**
 * @file
 * CNET Channel private routines and constants.
 */

#include <stdio.h>             // for snprintf, size_t, NULL
#include <sys/socket.h>        // for socklen_t, PF_INET, PF_INET6, PF_LOCAL
#include <sys/queue.h>         // for TAILQ_ENTRY
#include <netinet/in.h>        // for IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IGMP
#include <bsd/bitstring.h>
#include <pktmbuf.h>
#include <cnet_const.h>        // for _SELREAD, is_set, _SELWRITE
#include <cne_vec.h>
#include <cnet_protosw.h>        // for protosw_entry
#include <cne_graph_worker.h>
#include <pthread.h>          // for pthread_mutex_t, pthread_cond_t
#include <stdint.h>           // for uint16_t, int32_t, uint32_t, uintptr_t
#include <sys/types.h>        // for ssize_t

#include "cne_log.h"         // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_ERR
#include "cnet_tcp.h"        // for TCP_NORMAL_MSS
#include "cnet_udp.h"        // for _IPPORT_RESERVED

struct in_caddr;
struct netif;
struct stk_s;

#ifdef __cplusplus
extern "C" {
#endif

#define CHNL_VEC_SIZE 32                   /**< Number of initial Vectors to support for channel */
#define _MIN_BUF_SIZE (3 * TCP_NORMAL_MSS) /**< 1460 Normal MSS size for TCP */

#ifndef __CNET_CHNL_H
/**
 * Callback function for a channel to accept or receive packets
 *
 * @param ctype
 *   The type of channel callback defined by chnl_type_t enum.
 * @param cd
 *   The channel descriptor value
 * @return
 *   0 on success or -1 on error.
 */
typedef int (*chnl_cb_t)(int chnl_type, int cd);
#endif

/**
 * Channel buffer structure for send and receive packets. The structure
 * manages the amount of data sent and received to/from a channel.
 *
 */
struct chnl_buf {
    pktmbuf_t **cb_vec; /**< Vector of mbuf pointers */
    uint32_t cb_cc;     /**< actual chars in buffer */
    uint32_t cb_hiwat;  /**< high water mark */
    uint32_t cb_lowat;  /**< low water mark */
    uint32_t cb_size;   /**< protocol send/receive size */
};

struct chnl {
    uint16_t stk_id;                /**< Stack instance ID value */
    uint16_t ch_options;            /**< Options for channel */
    uint16_t ch_state;              /**< Current state of channel */
    uint16_t ch_error;              /**< Error value */
    int ch_cd;                      /**< Channel descriptor index value */
    pthread_mutex_t ch_mutex;       /**< Mutex for buffer */
    struct pcb_entry *ch_pcb;       /**< Pointer to the PCB */
    struct protosw_entry *ch_proto; /**< Current proto value */
    chnl_cb_t ch_callback;          /**< Channel callback routine */
    struct cne_node *ch_node;       /**< Next Node pointer */
    struct chnl_buf ch_rcv;         /**< Receive buffer */
    struct chnl_buf ch_snd;         /**< Transmit buffer */
};

/* Used for the chnl.ch_state, bits 0-3 are Channel state value */
enum {
    _NOSTATE         = 0,      /**< When state is not defined */
    _ISCONNECTED     = 1,      /**< channel connected to a peer */
    _ISCONNECTING    = 2,      /**< in process of connecting to peer */
    _ISDISCONNECTING = 3,      /**< in process of disconnecting */
    _ISDISCONNECTED  = 4,      /**< channel disconnected from peer */
    _CHNL_FREE       = 15,     /**< Free Channel */
    _CANTSENDMORE    = 0x0010, /**< can't send more data to peer */
    _CANTRECVMORE    = 0x0020, /**< can't receive more data from peer */
    _NBIO            = 0x0040  /**< non-blocking ops */
};

#define _STATE_MASK 0x000f /**< Channel state mask */

/**
 * Return the current channel state value
 *
 * @param ch
 *   The channel stucture pointer
 * @return
 *   Channel state or _NOSTATE is returned for invalid channel
 */
static inline int
chnl_state(struct chnl *ch)
{
    if (ch) {
        int ret = (int)(ch->ch_state & _STATE_MASK);

        if (ret <= _ISDISCONNECTED)
            return ret;
    }
    return _NOSTATE;
}

/**
 * Set the channel state to the give value.
 *
 * @param ch
 *   The chnl pointer to set the state
 * @param state
 *   0 on success or -1 on error
 * @return int
 */
static inline int
chnl_state_set(struct chnl *ch, int state)
{
    if (ch) {
        ch->ch_state &= ~_STATE_MASK;
        ch->ch_state |= state;
        return 0;
    }
    return -1;
}

/**
 * Test to see what state a channel is currently.
 *
 * @param ch
 *   The chnl pointer to test
 * @param state
 *   The state to test against
 * @return int
 */
static inline int
chnl_state_tst(struct chnl *ch, int state)
{
    if (ch)
        return chnl_state(ch) == state;
    return 0;
}

static inline const char *
chnl_domain_str(int domain)
{
    const char *p = NULL;
    static char buff[16];

    switch (domain) {
    case AF_LOCAL:
        p = "LOCAL";
        break;
    case AF_INET:
        p = "INET";
        break;
    case AF_INET6:
        p = "INET6";
        break;
    case AF_NETLINK:
        p = "NETLINK";
        break;
    case AF_PACKET:
        p = "PACKET";
        break;
    default:
        p = buff;
        snprintf(buff, sizeof(buff) - 1, "%d", domain);
        break;
    }
    return (char *)(uintptr_t)p;
}

#define SOCK_ANY 0

static inline const char *
chnl_type_str(int type)
{
    const char *p = NULL;
    static char buff[16];

    switch (type) {
    case SOCK_ANY:
        p = "ANY";
        break;
    case SOCK_STREAM:
        p = "STREAM";
        break;
    case SOCK_DGRAM:
        p = "DGRAM";
        break;
    case SOCK_RAW:
        p = "RAW";
        break;
    case SOCK_SEQPACKET:
        p = "SEQPKT";
        break;
    case SOCK_PACKET:
        p = "PACKET";
        break;
    default:
        p = buff;
        snprintf(buff, sizeof(buff) - 1, "%d", type);
        break;
    }
    return (char *)(uintptr_t)p;
}

static inline const char *
chnl_protocol_str(int protocol)
{
    const char *p = NULL;
    static char buff[16];

    switch (protocol) {
    case IPPROTO_IP:
        p = "IP";
        break;
    case IPPROTO_ICMP:
        p = "ICMP";
        break;
    case IPPROTO_IGMP:
        p = "IGMP";
        break;
    case IPPROTO_TCP:
        p = "TCP";
        break;
    case IPPROTO_UDP:
        p = "UDP";
        break;
    case IPPROTO_IPV6:
        p = "IPV6";
        break;
    case IPPROTO_SCTP:
        p = "SCTP";
        break;
    case IPPROTO_MPLS:
        p = "MPLS";
        break;
    case IPPROTO_RAW:
        p = "RAW";
        break;
    case IPPROTO_ICMPV6:
        p = "ICMPV6";
        break;
    default:
        p = buff;
        snprintf(buff, sizeof(buff) - 1, "%d", protocol);
        break;
    }
    return (char *)(uintptr_t)p;
}

/**< Bit flags for various IPPROTO_IP Channel options */
enum {
    IP_HDRINCL_FLAG     = 0x0001,
    IP_RECVDSTADDR_FLAG = 0x0002,
    IP_PKTINFO_FLAG     = 0x0004,
    IP_RECVIF_FLAG      = 0x0008,
    IP_DONTFRAG_FLAG    = 0x0010,
    IP_RECVTTL_FLAG     = 0x0020,
    IP_RECVTOS_FLAG     = 0x0040,
    UDP_CHKSUM_FLAG     = 0x0080,
    TCP_NODELAY_FLAG    = 0x0200, /* A few TCP flags */
    TCP_NOOPT_FLAG      = 0x0400,
    TCP_NOPUSH_FLAG     = 0x0800,
    TCP_MAXSEG_FLAG     = 0x1000,
};

/**
 * Check if the channel can receive data.
 *
 * @param ch
 *   Pointer to the channel to wait for data.
 * @param which
 *   The flag(s) to test and return true or false if found. Could be a number of flags and they must
 *   all be set to return true.
 * @return
 *   true if flags are set or false if not.
 */
static inline int
chnl_snd_rcv_more(struct chnl *ch, int which)
{
    return (ch->ch_state & which) == which;
}

/**
 * Set the channel flags to be able to not send/receive data.
 *
 * @param ch
 *   Pointer to the channel to determine if data can be sent.
 * @param which
 *   The flag to set can't send/receive more data. The which value can
 *   only have two values _CANTSENDMORE and/or _CANTRECVMORE.
 */
static inline void
chnl_cant_snd_rcv_more(struct chnl *ch, int32_t which)
{
    ch->ch_state |= (which & (_CANTSENDMORE | _CANTRECVMORE));
}

/**
 * Check if a channel can't receive more data.
 *
 * @param ch
 *   Pointer to the channel to determine if data can be sent.
 * @return
 *   true if channel can't receive more data, false otherwise.
 */
static inline int
chnl_cant_rcv_more(struct chnl *ch)
{
    return ch->ch_state & _CANTRECVMORE;
}

/**
 * Check if a channel can't send more data.
 *
 * @param ch
 *   Pointer to the channel to determine if data can be sent.
 * @return
 *   true if unable to send more data, false otherwise.
 */
static inline int
chnl_cant_snd_more(struct chnl *ch)
{
    return ch->ch_state & _CANTSENDMORE;
}

/**
 * Check to see how much data is available in the channel buffer.
 *
 * @param cb
 *   The channel buffer structure pointer.
 * @return
 *   Number of bytes in the channel buffer.
 */
static inline uint32_t
cb_avail(struct chnl_buf *cb)
{
    return cb->cb_cc;
}

/**
 * Check to see how much free space is available in the channel buffer.
 *
 * @param cb
 *   The channel buffer structure pointer.
 * @return
 *   Number of bytes in the channel buffer which are available.
 */
static inline uint32_t
cb_space(struct chnl_buf *cb)
{
    return (uint32_t)((cb->cb_hiwat > cb->cb_cc) ? (cb->cb_hiwat - cb_avail(cb)) : 0);
}

/**
 * Get and return the struct chnl structure pointer
 *
 * @param cd
 *   The channel descriptor index value
 * @return
 *   struct chnl structure pointer or NULL on error.
 */
static inline struct chnl *
ch_get(int cd)
{
    struct cnet *cnet = this_cnet;

    if (cnet && cd >= 0 && cd < (int)cnet->num_chnls)
        return (struct chnl *)cnet->chnl_descriptors[cd];

    return NULL;
}

/**
 * This is a protocol back-end routine for operations that don't need to do
 * any further work.
 *
 * @param ch
 *   Chnl structure pointer as this an internal function.
 * @return
 *   0 on success
 */
int chnl_OK(struct chnl *ch);

/**
 * Clean up a channel structure
 *
 * @param ch
 *   The channel structure pointer to cleanup.
 * @return
 *   N/A
 */
void chnl_cleanup(struct chnl *ch);

/**
 * Helper routine to create a channel structure.
 *
 * @param dom
 *   The protocol domain value
 * @param type
 *   The protocol type value
 * @param pro
 *   The proto type value
 * @param pcb
 *   The parent PCB pointer, can be NULL.
 * @return
 *   NULL on error or pointer to channel structure.
 */
struct chnl *__chnl_create(int32_t dom, int32_t type, int32_t pro, struct pcb_entry *pcb);

/**
 * Validate the chnl_buf structure and print a message if invalid
 *
 * @param msg
 *   Caller message to be added to the output if invalid.
 * @param cb
 *   The chnl_buf structure pointer to validate.
 * @return
 *   -1 on error or 0 on success
 */
int chnl_validate_cb(const char *msg, struct chnl_buf *cb);

/**
 * Dump out the channel structure list.
 *
 * @param stk
 *   The stack instance pointer to be used for the dump.
 * @return
 *   N/A
 */
void chnl_list(stk_t *stk);

/**
 * Common channel connect routine used by protocols.
 *
 * @param ch
 *   The channel structure pointer
 * @param to
 *   The IP address of the 'to' or foreign address.
 * @param tolen
 *   The length of the 'to' address.
 * @return
 *   -1 on error or 0 on success
 */
int chnl_connect_common(struct chnl *ch, struct in_caddr *to, int32_t tolen);

/**
 * Channel Bind common routine used by protocols
 *
 * @param ch
 *   The channel structure pointer
 * @param addr
 *   The IP address to bind
 * @param len
 *   The length of the IP address to bind
 * @param hd
 *   The head of the PCB list to add the channel
 * @return
 *   -1 on error or 0 on success
 */
int chnl_bind_common(struct chnl *ch, struct in_caddr *addr, int32_t len, struct pcb_hd *hd);

#ifdef __cplusplus
}
#endif

#endif /* __CHNL_PRIV_H */
