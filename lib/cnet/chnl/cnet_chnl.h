/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_CHNL_H
#define __CNET_CHNL_H

/**
 * @file
 * CNET Channel routines and constants.
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

#include <cne_spinlock.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHNL_VEC_SIZE 32
#define _MIN_BUF_SIZE (3 * TCP_NORMAL_MSS) /* 1460 Normal MSS size for TCP */

#ifdef _IPPORT_RESERVED
#undef _IPPORT_RESERVED
#endif
#define _IPPORT_RESERVED 49152 /* Starting Ephemeral Port value */

typedef int (*chnl_cb_t)(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs);

struct pcb_entry;

/* TODO: Trying to remove this structure as it may not be needed. TCP uses it now */
struct chnl_buf {
    pktmbuf_t **cb_vec;
    uint32_t cb_acc;        /**< (notused) Available space in buffer */
    uint32_t cb_cc;         /**< actual chars in buffer */
    uint32_t cb_hiwat;      /**< max actual char count */
    uint32_t cb_lowat;      /**< low water mark */
    uint32_t cb_size;       /**< protocol send/receive size */
    uint16_t cb_flags;      /**< flags, see below */
    uint16_t cb_selCount;   /**< # tasks selecting on this cb */
    uint64_t cb_timeo;      /**< timeout for read/write */
    pthread_mutex_t mutex;  /**< Mutex for buffer */
    pthread_cond_t cb_cond; /**< Condition variable pointer */
};

/* chnl_buf.cb_flags bits */
#define CB_LOCK   0x0001 /* lock on data queue */
#define CB_WANT   0x0002 /* someone is waiting to lock */
#define CB_WAIT   0x0004 /* someone is waiting for data/space */
#define CB_SEL    0x0008 /* someone is selecting */
#define CB_ASYNC  0x0010 /* ASYNC I/O, need signals */
#define CB_UPCALL 0x0020 /* someone wants an upcall */
#define CB_NOINTR 0x0040 /* operations not interruptible */
#define CB_AIO    0x0080 /* AIO operations queued */
#define CB_KNOTE  0x0100 /* kernel note attached */

struct pcb_hd;

struct chnl {
    TAILQ_ENTRY(chnl) ch_entry;
    struct pcb_entry *ch_pcb;       /**< Pointer to the PCB */
    struct protosw_entry *ch_proto; /**< Current proto value */
    pthread_mutex_t ch_mutex;       /**< Channel mutex */
    struct chnl *ch_ch;             /**< Sister local channel */
    chnl_cb_t callback;             /**< Callback routine */
    struct cne_node *ch_node;       /**< Next Node pointer */
    uint64_t callback_cnt;          /** Number of callback calls */
    uint16_t ch_idx;                /**< Network index value */
    uint16_t ch_options;            /**< Options for channel */
    uint16_t ch_linger;             /**< Linger value */
    uint16_t ch_state;              /**< Current state of channel */
    uint16_t initialized;           /**< Set to 1 when channel is initialized */
    uint16_t ch_error;              /**< Error value */

    struct chnl_buf ch_rcv; /**< Receive buffer */
    struct chnl_buf ch_snd; /**< Transmit buffer */
};

/* Used for the chnl.ch_state */
enum {
    _NOFDREF         = 0x0001, /**< no file table ref any more */
    _ISCONNECTED     = 0x0002, /**< channel connected to a peer */
    _ISCONNECTING    = 0x0004, /**< in process of connecting to peer */
    _ISDISCONNECTING = 0x0008, /**< in process of disconnecting */
    _CANTSENDMORE    = 0x0010, /**< can't send more data to peer */
    _CANTRECVMORE    = 0x0020, /**< can't receive more data from peer */
    _RCVATMARK       = 0x0040, /**< at mark on input */
    _PRIV            = 0x0080, /**< privileged for broadcast, raw... */
    _NBIO            = 0x0100, /**< non-blocking ops */
    _ASYNC           = 0x0200, /**< async i/o notify */
    _ISCONFIRMING    = 0x0400, /**< deciding to accept connection req */
    _INCOMP          = 0x0800, /**< unaccepted, incomplete connection */
    _ISDISCONNECTED  = 0x1000, /**< channel disconnected from peer */
    _CHNL_FREE       = 0x8000  /**< Free Channel flag */
};

static inline char *
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

static inline char *
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

static inline char *
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

#define SO_CHANNEL    1
#define SO_UDP_CHKSUM 1024
#define IP_DONTFRAG   1025

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

/*
 * ioctl extensions
 */
enum {
    SHUT_BIT_RD   = 0x01,
    SHUT_BIT_WR   = 0x02,
    SHUT_BIT_RDWR = 0x03,
};

/**
 * Channel buffer wait routine used to wait for data.
 *
 * @param ch
 *   Pointer to the channel to wait for data.
 * @param cb
 *   The channel buffer structure pointer.
 * @return
 *   0 on success or -1 on error.
 */
CNDP_API int chnl_cb_wait(struct chnl *ch, struct chnl_buf *cb);

/**
 * Wakeup a waiting channel to indicate data has arrived.
 *
 * @param ch
 *   Pointer to the channel to wait for data.
 * @param cb
 *   The channel buffer structure pointer.
 * @param wakeup_type
 *   Wakeup for reading or writing.
 */
CNDP_API void chnl_cb_wakeup(struct chnl *ch, struct chnl_buf *cb, int wakeup_type);

/**
 * Short hand macros for read or write wakeup calls.
 */
#define ch_rwakeup(_c) chnl_cb_wakeup((_c), &(_c)->ch_rcv, _SELREAD)
#define ch_wwakeup(_c) chnl_cb_wakeup((_c), &(_c)->ch_snd, _SELWRITE)

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
 * Check if the channel can send data. Call channel wakeup for read or write if valid.
 *
 * @param ch
 *   Pointer to the channel to determine if data can be sent.
 * @param which
 *   The flag(s) to test and return true or false if found. Could be a number of flags and they must
 *   all be set to return true.
 */
static inline void
chnl_cant_snd_rcv_more(struct chnl *ch, int32_t which)
{
    ch->ch_state |= (which & (_CANTSENDMORE | _CANTRECVMORE));

    if (is_set(which, _CANTRECVMORE))
        ch_rwakeup(ch);

    if (is_set(which, _CANTSENDMORE))
        ch_wwakeup(ch);
}

/**
 * Check if a channel has more data to receive.
 *
 * @param ch
 *   Pointer to the channel to determine if data can be sent.
 * @return
 *   true if more data is available, false otherwise.
 */
static inline int
chnl_cant_rcv_more(struct chnl *ch)
{
    return ch->ch_state & _CANTRECVMORE;
}

/**
 * Check if a channel can send more data.
 *
 * @param ch
 *   Pointer to the channel to determine if data can be sent.
 * @return
 *   true if able to send more data, false otherwise.
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
    return (uint32_t)((cb->cb_hiwat > cb->cb_cc) ? (cb->cb_hiwat - cb->cb_cc) : 0);
}

/**
 * Check to see if channel is readable.
 *
 * @param ch
 *   Chnl structure pointer.
 * @return
 *   Number of bytes in the channel buffer which are available.
 */
static inline int
ch_readable(struct chnl *ch)
{
    int ret;

    if (!ch) {
        CNE_ERR("Channel is NULL\n");
        return 0;
    }

    ret =
        (cb_avail(&ch->ch_rcv) >= ch->ch_rcv.cb_lowat) && !chnl_cant_rcv_more(ch) && !ch->ch_error;

    return ret;
}

/**
 * Check to see if channel is writeable.
 *
 * @param ch
 *   Chnl structure pointer.
 * @return
 *   Number of bytes in the channel buffer which are writable.
 */
static inline int
ch_writeable(struct chnl *ch)
{
    int ret;

    if (!ch) {
        CNE_ERR("Channal is NULL\n");
        return 0;
    }

    ret = (cb_space(&ch->ch_snd) >= ch->ch_snd.cb_lowat &&
           ((ch->ch_state & _ISCONNECTED) || (ch->ch_proto->proto != SOCK_STREAM))) ||
          !chnl_cant_snd_more(ch) || !ch->ch_error;

    return ret;
}

/**
 * @brief This is a protocol back-end routine for operations that don't need to do
 * any further work.
 *
 * @param ch
 *   Chnl structure pointer.
 * @return
 *   0 on success
 */
CNDP_API int chnl_OK(struct chnl *ch);

/**
 * @brief This is a protocol back-end routine for operations that don't need to do
 * any further work and need to report an error.
 *
 * @param ch
 *   Chnl structure pointer.
 * @return
 *   -1 on error
 */
CNDP_API int chnl_ERROR(struct chnl *ch);

/**
 * @brief This is a protocol back-end routine for operations that don't need to do
 * any further work and need to report a NULL.
 *
 * @param ch
 *   Chnl structure pointer.
 * @return
 *   NULL on return
 */
CNDP_API struct chnl *chnl_NULL(struct chnl *ch);

/**
 * @brief Clean up a channel structure
 *
 * @param ch
 *   The channel structure pointer to cleanup.
 * @return
 *   N/A
 */
CNDP_API void chnl_cleanup(struct chnl *ch);

/**
 * @internal
 * @brief Helper routine to create a channel structure.
 *
 * @param dom
 *   The protocol domain value
 * @param type
 *   The protocol type value
 * @param pro
 *   The proto type value
 * @param pcb
 *   The PCB structure pointer to update.
 * @return
 *   NULL on error or pointer to channel structure.
 */
CNDP_API struct chnl *__chnl_create(int32_t dom, int32_t type, int32_t pro, struct pcb_entry *pcb);

/**
 * @brief Dump out the channel structure list.
 *
 * @param stk
 *   The stack instance pointer to be used for the dump.
 * @return
 *   N/A
 */
CNDP_API void chnl_list(stk_t *stk);

/**
 * @brief Validate the chnl_buf structure and print a message if invalid
 *
 * @param msg
 *   Caller message to be added to the output if invalid.
 * @param cb
 *   The chnl_buf structure pointer to validate.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_validate_cb(const char *msg, struct chnl_buf *cb);

/* Common bind and connect routines for all protocols */
/**
 * @brief Common channel connect routine used by protocols.
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
CNDP_API int chnl_connect_common(struct chnl *ch, struct in_caddr *to, int32_t tolen);

/**
 * @brief Common channel connect2 routine used by protocols.
 *
 * @param ch1
 *   The channel structure pointer
 * @param ch2
 *   The channel structure pointer
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_connect2_common(struct chnl *ch1, struct chnl *ch2);

/**
 * @brief Channel Bind common routine used by protocols
 *
 * @param ch
 *   The channel structure pointer to bind too
 * @param pAddr
 *   The IP address to bind
 * @param len
 *   The length of the IP address to bind
 * @param pHd
 *   The head of the PCB list to add the channel
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_bind_common(struct chnl *ch, struct in_caddr *pAddr, int32_t len,
                              struct pcb_hd *pHd);

/* Standard chnl routines for user level API. */
/**
 * @brief The routine to create a channel structure similar to 'socket()'
 *
 * @param domain
 *   The domain ID value
 * @param type
 *   The protocol type value
 * @param proto
 *   The proto value
 * @param cb
 *   The callback routine to call when data is received.
 * @return
 *   NULL on error or a chnl structure pointer.
 */
CNDP_API struct chnl *channel(int domain, int type, int proto, chnl_cb_t cb);

/**
 * @brief Bind an address to a channel similar to 'bind()'
 *
 * @param ch
 *   The channel structure pointer
 * @param addr
 *   The IP address to bind to the channel.
 * @param addrlen
 *   The IP address length in bytes
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_bind(struct chnl *ch, struct sockaddr *addr, int addrlen);

/**
 * @brief Listen on a channel similar to 'listen()'
 *
 * @param ch
 *   The channel structure pointer
 * @param backlog
 *   The number of backlog connections allowed (not fully used)
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_listen(struct chnl *ch, int backlog);

/**
 * @brief Accept on a channel similar to 'accept()'
 *
 * @param ch
 *   The channel structure pointer
 * @param sa
 *   The sockaddr to fill in when accepting a connection.
 * @param addrlen
 *   The length of the new accepted connection
 * @return
 *   NULL on error or pointer to channel structure
 */
CNDP_API struct chnl *chnl_accept(struct chnl *ch, struct sockaddr *sa, socklen_t *addrlen);

/**
 * @brief Connect to a channel, similar to 'connect()'
 *
 * @param ch
 *   The channel structure pointer
 * @param sa
 *   The sockaddr to fill in when accepting a connection.
 * @param addrlen
 *   The length of the new accepted connection
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_connect(struct chnl *ch, struct sockaddr *sa, int addrlen);

/**
 * @brief Connect to a channel, similar to 'connect2()'
 *
 * @param ch1
 *   The channel structure pointer
 * @param ch2
 *   The channel structure pointer
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_connect2(struct chnl *ch1, struct chnl *ch2);

/**
 * @brief Copy data from one mbuf to another
 *
 * @param to
 *   Array of mbuf pointers to use in the copy as the destination
 * @param from
 *   Array of mbuf pointers to use in the copy as the source
 * @param len
 *   Number of bytes to copy
 * @return
 *   -1 on error or Number of bytes copied.
 */
CNDP_API size_t chnl_copy_data(pktmbuf_t **to, pktmbuf_t **from, int len);

/**
 * @brief Send data to a channel similar to 'send()'
 *
 * @param ch
 *   The channel structure pointer
 * @param mbufs
 *   The mbuf array to send multiple data buffers
 * @param nb_mbufs
 *   Number of mbufs in the mbufs array
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_send(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs);

/**
 * @brief Send data to a channel similar to 'sendto()'
 *
 * @param ch
 *   The channel structure pointer
 * @param sa
 *   The sockaddr to fill in when accepting a connection.
 * @param mbufs
 *   The mbuf array to send multiple data buffers
 * @param nb_mbufs
 *   Number of mbufs in the mbufs array
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_sendto(struct chnl *ch, struct sockaddr *sa, pktmbuf_t **mbufs,
                         uint16_t nb_mbufs);

/**
 * @brief file control function similar to 'fcntl()'
 *
 * @param ch
 *   The channel structure pointer
 * @param cmd
 *   The command to be executed
 * @param ...
 *   The variable list arguments to be to the command.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_fcntl(struct chnl *ch, int cmd, ...);

/**
 * @brief Get channel name or address of channel similar to 'getsockname()'
 *
 * @param ch
 *   The channel structure pointer
 * @param name
 *   The address of the channel
 * @param namelen
 *   The length of the address
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_getchnlname(struct chnl *ch, struct sockaddr *name, socklen_t *namelen);

/**
 * @brief Get channel peer address of channel similar to 'getpeername()'
 *
 * @param ch
 *   The channel structure pointer
 * @param name
 *   The address of the channel
 * @param namelen
 *   The length of the address
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_getpeername(struct chnl *ch, struct sockaddr *name, socklen_t *namelen);

/**
 * @brief Shutdown a channel connection similar to 'shutdown()'
 *
 * @param ch
 *   The channel structure pointer
 * @param how
 *   How to shutdown the connection
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_shutdown(struct chnl *ch, int how);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_CHNL_H */
