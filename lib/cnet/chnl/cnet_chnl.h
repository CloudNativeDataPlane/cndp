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

#define CHNL_VEC_SIZE 32                   /**< Number of initial Vectors to support for channel */
#define _MIN_BUF_SIZE (3 * TCP_NORMAL_MSS) /**< 1460 Normal MSS size for TCP */

#define CHNL_ENABLE_UDP_CHECKSUM (1 << 0) /**< Enable UDP checksum */

#ifdef _IPPORT_RESERVED
#undef _IPPORT_RESERVED
#endif
#define _IPPORT_RESERVED 49152 /* Starting Ephemeral Port value */

typedef enum {
    CHNL_UDP_RECV_TYPE,   /**< Callback for receiving UDP packets */
    CHNL_UDP_CLOSE_TYPE,  /**< Callback for UDP close */
    CHNL_TCP_ACCEPT_TYPE, /**< Callback type for accepting TCP connection */
    CHNL_TCP_RECV_TYPE,   /**< Callback for receiving TCP packets */
    CHNL_TCP_CLOSE_TYPE,  /**< Callback for TCP close */
    CHNL_CALLBACK_TYPES   /**< Maximum number of callback types */
} chnl_type_t;

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
typedef int (*chnl_cb_t)(chnl_type_t chnl_type, int cd);

/**
 * Channel buffer structure for send and receive packets. The structure
 * manages the amount of data sent and received to/from a channel.
 *
 */
struct chnl_buf {
    pktmbuf_t **cb_vec;    /**< Vector of mbuf pointers */
    uint32_t cb_cc;        /**< actual chars in buffer */
    uint32_t cb_hiwat;     /**< high water mark */
    uint32_t cb_lowat;     /**< low water mark */
    uint32_t cb_size;      /**< protocol send/receive size */
    pthread_mutex_t mutex; /**< Mutex for buffer */
};

struct chnl {
    uint16_t stk_id;                /**< Stack instance ID value */
    uint16_t ch_options;            /**< Options for channel */
    uint16_t ch_state;              /**< Current state of channel */
    uint16_t ch_error;              /**< Error value */
    int ch_cd;                      /**< Channel descriptor index value */
    struct pcb_entry *ch_pcb;       /**< Pointer to the PCB */
    struct protosw_entry *ch_proto; /**< Current proto value */
    pthread_mutex_t ch_mutex;       /**< Channel mutex */
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

/**
 * Lock the channel structure.
 *
 * @param ch
 *   Pointer to structure chnl to lock.
 * @return
 *   1 on success or 0 on failure to lock.
 */
static inline int
chnl_lock(struct chnl *ch)
{
    if (ch && pthread_mutex_lock(&ch->ch_mutex) == 0)
        return 1;
    CNE_ERR_RET_VAL(0, "unable to lock channel %d\n", (ch) ? ch->ch_cd : -1);
}

/**
 * Unlock the chnl structure.
 *
 * @param ch
 *   Pointer to structure chnl to unlock.
 */
static inline void
chnl_unlock(struct chnl *ch)
{
    if (ch && pthread_mutex_unlock(&ch->ch_mutex) == 0)
        return;
    CNE_RET("unable to unlock channel %d\n", (ch) ? ch->ch_cd : -1);
}

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
 * @brief This is a protocol back-end routine for operations that don't need to do
 * any further work.
 *
 * @param cd
 *   Chnl descriptor value.
 * @return
 *   0 on success
 */
CNDP_API int chnl_OK(int cd);

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
 *   The parent PCB pointer, can be NULL.
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
 * @brief Dump out a channel structure
 *
 * @param msg
 *   A message to print if present, can be NULL
 * @param ch
 *   The chnl structure to dump out.
 */
CNDP_API void chnl_dump(const char *msg, struct chnl *ch);

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
 * @param cd
 *   The channel descriptor value
 * @param to
 *   The IP address of the 'to' or foreign address.
 * @param tolen
 *   The length of the 'to' address.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_connect_common(int cd, struct in_caddr *to, int32_t tolen);

/**
 * @brief Channel Bind common routine used by protocols
 *
 * @param cd
 *   The channel descriptor value
 * @param pAddr
 *   The IP address to bind
 * @param len
 *   The length of the IP address to bind
 * @param pHd
 *   The head of the PCB list to add the channel
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_bind_common(int cd, struct in_caddr *pAddr, int32_t len, struct pcb_hd *pHd);

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
 *   -1 on error or >= 0 on success
 */
CNDP_API int channel(int domain, int type, int proto, chnl_cb_t cb);

/**
 * @brief Bind an address to a channel similar to 'bind()'
 *
 * @param cd
 *   The channel descriptor index
 * @param addr
 *   The IP address to bind to the channel.
 * @param addrlen
 *   The IP address length in bytes
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_bind(int cd, struct sockaddr *addr, int addrlen);

/**
 * @brief Listen on a channel similar to 'listen()'
 *
 * @param cd
 *   The channel descriptor index
 * @param backlog
 *   The number of backlog connections allowed (not fully used)
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_listen(int cd, int backlog);

/**
 * @brief Accept on a channel similar to 'accept()'
 *
 * @param cd
 *   The channel descriptor index
 * @param sa
 *   The sockaddr to fill in when accepting a connection.
 * @param addrlen
 *   The length of the new accepted connection
 * @return
 *   -1 on error or >= 0 on success
 */
CNDP_API int chnl_accept(int cd, struct sockaddr *sa, socklen_t *addrlen);

/**
 * @brief Connect to a channel, similar to 'connect()'
 *
 * @param cd
 *   The channel descriptor index
 * @param sa
 *   The sockaddr to fill in when accepting a connection.
 * @param addrlen
 *   The length of the new accepted connection
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_connect(int cd, struct sockaddr *sa, int addrlen);

/**
 * This routine receives data from a chnl.  It is normally used with
 * connected chnls, because it does not return the source address of the
 * received data.
 *
 * @param cd
 *   The channel descriptor index
 * @param mbufs
 *   Vector list of pktmbuf_t pointers.
 * @param len
 *   Number of entries in the mbufs array.
 *
 * @return
 *   Number of mbufs in the list or -1 on error.
 */
CNDP_API int chnl_recv(int cd, pktmbuf_t **mbufs, size_t len);

/**
 * This routine transmits data to a previously connected chnl.
 *
 * @param cd
 *   The channel descriptor index
 * @param mbufs
 *   List of pointer vectors
 * @param nb_mbufs
 *   Number of mbufs in the vector list.
 *
 * @returns
 *   0 on success or -1 on failure.
 *
 * @Note ERRNO
 * EACCES
 *   An attempt was made to send to a broadcast address without the
 *   SO_BROADCAST option set.
 * EBADF
 *   ch is not a valid chnl descriptor.
 * EDESTADDRREQ
 *   The datagram chnl is not connected, and the destination address is not
 *   supplied as an argument.
 * EFAULT
 *   buf or len is invalid.
 * ENOBUFS
 *   Insufficient resources were available to complete the operation.
 * ENOTCONN
 *   The stream chnl is not connected.
 * EOPNOTSUPP
 *   Operation is not supported on this chnl type.
 * EPIPE
 *   The chnl is shut down for writing, or the stream chnl is no longer
 *   connected.
 * EWOULDBLOCK
 *   The chnl is marked non-blocking, and the operation cannot be completed
 *   without blocking.
 */
CNDP_API int chnl_send(int cd, pktmbuf_t **mbufs, uint16_t nb_mbufs);

/**
 * @brief Send data to a channel similar to 'sendto()'
 *
 * @param cd
 *   The channel descriptor index
 * @param sa
 *   The sockaddr to fill in when accepting a connection.
 * @param mbufs
 *   The mbuf array to send multiple data buffers
 * @param nb_mbufs
 *   Number of mbufs in the mbufs array
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_sendto(int cd, struct sockaddr *sa, pktmbuf_t **mbufs, uint16_t nb_mbufs);

/**
 * This routine gets the current name for the specified chnl.
 *
 * @param cd
 *   The channel descriptor index
 * @param name
 *   Buffer to receive the chnl name.
 * @param namelen
 *   Length of name.
 *   This is a value/result parameter.  On entry, it must be initialized to
 *   the size of the buffer pointed to by name.  On return, it contains the
 *   size of the chnl name.
 *
 * @NOTE
 *   If namelen is less than the actual length of the address, the
 *   value stored at name will be silently truncated.
 *
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_getchnlname(int cd, struct sockaddr *name, socklen_t *namelen);

/**
 * This routine gets the name of the peer connected to the specified chnl.
 *
 * @param cd
 *   The channel descriptor index
 * @param sa
 *   Buffer to receive the chnl name.
 * @param salen
 *   Length of name.
 *   This is a value/result parameter.  On entry, it must be initialized to
 *   the size of the buffer pointed to by name.  On return, it contains the
 *   size of the chnl name.
 *
 * @NOTE
 *   If namelen is less than the actual length of the address, the
 *   value stored at name will be silently truncated.
 *
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_getpeername(int cd, struct sockaddr *sa, socklen_t *salen);

/**
 * Close a connection to the specified chnl descriptor.
 *
 * @param cd
 *   The chnl descriptor index
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int chnl_close(int cd);

/**
 * @brief Shutdown a channel connection similar to 'shutdown()'
 *
 * @param cd
 *   The channel descriptor index
 * @param how
 *   How to shutdown the connection SHUT_RD, SHUT_WR or SHUT_RDWR.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int chnl_shutdown(int cd, int how);

/**
 * Open a channel with a string configuration.
 *
 * The channel string is similar to socat style strings, but not all string types
 * are support.
 * Some string types supported are:
 *   udp4-listen:0.0.0.0:5678     - Open a listening UDP4 channel on port 5678 or
 *   udp4-listen:5678             - Open a listening UDP4 channel on port 5678.
 *   tcp4-listen:0.0.0.0:4433     - Open a listening TCP4 channel on port 4433 or
 *   tcp4-listen:4433             - Open a listening TCP4 channel on port 4433.
 *   tcp4-connect:198.18.2.1:2222 - Open TCP4 connection to port 2222 and IP address
 *
 * Port value can be in hex '0x1234' or decimal format.
 *
 * @param str
 *   The string to parse to open or create a channel.
 * @param flags
 *   Some flags to control the creation of a channel, see CHNL_ENABLE_UDP_CHECKSUM
 *   and other flags to be defined.
 * @param fn
 *   Function pointer for channel callback.
 * @return
 *   -1 on error or channel descriptor value is returned.
 */
CNDP_API int chnl_open(const char *str, int flags, chnl_cb_t fn);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_CHNL_H */
