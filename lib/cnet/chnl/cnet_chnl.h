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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __CHNL_PRIV_H
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

#define CHNL_ENABLE_UDP_CHECKSUM (1 << 0) /**< Enable UDP checksum */

#define SO_CHANNEL    1
#define SO_UDP_CHKSUM 1024
#define IP_DONTFRAG   1025

enum {
    SHUT_BIT_RD   = 0x01, /**< Shutdown Read side */
    SHUT_BIT_WR   = 0x02, /**< Shutdown Write side */
    SHUT_BIT_RDWR = 0x03, /**< Shutdown Read and write side */
};

typedef enum {
    CHNL_UDP_RECV_TYPE,   /**< Callback for receiving UDP packets */
    CHNL_UDP_CLOSE_TYPE,  /**< Callback for UDP close */
    CHNL_TCP_ACCEPT_TYPE, /**< Callback type for accepting TCP connection */
    CHNL_TCP_RECV_TYPE,   /**< Callback for receiving TCP packets */
    CHNL_TCP_CLOSE_TYPE,  /**< Callback for TCP close */
    CHNL_CALLBACK_TYPES   /**< Maximum number of callback types */
} chnl_type_t;

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
 * @brief Channel Bind common routine used by protocols
 *
 * @param ch
 *   The channel structure pointer
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
