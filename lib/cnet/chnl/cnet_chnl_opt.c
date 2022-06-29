/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <bsd/sys/time.h>
#include <netinet/in.h>        // for IPPROTO_IP, IP_PKTINFO, IP_REC...
#include <cnet_stk.h>          // for stk_entry, per_thread_stk, this_stk
#include <cnet_pcb.h>          // for pcb_entry
#include "chnl_priv.h"
#include <cnet_chnl.h>        // for chnl, chnl_buf
#include <cnet_chnl_opt.h>
#include <errno.h>         // for EINVAL, ENOPROTOOPT
#include <stdlib.h>        // for NULL, calloc, size_t
#include <string.h>        // for memcpy

#include "cne_common.h"        // for CNE_MIN, CNE_MAX
#include "cne_log.h"           // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_ERR, CNE_L...
#include "cne_vec.h"
#include "cnet_const.h"          // for __errno_set, __errno_get, chnl_unlock, CHNL_...
#include "cnet_protosw.h"        // for protosw_entry

/**
 * This library provides an extension mechanism for channel option
 * processing.  Protocol processing modules can register to receive
 * setsockopt() and getsockopt() calls for options that are not
 * understood by the core setsockopt() and getsockopt() functions.
 */

/**
 * Add a sockopt switch structure.  There can be multiple handlers for each
 * level (e.g. IPPROTO_IP handlers for raw channel options, multicast options,
 * etc).
 *
 * RETURNS: 0, or -1 if the switch table is full
 */
int
cnet_chnl_opt_add(struct chnl_optsw *p)
{
    stk_t *stk = this_stk;

    if (!stk)
        return -1;

    vec_add(stk->chnlopt, p);

    return 0;
}

/**
 * This routine iterates through the sockopt structure table, calling the
 * 'setfunc' routine for any entry that matches <level>.  If the callback
 * function returns 0 or an errno value other than ENOPROTOOPT, it has
 * processed the option, and protoswIterateSet() returns.  Otherwise,
 * it proceeds to the next handler (if any).
 *
 * RETURNS: 0 or -1.
 */
int
cnet_chnl_opt_iterate_set(struct chnl *ch, int level, int optname, const void *optval,
                          uint32_t optlen)
{
    stk_t *stk = this_stk;
    struct chnl_optsw *p;
    int ret;

    if (!stk || !stk->chnlopt)
        return __errno_set(EINVAL);

    vec_foreach_ptr (p, stk->chnlopt) {
        if (p->level == level) {
            ret = p->setfunc(ch, level, optname, optval, optlen);
            if (ret == 0 || __errno_get() != ENOPROTOOPT)
                return ret;
        }
    }

    return __errno_set(ENOPROTOOPT);
}

/**
 * This routine iterates through the sockopt structure table, calling the
 * 'getfunc' routine for any entry that matches <level>.  If the callback
 * function returns 0 or an errno value other than ENOPROTOOPT, it has
 * processed the option, and protoswIterateGet() returns.  Otherwise,
 * it proceeds to the next handler (if any).
 *
 * RETURNS: 0 or -1.
 */
int
cnet_chnl_opt_iterate_get(struct chnl *ch, int level, int optname, void *optval, uint32_t *optlen)
{
    stk_t *stk = this_stk;
    struct chnl_optsw *p;
    int ret;

    if (!stk || !stk->chnlopt)
        return __errno_set(EINVAL);

    vec_foreach_ptr (p, stk->chnlopt) {
        if (p->level == level) {
            ret = p->getfunc(ch, level, optname, optval, optlen);
            if (ret == 0 || __errno_get() != ENOPROTOOPT)
                return ret;
        }
    }

    return __errno_set(ENOPROTOOPT);
}

/**
 * This routine sets the maximum limit on how much data can be queued to a
 * packet buffer, subject to the following constraints: 'cb_hiwat' cannot be
 * greater than 'cb_size' (configured at project build time, defaults to
 * MAX_UDP_RCV_SIZE for UDP and raw, MAX_TCP_RCV_SIZE for TCP) or less
 * than _MIN_BUF_SIZE (defaults to 3xMSS); and 'cb_hiwat' cannot be less
 * than 'cb_lowat'.
 */
static inline void
chnl_sbreserve(struct chnl_buf *sb, uint32_t cc)
{
    sb->cb_hiwat = CNE_MIN(cc, (uint32_t)sb->cb_size);

    if (sb->cb_hiwat < _MIN_BUF_SIZE)
        sb->cb_hiwat = _MIN_BUF_SIZE;

    if (sb->cb_lowat > sb->cb_hiwat)
        sb->cb_lowat = sb->cb_hiwat;
}

/**
 * This routine sets the minimum amount of data that must be queued to a chnl
 * buffer before a listening process will be woken up, subject to the following
 * constraints: 'cb_lowat' cannot be less than 1 or more than 'cb_hiwat'.
 */
static inline void
chnl_sblimit(struct chnl_buf *sb, uint32_t cc)
{
    sb->cb_lowat = (int32_t)CNE_MAX(cc, (uint32_t)1);

    if (sb->cb_lowat > sb->cb_hiwat)
        sb->cb_lowat = sb->cb_hiwat;
}

/**
 * This routine get an integer chnl option value, regardless of the
 * size of the integer.
 *
 * Integer chnl options are not required to be 4 bytes, ch setsockopt()
 * has to examine the <optlen> argument.
 *
 */
uint32_t
chnl_optval_get(const void *optval, uint32_t optlen)
{
    switch (optlen) {
    case 1:
        return (uint32_t)(*(uint8_t *)(uintptr_t)optval);

    case 2:
        return (uint32_t)(*(uint16_t *)(uintptr_t)optval);

    case 4:
        return (uint32_t)(*(uint32_t *)(uintptr_t)optval);

    default:
        return 0;
    }
}

/**
 * This routine sets an option value associated with a chnl.
 *
 * The following options apply to all chnl types.
 *
 * SO_RCVBUF - receive buffer size ('int')
 * This option sets the maximum size of the chnl-level receive buffer.
 * The value at optval specifies the size of the chnl-level receive
 * buffer to be allocated.
 *
 * When chnls are created, each transport protocol reserves a set amount
 * of space at the chnl level for use when the chnls are attached to a
 * protocol.  This defaults to MAX_TCP_RCV_SIZE bytes for all protocols.
 *
 * The effect of setting the maximum size of buffers (for both
 * SO_RCVBUF and SO_SNDBUF, described below) is not actually to
 * allocate the mbufs from the mbuf pool, but to set the high-water
 * mark in the protocol data structure which is used later to limit the
 * amount of mbuf allocation.  Thus, the maximum size specified for the
 * packet level send and receive buffers can affect the performance of
 * bulk data transfers.  For example, the size of the TCP receive
 * windows is limited by the remaining chnl-level buffer space.
 * These parameters must be adjusted to produce the optimal result for
 * a given application.
 *
 * SO_RCVLOWAT - receive low-water mark ('int')
 * This option sets the minimum number of bytes to read on a receive
 * operation.  The default value is 1.  Note that, even if SO_RCVLOWAT is
 * set to a higher value, a blocking receive operation may return less than
 * the low water mark if the receive side of the chnl has been shut down,
 * or a protocol-level error has occurred (e.g. connection reset by peer).
 *
 * SO_RCVTIMEO - receive timeout (struct 'timeval')
 * This option sets a timeout value for receive operations.  If a receive
 * operation has blocked for the specified time, it returns with a short
 * count or with the error EWOULDBLOCK if no data was received.  The default
 * value of zero indicates an infinite timeout (blocking operations will
 * wait indefinitely).
 *
 * SO_REUSEADDR - allow local address reuse ('int'/boolean)
 * This option controls whether a chnl can bind to a local port that may
 * already be bound to another chnl of the same type.  Note that this does
 * not allow a totally duplicate binding - each chnl must bind to
 * different local addresses or the unspecified address (INADDR_ANY).
 *
 * SO_REUSEPORT - allow local address and port reuse ('int'/boolean)
 * This option is similar to the SO_REUSEADDR option but it allows binding
 * to the same local address and port combination.
 *
 * This option is mainly required by multicast applications, where a number
 * of applications need to bind to the same multicast address and port to
 * receive multicast data. Unlike SO_REUSEADDR where only the later
 * applications need to set this option, with SO_REUSEPORT all applications
 * including the first to bind to the port are required to set this option.
 *
 * SO_SNDBUF - send buffer size ('int')
 * This option sets the maximum size of the chnl-level send buffer.
 * The value at optval specifies the size of the chnl-level send
 * buffer to be allocated.
 *
 * When chnls are created, each transport protocol reserves a set amount
 * of space at the chnl level for use when the chnls are attached to a
 * protocol.  At present, this defaults to MAX_TCP_RCV_SIZE bytes for all
 * protocols.
 *
 * See SO_RCVBUF above for a discussion of the impact of buffer size on
 * application performance.
 *
 * SO_SNDLOWAT - send low-water mark ('int')
 * This option sets the minimum number of bytes to transmit on a send
 * operation.  The default value is 1.
 *
 * SO_SNDTIMEO - send timeout (struct 'timeval')
 * This option sets a timeout value for send operations.  If a send
 * operation has blocked for the specified time, it returns with a short
 * count or with the error EWOULDBLOCK if no data was sent.  The default
 * value of zero indicates an infinite timeout (blocking operations will
 * wait indefinitely).
 *
 * The following SO_CHANNEL options only apply to stream chnls.
 *
 * SO_KEEPALIVE - keep connections alive ('int'/boolean)
 * This option helps the protocol layer detect dead connections, by
 * periodically transmitting zero-length TCP segment, to force a response
 * from a peer node.  If the peer does not respond after repeated
 * transmissions of the KEEPALIVE segments, the connection is dropped, all
 * protocol data structures are reclaimed, and processes sleeping on the
 * connection are awakened with an ETIMEDOUT error.
 *
 * The following SO_CHANNEL option only applies to datagram chnls.
 *
 * SO_BROADCAST - permit sending of broadcast msgs ('int'/boolean)
 * This option enables an application to send data to a broadcast address.
 *
 * IPPROTO_IP OPTIONS
 *
 * IP_RECVTOS - IP type of service value ('int')
 * This option sets the Type-Of-Service field for each packet sent from this
 * packet.  optval can be set to IPTOS_LOWDELAY, IPTOS_THROUGHPUT,
 * IPTOS_RELIABILITY, or IPTOS_MINCOST, to indicate how the packets sent on
 * this chnl should be prioritized.
 *
 * IP_RECVTTL - IP time to live value ('int')
 * This option sets the Time-To-Live field for each packet sent from this
 * packet.  optval indicates the number of hops a packet can take before
 * it is discarded.
 *
 * IP_DONTFRAG - IP don't-fragment bit ('int'/boolean)
 * This option sets the DontFragment bit for each packet sent from this
 * packet.  This bit instructs intermediate routers not to fragment the
 * packet if it exceeds the link MTU.  Instead, the router will drop the
 * packet and return an ICMP message.
 *
 * IP_HDRINCL - IP header included with outgoing packets ('int'/boolean)
 * This option indicates that the application will include a completed IP
 * header in all send operations.  This option only applies to raw chnls.
 *
 * IP_UDP_XCHKSUM - enable checksum for outgoing UDP packets ('int'/boolean)
 * This option enables or disables checksum calculations in outgoing UDP
 * packets. Checksums in incoming packets will still be validated, even if
 * outgoing checksums are disabled.  Disabling checksums provides a very
 * slight performance gain, at the risk of undetected data corruption, and
 * is consequently discouraged.  This option only applies to UDP chnls.
 *
 *
 * IPPROTO_TCP OPTIONS
 *
 * TCP_NODELAY
 * This option instructs the TCP layer not to coalesce packets.  It is
 * commonly used for real-time protocols, such as the X Window System
 * Protocol, that require immediate delivery of many small messages.
 *
 * TCP_MAXSEG
 * This option sets the Max Segment Size (MSS) for a TCP connection.
 * Specify the TCP_MAXSEG option to decrease the maximum allowable size of an
 * outgoing TCP segment. This option cannot be used to increase the MSS.
 *
 * TCP_NOOPT
 * This option instructs the TCP layer not to use options.
 *
 * TCP_NOPUSH
 * This option instructs the TCP layer not to send a segment just to empty
 * the chnl send buffer.
 *
 * @return
 *   OK or ERROR.
 */
int
chnl_set_opt(int cd, int level, int optname, const void *optval, int optlen)
{
    struct chnl *ch = ch_get(cd);
    uint32_t val    = 0;
    int rs          = 0;

    if (!ch || optval == NULL || (int32_t)optlen <= 0)
        return __errno_set(EINVAL);

    if (stk_lock()) {
        if (chnl_state_tst(ch, _CHNL_FREE)) {
            __errno_set(EINVAL);
            goto leave;
        }

        val = chnl_optval_get(optval, (uint32_t)optlen);

#define setsockoptBit(reg, bit, val) \
    if (val != 0)                    \
        (reg) |= (bit);              \
    else                             \
        (reg) &= ~(bit);

        switch (level) {
        case SO_CHANNEL:
            switch (optname) {
            /* flag options */
            case SO_KEEPALIVE:
            case SO_BROADCAST:
                setsockoptBit(ch->ch_options, optname, val);
                break;

            case SO_REUSEADDR:
            case SO_REUSEPORT:
                setsockoptBit(ch->ch_options, optname, val);
                break;

            case SO_SNDBUF:
            case SO_RCVBUF:
                /*
                 * Do not allow the receive buffer size to decrease if
                 * already connected.
                 */
                if ((val == 0) || ((optname == SO_RCVBUF) && chnl_state_tst(ch, _ISCONNECTED) &&
                                   (val < ch->ch_rcv.cb_hiwat))) {
                    CNE_ERR("val = %d\n", val);
                    rs = __errno_set(EINVAL);
                    break;
                }

                chnl_sbreserve(((optname == SO_SNDBUF) ? &ch->ch_snd : &ch->ch_rcv), val);
                break;

            default:
                CNE_ERR("Unknown option %d\n", optname);
                goto Unknown;
            }

            break;

        case IPPROTO_IP:
            switch (optname) {
            /* flag options */
            case IP_HDRINCL:
                setsockoptBit(ch->ch_pcb->opt_flag, IP_HDRINCL_FLAG, val);
                break;

            case IPV6_DONTFRAG:
                setsockoptBit(ch->ch_pcb->opt_flag, IP_DONTFRAG_FLAG, val);
                break;

            case SO_UDP_CHKSUM:
                setsockoptBit(ch->ch_pcb->opt_flag, UDP_CHKSUM_FLAG, val);
                break;

            /* value options */
            case IP_RECVTOS:
                ch->ch_pcb->tos = (uint8_t)val;
                break;

            case IP_RECVTTL:
                ch->ch_pcb->ttl = (uint8_t)val;
                break;

            default:
                CNE_ERR("Unknown optname %d\n", optname);
                goto Unknown;
            }

            break;

        default:
            CNE_ERR("Unknown level %d\n", level);
            goto Unknown;
        }

        stk_unlock();
    }
    return rs;

Unknown:
    /* level/optname not handled here - pass it on to extension handlers */
    rs = cnet_chnl_opt_iterate_set(ch, level, optname, optval, (uint32_t)optlen);
    if (rs == -1 && __errno_get() == ENOPROTOOPT)
        CNE_ERR("setsockopt: level %d optname %d not supported\n", level, optname);
leave:
    stk_unlock();
    return rs;
}

/**
 * This routine returns an option value associated with a chnl.
 *
 * @param cd
 *   Channel descriptor value
 * @param level
 *   Protocol level of option.
 *   To manipulate options at the "chnl" level, level should be SO_CHANNEL.
 *   Any other levels should use the appropriate protocol number.
 * @param optname
 *   Option name.
 * @param optval
 *   Value of option.
 * @param optlen
 *   Length of optval.
 *   This is a value/result parameter.  On entry, it must be initialized to
 *   the size of the buffer pointed to by optval.  On return, it contains the
 *   actual size of the option.
 *
 * @NOTE:
 *   If optlen is less than the size of the the option value, the
 *   value stored at optval will be silently truncated.
 *
 * SO_CHANNEL OPTIONS
 *
 * The following options apply to all chnl types.
 *
 * SO_ERROR - get error status and clear ('int')
 * This option retrieves a stored error code from the chnl.  This error
 * code, if present, will have been set asynchronously by a lower-layer
 * protocol module, in response to a network error condition.  The most
 * common causes of such errors are ICMP messages and TCP connection resets.
 *
 * SO_TYPE - get chnl type ('int')
 * This option reports the chnl type, e.g. SOCK_STREAM, SOCK_DGRAM, or
 * SOCK_RAW.
 *
 * SO_RCVBUF - receive buffer size ('int')
 * This option reports the maximum size of the chnl-level receive buffer.
 *
 * SO_RCVLOWAT - receive low-water mark ('int')
 * This option reports the minimum number of bytes to read on a receive
 * operation.
 *
 * SO_RCVTIMEO - receive timeout (struct 'timeval')
 * This option reports the timeout value for receive operations.
 *
 * SO_REUSEADDR - allow local address reuse ('int'/boolean)
 * This option reports whether a chnl can bind to a local port that may
 * already be bound to another chnl of the same type.
 *
 * SO_REUSEPORT - allow local address and port reuse ('int'/boolean)
 * This option reports whether a chnl can create a completely duplicate
 * binding as another chnl of the same type.
 *
 * SO_SNDBUF - send buffer size ('int')
 * This option reports the maximum size of the chnl-level send buffer.
 *
 * SO_SNDLOWAT - send low-water mark ('int')
 * This option reports the minimum number of bytes to transmit on a send
 * operation.
 *
 * SO_SNDTIMEO - send timeout (struct 'timeval')
 * This option reports the timeout value for send operations.
 *
 * The following SO_CHANNEL options only apply to stream chnls.
 *
 * SO_KEEPALIVE - keep connections alive ('int'/boolean)
 * This option reports whether keep-alives are enabled.
 *
 * SO_ACCEPTCONN - return true, if the chnl is listening.
 * This option only applies to a TCP connection.
 *
 * The following SO_CHANNEL option only applies to datagram chnls.
 *
 * SO_BROADCAST - permit sending of broadcast msgs ('int'/boolean)
 * This option reports whether an application can send data to a broadcast
 * address.
 *
 * IPPROTO_IP OPTIONS
 *
 * IP_TOS - IP type of service value ('int')
 * This option reports the value of the Type-Of-Service field for each
 * packet sent from this chnl.
 *
 * IP_TTL - IP time to live value ('int')
 * This option reports the value of the Time-To-Live field for each packet
 * sent from this chnl.
 *
 * IP_DONTFRAG - IP don't-fragment bit ('int'/boolean)
 * This option reports the value of the DontFragment bit for each packet
 * sent from this chnl.
 *
 * IP_HDRINCL - IP header included with outgoing packets ('int'/boolean)
 * This option reports whether the application will include a completed IP
 * header in all send operations.  This option only applies to raw chnls.
 *
 * IP_UDP_XCHKSUM - enable checksum for outgoing UDP packets ('int'/boolean)
 * This option reports whether checksums will be calculated foroutgoing UDP
 * packets.  This option only applies to UDP chnls.
 *
 * @return
 *   OK or ERROR.
 */
int
chnl_get_opt(int cd, int level, int optname, void *optval, socklen_t *optlen)
{
    struct chnl *ch = ch_get(cd);
    uint32_t len;
    uint64_t resI = 0;
    void *resP    = &resI;
    int rs        = -1;

    if (!ch || optval == NULL || optlen == NULL || *(int32_t *)optlen <= 0)
        return __errno_set(EINVAL);

    if (stk_lock()) {
        if (chnl_state_tst(ch, _CHNL_FREE)) {
            __errno_set(EINVAL);
            goto leave;
        }

        len = CNE_MIN(*(uint32_t *)optlen, sizeof(int)); /* most options are int */

        switch (level) {
        case SO_CHANNEL:
            switch (optname) {
            /* bit-flag options */
            case SO_REUSEADDR:
            case SO_KEEPALIVE:
            case SO_BROADCAST:
            case SO_REUSEPORT:
                resI = (int)((ch->ch_options & optname) != 0);
                break;

            /* value options */
            case SO_RCVLOWAT:
                resI = (int)ch->ch_rcv.cb_lowat;
                break;

            case SO_SNDLOWAT:
                resI = (int)ch->ch_snd.cb_lowat;
                break;

            case SO_SNDBUF:
                resI = (int)ch->ch_snd.cb_hiwat;
                break;

            case SO_RCVBUF:
                resI = (int)ch->ch_rcv.cb_hiwat;
                break;

            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
                break;

            case SO_ERROR:
                resI         = (int)ch->ch_error;
                ch->ch_error = 0;
                break;

            case SO_TYPE:
                resI = (int)ch->ch_proto->type;
                break;

            default:
                goto Unknown;
            }

            break;

        case IPPROTO_IP:
            switch (optname) {
            /* flag options */
            case IP_HDRINCL:
                resI = (int)((ch->ch_pcb->opt_flag & IP_HDRINCL_FLAG) != 0);
                break;

            case IP_DONTFRAG:
                resI = (int)((ch->ch_pcb->opt_flag & IP_DONTFRAG_FLAG) != 0);
                break;

            case UDP_CHKSUM_FLAG:
                resI = (int)((ch->ch_pcb->opt_flag & UDP_CHKSUM_FLAG) != 0);
                break;

            case IP_RECVTOS:
                resI = (int)ch->ch_pcb->tos;
                break;

            case IP_RECVTTL:
                resI = (int)ch->ch_pcb->ttl;
                break;

            case IP_PKTINFO:
                CNE_ERR("IP_PKTINFO\n");
                break;

            default:
                goto Unknown;
            }

            break;
        default:
            goto Unknown;
        }

        if (len == 4) {
            int32_t *p32 = (int32_t *)optval;
            *p32         = resI;
        } else
            memcpy(optval, resP, len);
        *optlen = (size_t)len;

        stk_unlock();
    }

    return 0;

Unknown:

    /* level/optname not handled here - pass it on to any extension handlers */
    rs = cnet_chnl_opt_iterate_get(ch, level, optname, optval, (uint32_t *)optlen);

    if (rs == -1 && __errno_get() == ENOPROTOOPT)
        CNE_DEBUG("chnl_get_opt: level %d optname %d not supported\n", level, optname);
leave:
    stk_unlock();

    return rs;
}
