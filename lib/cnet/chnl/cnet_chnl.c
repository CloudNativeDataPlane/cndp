/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <pthread.h>           // for pthread_mutex_init, pthread_cond_init, pth...
#include <cnet.h>              // for cnet_add_instance
#include <cnet_stk.h>          // for stk_entry, per_thread_stk, this_stk, cnet_...
#include <cne_inet.h>          // for in_caddr, in_caddr_copy
#include <cne_vec.h>           // for vec_len, vec_pool_free, vec_add_ptr
#include <cnet_pcb.h>          // for pcb_entry, pcb_key, cnet_pcb_delete, pcb_hd
#include <cnet_udp.h>          // for udp_entry
#include <cnet_tcp.h>          // for tcp_entry
#include <cnet_netif.h>        // for cnet_netif_match_subnet
#include "chnl_priv.h"
#include <cnet_chnl.h>
#include <errno.h>         // for EFAULT, EINVAL, EADDRINUSE, EADDRNOTAVAIL
#include <string.h>        // for memcpy, memset, strerror
#include <cnet_meta.h>
#include <cne_mutex_helper.h>

#include "cne_common.h"        // for __cne_unused, CNE_MIN, CNE_SET_USED
#include "cne_log.h"           // for cne_panic
#include "cnet_const.h"        // for __errno_set, chnl_unlock, chnl_lock, is_set
#include "cnet_reg.h"
#include "cnet_ipv4.h"           // for TOS_DEFAULT, TTL_DEFAULT
#include "cnet_protosw.h"        // for protosw_entry, proto_funcs, cnet_protosw_find
#include "mempool.h"             // for mempool_cfg, mempool_create, mempool_get
#include "pktmbuf.h"             // for pktmbuf_data_len, pktmbuf_t, ...

static void chnl_free(struct chnl *ch);

static inline int
alloc_cd(struct chnl *ch)
{
    struct cnet *cnet = this_cnet;

    if (cnet && ch) {
        int cd = uid_alloc(cnet->chnl_uids);

        if (cd >= 0) {
            cnet->chnl_descriptors[cd] = ch;
            ch->ch_cd                  = cd;
            ch->stk_id                 = this_stk->idx;
            return 0;
        }
    }
    return -1;
}

static inline void
free_cd(struct chnl *ch)
{
    struct cnet *cnet = this_cnet;

    if (cnet && ch && ch->ch_cd >= 0 && ch->ch_cd < uid_max_ids(cnet->chnl_uids)) {
        uid_free(cnet->chnl_uids, ch->ch_cd);

        cnet->chnl_descriptors[ch->ch_cd] = NULL;
        ch->ch_cd                         = -1;
    }
}

static void
mp_init(mempool_t *mp, void *opaque_arg __cne_unused, void *_b, unsigned i __cne_unused)
{
    struct chnl *ch = _b;

    memset(ch, 0, mempool_objsz(mp));

    chnl_state_set(ch, _CHNL_FREE);
    ch->ch_cd = -1;
}

/*
 * This routine allocates a chnl structure from the free list,
 * and initializes it for use.
 */
static struct chnl *
chnl_alloc(void)
{
    stk_t *stk             = this_stk;
    struct mempool_cfg cfg = {0};
    struct chnl *ch        = NULL;
    struct cnet *cnet      = cnet_get();

    if (stk_lock()) {
        if (!stk->chnl_objs) {
            cfg.objcnt     = cnet->num_chnls;
            cfg.objsz      = sizeof(struct chnl);
            cfg.cache_sz   = 64;
            stk->chnl_objs = mempool_create(&cfg);

            if (!stk->chnl_objs) {
                stk_unlock();
                CNE_NULL_RET("Unable to create objpool\n");
            }

            mempool_obj_iter(stk->chnl_objs, mp_init, NULL);
        }
        stk_unlock();
    } else
        CNE_NULL_RET("Unable to acquire mutex\n");

    if (mempool_get(stk->chnl_objs, (void *)&ch) < 0)
        CNE_NULL_RET("Allocate for chnl_obj failed\n");

    if (alloc_cd(ch) < 0) {
        mempool_put(stk->chnl_objs, ch);
        CNE_NULL_RET("allocate of channel descriptor failed\n");
    }

    chnl_state_set(ch, _NOSTATE);

    return ch;
}

/*
 * This routine re-initializes a chnl structure, and returns it to the free
 * list.
 */
static void
chnl_free(struct chnl *ch)
{
    stk_t *stk = this_stk;

    if (!ch || !stk)
        return;

    if (chnl_state_tst(ch, _CHNL_FREE))
        CNE_RET("chnl is already free!");

    free_cd(ch);

    vec_free(ch->ch_rcv.cb_vec);
    vec_free(ch->ch_snd.cb_vec);

    ch->ch_rcv.cb_vec = NULL;
    ch->ch_snd.cb_vec = NULL;

    /* Set chnl structure to the free state */
    chnl_state_set(ch, _CHNL_FREE);
    ch->ch_pcb = NULL;

    if (cne_mutex_destroy(&ch->ch_mutex))
        CNE_ERR("unable to destroy ch_mutex\n");

    mempool_put(stk->chnl_objs, (void *)ch);
}

/*
 * This routine flushes all queued data in a chnl buffer.
 */
static void
chnl_cbflush(struct chnl_buf *cb)
{
    if (vec_len(cb->cb_vec)) {
        pktmbuf_free_bulk(cb->cb_vec, vec_len(cb->cb_vec));
        vec_set_len(cb->cb_vec, 0);
        cb->cb_cc = 0;
    }
}

/*
 * This routine is called as the last part of the close() sequence.
 */
void
chnl_cleanup(struct chnl *ch)
{
    if (!ch)
        CNE_RET("Channel NULL\n");

    if (stk_lock()) {
        if (chnl_state_tst(ch, _CHNL_FREE)) {
            stk_unlock();
            CNE_RET("Already free!\n");
        }

        chnl_state_set(ch, _ISDISCONNECTED);

        /* Just to be sure the RD/WR are awake */
        chnl_cant_snd_rcv_more(ch, (_CANTSENDMORE | _CANTRECVMORE));

        /* Flush the chnl buffers */
        chnl_cbflush(&ch->ch_snd);
        chnl_cbflush(&ch->ch_rcv);

        if (ch->ch_proto) {
            struct pcb_entry *pcb;

            pcb        = ch->ch_pcb;
            ch->ch_pcb = NULL;

            if (ch->ch_proto->proto == IPPROTO_UDP)
                cnet_pcb_delete(&this_stk->udp->udp_hd, pcb);
            else if (ch->ch_proto->proto == IPPROTO_TCP)
                cnet_pcb_delete(&this_stk->tcp->tcp_hd, pcb);
            else
                CNE_WARN("Unable to determine pcb type %d\n", ch->ch_proto->proto);
        }
        chnl_free(ch);

        stk_unlock();
    }
}

static int
__alloc_pcb(struct chnl *ch, int typ)
{
    stk_t *stk = this_stk;
    struct chnl_buf *rb, *sb;
    struct pcb_entry *pcb;

    rb = &ch->ch_rcv;
    sb = &ch->ch_snd;

    if (typ == SOCK_DGRAM) {
        rb->cb_size = rb->cb_hiwat = stk->udp->rcv_size;
        sb->cb_size = sb->cb_hiwat = stk->udp->snd_size;
        rb->cb_lowat = sb->cb_lowat = 1;

        if ((pcb = cnet_pcb_alloc(&stk->udp->udp_hd, IPPROTO_UDP)) == NULL)
            return __errno_set(ENOBUFS);

        if (stk->udp->cksum_on)
            pcb->opt_flag |= UDP_CHKSUM_FLAG;

        ch->ch_proto->proto = IPPROTO_UDP;
    } else {
        rb->cb_size = rb->cb_hiwat = stk->tcp->rcv_size;
        sb->cb_size = sb->cb_hiwat = stk->tcp->snd_size;
        rb->cb_lowat = sb->cb_lowat = 1;

        if ((pcb = cnet_pcb_alloc(&stk->tcp->tcp_hd, IPPROTO_TCP)) == NULL)
            return __errno_set(ENOBUFS);

        ch->ch_proto->proto = IPPROTO_TCP;
    }

    pcb->ch    = ch;
    ch->ch_pcb = pcb;
    pcb->ttl   = TTL_DEFAULT;
    pcb->tos   = TOS_DEFAULT;

    rb->cb_vec = vec_alloc(rb->cb_vec, rb->cb_size / PROTO_DEFAULT_MBUF_COUNT);
    if (rb->cb_vec == NULL) {
        cnet_pcb_free(pcb);
        return __errno_set(ENOBUFS);
    }
    sb->cb_vec = vec_alloc(sb->cb_vec, sb->cb_size / PROTO_DEFAULT_MBUF_COUNT);
    if (sb->cb_vec == NULL) {
        vec_free(rb->cb_vec);
        cnet_pcb_free(pcb);
        return __errno_set(ENOBUFS);
    }
    return 0;
}

/*
 * This routine allocates and initializes a new chnl structure.
 *
 * If the <ppcb> or parent PCB is not null then use some information from
 * the parent chnl structure.
 *
 * @return
 *   struct chnl pointer or NULL.
 */
struct chnl *
__chnl_create(int32_t dom, int32_t type, int32_t pro, struct pcb_entry *ppcb)
{
    struct chnl *ch;
    struct pcb_entry *pcb;

    /* Allocate a new chnl structure */
    if ((ch = chnl_alloc()) == NULL) {
        __errno_set(ENOBUFS);
        goto err;
    }

    /* If this is a raw chnl, register it as IPPROTO_IP, and store the
     * protocol number in the PCB.
     */
    ch->ch_proto = cnet_protosw_find(dom, type, ((type == SOCK_RAW) ? IPPROTO_RAW : pro));
    if (ch->ch_proto == NULL) {
        __errno_set(EPROTONOSUPPORT);
        goto err;
    }

    if (__alloc_pcb(ch, type)) {
        __errno_set(ENOBUFS);
        goto err;
    }
    pcb = ch->ch_pcb;

    if (ppcb) {
        CNE_DEBUG("Copy the parent PCB information\n");
        CNE_DEBUG("   chnl @ [orange]%p[], netif @ [orange]%p[]\n", ppcb->ch, ppcb->netif);

        if (ppcb->ch) {
            struct chnl *_ch = ppcb->ch;

            /* Clone the information from the parent */
            ch->ch_rcv.cb_lowat = _ch->ch_rcv.cb_lowat;
            ch->ch_snd.cb_lowat = _ch->ch_snd.cb_lowat;
            ch->ch_rcv.cb_hiwat = _ch->ch_rcv.cb_hiwat;
            ch->ch_snd.cb_hiwat = _ch->ch_snd.cb_hiwat;
            ch->ch_rcv.cb_size  = _ch->ch_rcv.cb_size;
            ch->ch_snd.cb_size  = _ch->ch_snd.cb_size;
        }
        pcb->netif = ppcb->netif;
    }

    CIN_FAMILY(&pcb->key.laddr) = CIN_FAMILY(&pcb->key.faddr) = dom;
    CIN_LEN(&pcb->key.laddr) = CIN_LEN(&pcb->key.faddr) = 0;

    return ch;
err:
    chnl_cleanup(ch);
    return NULL;
}

/*
 * This routine opens a chnl and returns a chnl descriptor.
 * The chnl descriptor is passed to the other chnl routines to identify the
 * channel to process.
 */
int
channel(int domain, int type, int proto, chnl_cb_t cb)
{
    struct chnl *ch;

    if (this_stk == NULL)
        return __errno_set(EFAULT);

    if ((ch = __chnl_create(domain, type, proto, NULL)) == NULL)
        return __errno_set(EINVAL);

    ch->ch_callback = cb;

    return ch->ch_cd;
}

int
chnl_close(int cd)
{
    struct chnl *ch = ch_get(cd);
    int ret         = -1;

    if (!ch || (this_stk == NULL))
        return __errno_set(EFAULT);

    if (stk_lock()) {
        ret = ch->ch_proto->funcs->close_func(ch);
        stk_unlock();
    }

    return ret;
}

/*
 * This routine shuts down the receive and/or send side of a connection.
 *
 * On a TCP chnl, shutting down the send side initiates a protocol-level
 * connection close (send FIN and progress to FIN_WAIT_1 state).
 *
 * NOTE: Shutting down the receive side does not de-queue any data that
 * may have been received by the protocol layer.
 */
int
chnl_shutdown(int cd, int how)
{
    struct protosw_entry *psw;
    struct chnl *ch = ch_get(cd);
    int status      = 0;

    if (!ch || this_stk == NULL || (how < SHUT_RD) || (how > SHUT_RDWR))
        return __errno_set(EINVAL);

    if (stk_lock()) {
        /* normalize from 0-2 to 1-3 so we can bit-test */
        how++;

        psw = ch->ch_proto;
        if (psw && psw->funcs)
            status = psw->funcs->shutdown_func(ch, how);

        if (!status) {
            /* shutdown recv side */
            if ((how & SHUT_BIT_RD) && !chnl_cant_rcv_more(ch))
                chnl_cant_snd_rcv_more(ch, _CANTRECVMORE);

            /* shutdown send side */
            if ((how & SHUT_BIT_WR) && !chnl_cant_snd_more(ch))
                chnl_cant_snd_rcv_more(ch, _CANTSENDMORE);
        }

        if (chnl_snd_rcv_more(ch, _CANTRECVMORE | _CANTSENDMORE))
            chnl_cleanup(ch);

        stk_unlock();
    }

    return status;
}

/*
 * This routine associates a network address (also referred to as its "name")
 * with a chnl ch that other processes can connect or send to it.
 * When a chnl is created with chnl(), it belongs to an address family
 * but has no assigned name.
 *
 */
int
chnl_bind(int cd, struct sockaddr *sa, int namelen)
{
    struct in_caddr *name = (struct in_caddr *)sa;
    struct chnl *ch       = ch_get(cd);
    int rs                = -1;

    if (!ch || this_stk == NULL)
        return -1;

    if (stk_lock()) {
        /* Check that address structure is passed and is not too short.
         * One special case is allowed: a NULL name with a namelen of 0.
         */
        if (((name == NULL) && (namelen != 0)) ||
            ((name != NULL) && (namelen > (int)sizeof(struct sockaddr)))) {
            __errno_set(EINVAL);
            CNE_ERR_GOTO(leave, "Name Invalid name %p, namelen %d > %ld\n", name, namelen,
                         sizeof(struct in_caddr));
        }

        if ((name != NULL) && (CIN_FAMILY(name) != ch->ch_proto->domain)) {
            __errno_set(EAFNOSUPPORT);
            CNE_ERR_GOTO(leave, "Error family\n");
        }

        rs = ch->ch_proto->funcs->bind_func(ch, name, namelen);
        stk_unlock();
    }
    return rs;

leave:
    stk_unlock();
    return -1;
}

/*
 * If <ch> is a stream chnl, this routine establishes a virtual circuit
 * between <ch> and another chnl specified by <name>.  If <ch> is a datagram
 * packet, it permanently specifies the peer to which messages are sent.
 */
int
chnl_connect(int cd, struct sockaddr *sa, int namelen)
{
    struct in_caddr *name = (struct in_caddr *)sa;
    struct chnl *ch       = ch_get(cd);
    int rs                = -1;
    struct protosw_entry *psw;
    struct in_caddr faddr = {0};

    if (!cd || this_stk == NULL)
        return __errno_set(EFAULT);

    if (!name || (namelen > (int)sizeof(struct in_caddr)) || !ch || !ch->ch_proto)
        CNE_ERR_RET_VAL(__errno_set(EINVAL), "Channel name %p or len %d != %ld\n", name, namelen,
                        sizeof(struct in_caddr));

    if (stk_lock()) {
        if (CIN_FAMILY(name) != ch->ch_proto->domain) {
            __errno_set(EAFNOSUPPORT);
            CNE_ERR_GOTO(leave, "Channel family does not match %d != %d\n", CIN_FAMILY(name),
                         ch->ch_proto->domain);
        }

        if ((CIN_FAMILY(name) == AF_INET) && (CIN_CADDR(name) == INADDR_ANY)) {
            __errno_set(EADDRNOTAVAIL);
            CNE_ERR_GOTO(leave, "Channel family does not match %d != %d\n", CIN_FAMILY(name),
                         ch->ch_proto->domain);
        }

        /* Get a local copy of the user struct in_caddr data, as his may be dirty */
        in_caddr_copy(&faddr, name);

        psw = ch->ch_proto;

        /* If the chnl is not bound, bind it now. */
        if ((CIN_PORT(&ch->ch_pcb->key.laddr) == 0) && (ch->ch_proto->type != SOCK_RAW)) {
            struct in_caddr saddr;

            in_caddr_zero(&saddr);

            CIN_LEN(&saddr)    = CIN_LEN(&faddr);
            CIN_FAMILY(&saddr) = CIN_FAMILY(&faddr);
            CIN_PORT(&saddr)   = CIN_PORT(&faddr);

            if (psw->funcs) {
                rs = psw->funcs->bind_func(ch, &saddr, CIN_LEN(&saddr));
                if (rs)
                    CNE_ERR_GOTO(leave, "Failed bind call\n");
            }
        }

        in_caddr_copy(&ch->ch_pcb->key.faddr, &faddr);

        if (psw && psw->funcs)
            rs = psw->funcs->connect_func(ch, name, namelen);
        stk_unlock();
    }
    return 0;

leave:
    stk_unlock();
    return -1;
}

/*
 * This routine enables connections to a stream chnl. After enabling
 * connections with listen(), connections are actually accepted by accept().
 */
int
chnl_listen(int cd, int backlog)
{
    struct chnl *ch = ch_get(cd);
    int rs          = -1;

    if (!ch || this_stk == NULL)
        return __errno_set(EFAULT);

    if (stk_lock()) {
        rs = ch->ch_proto->funcs->listen_func(ch, backlog);
        stk_unlock();
    }
    return rs;
}

/*
 * This routine accepts an incoming connection on a parent chnl <s>, and
 * returns a new child chnl created for the connection.  The parent chnl
 * must be bound to an address with bind(), and enabled for accepting new
 * connections by a call to listen().  The accept() routine dequeues the
 * first connection and creates a new chnl with the same options as <s>.
 * It blocks the caller until a connection is present, unless the chnl is
 * marked as non-blocking.
 */
int
chnl_accept(int cd, struct sockaddr *sa, socklen_t *addrlen)
{
    struct in_caddr *name = (struct in_caddr *)sa;
    struct chnl *ch       = ch_get(cd);
    int ncd               = -1;

    if (!ch || this_stk == NULL)
        return __errno_set(EFAULT);

    if (stk_lock()) {
        ncd = ch->ch_proto->funcs->accept_func(ch, name, (int *)addrlen);
        stk_unlock();
    }

    return ncd;
}

/*
 * This routine gets the current name for the specified chnl.
 *
 * @param ch
 *   Channel descriptor.
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
 *   OK or ERROR.
 */
int
chnl_getchnlname(int cd, struct sockaddr *sa, socklen_t *namelen)
{
    struct chnl *ch       = ch_get(cd);
    struct in_caddr *name = (struct in_caddr *)sa;

    if (!ch || this_stk == NULL || (name == NULL) || (namelen == NULL) ||
        (*namelen > (int)sizeof(struct in_caddr)))
        return __errno_set(EFAULT);

    if (stk_lock()) {
        /* POSIX says: "If the actual length of the address is greater than the
         * length of the supplied sockaddr structure, the stored address shall be
         * truncated."
         */
        *namelen = CNE_MIN(*namelen, CIN_LEN(&ch->ch_pcb->key.laddr));
        memcpy(name, &ch->ch_pcb->key.laddr, *namelen);

        stk_unlock();
    }

    return 0;
}

/*
 * This routine gets the name of the peer connected to the specified chnl.
 *
 * @param ch
 *   Channel descriptor.
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
 *   OK or ERROR.
 */
int
chnl_getpeername(int cd, struct sockaddr *sa, socklen_t *namelen)
{
    struct chnl *ch       = ch_get(cd);
    struct in_caddr *name = (struct in_caddr *)sa;

    if (!ch || this_stk == NULL || (name == NULL) || (namelen == NULL) ||
        (*namelen > (int)sizeof(struct in_caddr)))
        return __errno_set(EFAULT);

    if (stk_lock()) {
        /* POSIX says: "If the actual length of the address is greater than the
         * length of the supplied sockaddr structure, the stored address shall be
         * truncated."
         */
        *namelen = CNE_MIN(*namelen, CIN_LEN(&ch->ch_pcb->key.faddr));
        memcpy(name, &ch->ch_pcb->key.faddr, *namelen);

        stk_unlock();
    }

    return 0;
}

int
chnl_recv(int cd, pktmbuf_t **mbufs, size_t len)
{
    struct chnl *ch = ch_get(cd);
    ssize_t ret;

    if (len == 0)
        return 0;

    if (!ch || this_stk == NULL || !mbufs)
        return __errno_set(EFAULT);

    if (chnl_state_tst(ch, _CHNL_FREE) || chnl_state_tst(ch, _ISCONNECTING)) {
        if (chnl_state_tst(ch, _CHNL_FREE))
            return __errno_set(EPIPE);
        return __errno_set(EINPROGRESS);
    }
    if (!chnl_state_tst(ch, _ISCONNECTED))
        return __errno_set(ENOTCONN);

    __errno_set(0);

    ret = ch->ch_proto->funcs->recv_func(ch, mbufs, len);

    return ret;
}

static int
sendit(int cd, struct sockaddr *sa, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    struct chnl *ch = ch_get(cd);

    if (nb_mbufs == 0)
        return 0;

    if (this_stk == NULL)
        return __errno_set(EINVAL);

    if (!ch || !mbufs)
        return __errno_set(EFAULT);

    if (chnl_state_tst(ch, _CHNL_FREE) || is_set(ch->ch_state, _CANTSENDMORE))
        CNE_ERR_RET_VAL(__errno_set(EPIPE), "State is free or cant sent more\n");

    if (nb_mbufs == 0)
        return 0;

    if (sa) {
        for (int i = 0; i < nb_mbufs; i++) {
            struct cnet_metadata *md;
            struct sockaddr_in *addr;

            if (!mbufs[i])
                CNE_ERR_RET_VAL(__errno_set(EFAULT), "pktmbuf entry is NULL\n");

            md = pktmbuf_metadata(mbufs[i]);
            if (!md)
                CNE_ERR_RET_VAL(__errno_set(EFAULT), "pktmbuf metadata is NULL\n");

            addr = (struct sockaddr_in *)&sa[i];
            if (addr->sin_family == AF_INET) {
                md->faddr.cin_family      = addr->sin_family;
                md->faddr.cin_port        = addr->sin_port;
                md->faddr.cin_len         = sizeof(struct in_addr);
                md->faddr.cin_addr.s_addr = addr->sin_addr.s_addr;
            }
        }
    }

    __errno_set(0);

    return ch->ch_proto->funcs->send_func(ch, mbufs, nb_mbufs);
}

/*
 * This routine transmits data to a previously connected chnl.
 *
 * @param ch
 *   Channel descriptor.
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
int
chnl_send(int cd, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    return sendit(cd, NULL, mbufs, nb_mbufs);
}

int
chnl_sendto(int cd, struct sockaddr *sa, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    if (!sa)
        return __errno_set(EFAULT);

    return sendit(cd, sa, mbufs, nb_mbufs);
}

/*
 * This routine implements the bulk of the bind() function, for all chnl
 * types.  It takes an additional argument pHd, which is a pointer to a
 * 'struct pcb_hd' structure.  There is one 'struct pcb_hd' per protocol, and it
 * contains the next ephemeral port number and the list of active PCBs for
 * the protocol.
 *
 * RETURNS: 0 or -1.
 */
int
chnl_bind_common(struct chnl *ch, struct in_caddr *addr, int32_t len, struct pcb_hd *hd)
{
    struct in_caddr laddr;
    struct in_caddr zero_faddr;
    struct netif *netif;
    struct pcb_key key;

    CNE_SET_USED(len);

    if (!ch || this_stk == NULL)
        return __errno_set(EFAULT);

    /* addr == NULL we return 0 */
    if (!addr) {
        in_caddr_zero(&ch->ch_pcb->key.laddr);
        CNE_ERR_RET_VAL(0, "Address is NULL\n");
    }

    /* Get a local copy of the user struct in_caddr data, as his may be dirty */
    in_caddr_copy(&laddr, addr);

    if (CIN_FAMILY(&laddr) == AF_INET) {
        /* does the requested local address exist? If so get interface */
        if (laddr.cin_addr.s_addr) {
            netif = cnet_netif_match_subnet((struct in_addr *)&laddr.cin_addr);
            if (!netif)
                return __errno_set(EADDRNOTAVAIL);
            ch->ch_pcb->netif = netif;
        }
    }

    in_caddr_zero(&zero_faddr);

    CIN_FAMILY(&zero_faddr) = CIN_FAMILY(&laddr);
    CIN_LEN(&zero_faddr)    = CIN_LEN(&laddr);

    in_caddr_copy(&key.laddr, &laddr);
    in_caddr_copy(&key.faddr, &zero_faddr);

    /* If local port is unassigned, obtain the next ephemeral port value */
    if (CIN_PORT(&laddr) == 0) {
        uint16_t prevPort = hd->local_port;

        /*
         * Check for reuse.  This could happen if someone explicitly bound
         * to a port in the ephemeral range, or if we wrapped.
         */
        do {
            uint16_t eport;

            /* Verify the new port has not wrapped or used all of the ports */
            if (++hd->local_port < _IPPORT_RESERVED)
                hd->local_port = _IPPORT_RESERVED;

            eport = hd->local_port;

            /* Verify we do not wrap around all of the port numbers */
            if (eport == prevPort)
                return __errno_set(EADDRNOTAVAIL);

            CIN_PORT(&key.laddr) = htons(eport);
        } while (cnet_pcb_lookup(hd, &key, BEST_MATCH) != NULL);

        CIN_PORT(&laddr) = CIN_PORT(&key.laddr);
    }
    /* else check for acceptable reuse of local port numbers. */
    else if (ch->ch_options & SO_REUSEPORT) {
        /*
         * SO_REUSEPORT allows a completely duplicate binding, but only if
         * all chnls using the addr/port (including the first) have
         * SO_REUSEPORT set.
         */
        struct pcb_entry *pcb;

        if (((pcb = cnet_pcb_lookup(hd, &key, EXACT_MATCH)) != NULL) &&
            ((pcb->ch->ch_options & SO_REUSEPORT) == 0))
            return __errno_set(EADDRINUSE);
    } else if (ch->ch_options & SO_REUSEADDR) {
        /*
         * SO_REUSEADDR allows two chnls to bind to the same port,
         * but only if they have different addresses.
         */
        if (cnet_pcb_lookup(hd, &key, EXACT_MATCH) != NULL)
            return __errno_set(EADDRINUSE);
    } else if (cnet_pcb_lookup(hd, &key, BEST_MATCH) != NULL)
        return __errno_set(EADDRINUSE);

    /* Setup the local address */
    in_caddr_copy(&ch->ch_pcb->key.laddr, &laddr);

    return 0;
}

/*
 * This routine is the protocol-specific connect() back-end function for
 * datagram chnls.
 */
int
chnl_connect_common(struct chnl *ch, struct in_caddr *to, int32_t tolen __cne_unused)
{
    if (!ch || this_stk == NULL)
        return __errno_set(EFAULT);
    chnl_state_set(ch, _ISCONNECTED);

    if (!ch->ch_pcb->netif)
        ch->ch_pcb->netif = cnet_netif_match_subnet(&to->cin_addr);

    return 0;
}

int
chnl_validate_cb(const char *msg, struct chnl_buf *cb)
{
    pktmbuf_t *m;
    uint32_t tot = 0, num;

    num = vec_len(cb->cb_vec);
    if (num == 0)
        return tot;

    vec_foreach_ptr (m, cb->cb_vec)
        tot += pktmbuf_data_len(m);

    if (tot != cb->cb_cc) {
        cne_printf("   *** chnl_buf (%s) not valid\n", msg);
        if (tot += cb->cb_cc)
            cne_printf("       cb_cc %u != %u total\n", cb->cb_cc, tot);
        return -1;
    }
    return 0;
}

void
chnl_dump(const char *msg, struct chnl *ch)
{
    if (ch) {
        const char *states[] = {"NoState", "Connected", "Connecting", "Disconnecting",
                                "Disconnected"};

        cne_printf("    [yellow]%s[] Channel descriptor: [orange]%d[] state [orange]%s %04x[]\n",
                   msg ? msg : "", ch->ch_cd, states[chnl_state(ch)], ch->ch_state);
        cne_printf("       pcb [cyan]%p[]  proto [cyan]%p[]", ch->ch_pcb, ch->ch_proto);
        cne_printf(" options [cyan]%04x error [cyan]%d[]\n", ch->ch_options, ch->ch_error);
        cne_printf("       RCV buf hiwat [cyan]%d[] lowat [cyan]%d[] cnt "
                   "[cyan]%u[] cc [cyan]%d[]\n",
                   ch->ch_rcv.cb_hiwat, ch->ch_rcv.cb_lowat,
                   ch->ch_rcv.cb_vec ? vec_len(ch->ch_rcv.cb_vec) : 0, ch->ch_rcv.cb_cc);
        chnl_validate_cb("RCV", &ch->ch_rcv);
        cne_printf("       SND buf hiwat [cyan]%d[] lowat [cyan]%d[] cnt "
                   "[cyan]%u[] cc [cyan]%d[]\n",
                   ch->ch_snd.cb_hiwat, ch->ch_snd.cb_lowat,
                   ch->ch_snd.cb_vec ? vec_len(ch->ch_snd.cb_vec) : 0, ch->ch_snd.cb_cc);
        chnl_validate_cb("SND", &ch->ch_snd);
        cnet_pcb_show(ch->ch_pcb);
    }
}

void
chnl_list(stk_t *stk)
{
    struct cnet *cnet = this_cnet;

    if (!stk)
        stk = this_stk;

    cne_printf("[yellow]CHNL[]: [skyblue]%s[]\n", stk->name);
    for (int i = 0; i < uid_max_ids(cnet->chnl_uids); i++) {
        if (uid_test(cnet->chnl_uids, i)) {
            struct chnl *ch = cnet->chnl_descriptors[i];

            if (stk->idx == ch->stk_id)
                chnl_dump(NULL, ch);
        }
    }
}

/*
 * This is a protocol back-end routine for operations that don't need to do
 * any further work.
 *
 * RETURNS: 0.
 */
int
chnl_OK(struct chnl *ch __cne_unused)
{
    return 0;
}
