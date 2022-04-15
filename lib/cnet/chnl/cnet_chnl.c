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
#include <cnet_chnl.h>
#include <errno.h>         // for EFAULT, EINVAL, EADDRINUSE, EADDRNOTAVAIL
#include <string.h>        // for memcpy, memset, strerror
#include <cnet_meta.h>

#include "cne_common.h"        // for __cne_unused, CNE_MIN, CNE_SET_USED
#include "cne_log.h"           // for cne_panic
#include "cnet_const.h"        // for __errno_set, chnl_unlock, chnl_lock, is_set
#include "cnet_reg.h"
#include "cnet_ipv4.h"           // for TOS_DEFAULT, TTL_DEFAULT
#include "cnet_protosw.h"        // for protosw_entry, proto_funcs, cnet_protosw_find
#include "mempool.h"             // for mempool_cfg, mempool_create, mempool_get
#include "pktmbuf.h"             // for pktmbuf_data_len, pktmbuf_t, ...

static void
_chnl_buf_init(mempool_t *mp, void *opaque_arg __cne_unused, void *_b, unsigned i __cne_unused)
{
    pthread_mutexattr_t attr;
    struct chnl *ch = _b;

    memset(ch, 0, mempool_objsz(mp));

    ch->ch_state = _CHNL_FREE;

    if (pthread_mutexattr_init(&attr))
        CNE_RET("mutex attribute init failed\n");
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
        pthread_mutexattr_destroy(&attr);
        CNE_RET("mutex attribute set type failed\n");
    }

    if (pthread_mutex_init(&ch->ch_rcv.mutex, &attr)) {
        pthread_mutexattr_destroy(&attr);
        CNE_RET("mutex init(ch_rcv) failed\n");
    }
    if (pthread_mutex_init(&ch->ch_snd.mutex, &attr)) {
        pthread_mutexattr_destroy(&attr);
        CNE_RET("mutex init(ch_snd) failed\n");
    }
    pthread_mutexattr_destroy(&attr);
    if (pthread_cond_init(&ch->ch_snd.cb_cond, NULL))
        CNE_RET("cond init(ch_snd) failed\n");
    if (pthread_cond_init(&ch->ch_rcv.cb_cond, NULL))
        CNE_RET("cond init(ch_rcv) failed\n");

    ch->ch_rcv.cb_vec = vec_alloc(ch->ch_rcv.cb_vec, CHNL_VEC_SIZE);
    if (ch->ch_rcv.cb_vec == NULL)
        return;

    ch->ch_snd.cb_vec = vec_alloc(ch->ch_snd.cb_vec, CHNL_VEC_SIZE);
    if (ch->ch_snd.cb_vec == NULL)
        vec_free(ch->ch_rcv.cb_vec);
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

    if (pthread_mutex_lock(&stk->mutex))
        CNE_NULL_RET("Unable to acquire mutex\n");
    if (stk->chnl_objs == NULL) {
        cfg.objcnt     = cnet->num_chnls;
        cfg.objsz      = sizeof(struct chnl);
        cfg.cache_sz   = 64;
        stk->chnl_objs = mempool_create(&cfg);

        if (stk->chnl_objs == NULL) {
            if (pthread_mutex_unlock(&stk->mutex))
                CNE_NULL_RET("Unable to release mutex\n");
            CNE_NULL_RET("Unable to create objpool\n");
        }

        mempool_obj_iter(stk->chnl_objs, _chnl_buf_init, NULL);
    }
    if (pthread_mutex_unlock(&stk->mutex))
        CNE_NULL_RET("Unable to release mutex\n");

    if (mempool_get(stk->chnl_objs, (void *)&ch) < 0)
        CNE_NULL_RET("Allocate for chnl_obj failed\n");
    ch->ch_state = _NOFDREF;

    ch->initialized = 1;
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
    pthread_mutexattr_t attr;

    if (ch == NULL)
        CNE_RET("Channel Pointer is NULL\n");

    if (is_set(ch->ch_state, _CHNL_FREE))
        CNE_RET("chnl is already free!");

    if (pthread_mutexattr_init(&attr))
        CNE_RET("mutex attribute init failed\n");
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
        pthread_mutexattr_destroy(&attr);
        CNE_RET("mutex attribute set type failed\n");
    }

    if (pthread_mutex_init(&ch->ch_rcv.mutex, &attr)) {
        pthread_mutexattr_destroy(&attr);
        CNE_RET("mutex init(ch_rcv) failed\n");
    }
    if (pthread_mutex_init(&ch->ch_snd.mutex, &attr)) {
        pthread_mutexattr_destroy(&attr);
        CNE_RET("mutex init(ch_snd) failed\n");
    }
    pthread_mutexattr_destroy(&attr);
    if (pthread_cond_init(&ch->ch_snd.cb_cond, NULL))
        CNE_RET("cond init(ch_snd) failed\n");
    if (pthread_cond_init(&ch->ch_rcv.cb_cond, NULL))
        CNE_RET("cond init(ch_rcv) failed\n");

    vec_free(ch->ch_rcv.cb_vec);
    vec_free(ch->ch_snd.cb_vec);

    ch->ch_rcv.cb_vec = NULL;
    ch->ch_snd.cb_vec = NULL;

    /* Set chnl structure to the free state */
    ch->ch_state = _CHNL_FREE;
    ch->ch_pcb   = NULL;

    if (pthread_mutex_lock(&stk->mutex))
        CNE_RET("mutex lock failed\n");
    TAILQ_REMOVE(&stk->chnls, ch, ch_entry);
    if (pthread_mutex_unlock(&stk->mutex))
        CNE_RET("mutex unlock failed\n");

    mempool_put(stk->chnl_objs, (void *)ch);
}

/*
 * This routine flushes all queued data in a chnl buffer.
 */
static void
chnl_cbflush(struct chnl_buf *cb)
{
    if (pthread_mutex_lock(&cb->mutex))
        CNE_RET("mutex lock failed\n");

    if (vec_len(cb->cb_vec)) {
        pktmbuf_free_bulk(cb->cb_vec, vec_len(cb->cb_vec));
        vec_set_len(cb->cb_vec, 0);
        cb->cb_cc = 0;
    }

    if (pthread_mutex_unlock(&cb->mutex))
        CNE_RET("Unable to release lock\n");
}

/*
 * This routine is called as the last part of the close() sequence.
 */
void
chnl_cleanup(struct chnl *ch)
{
    if (!ch)
        CNE_RET("Channel NULL\n");

    if (ch->ch_state & _CHNL_FREE)
        CNE_RET("Already free!\n");

    ch->ch_state &= ~_ISCONNECTED;
    ch->ch_state |= _ISDISCONNECTED;

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
}

/*
 * This routine waits on a chnl buffer semaphore, which could mean the caller
 * is waiting for data for a read or space to write data. The CB_WAIT flag is
 * set to indicate to chnl_sbwakeup() when some thead or threads are waiting on
 * the packet buffer semaphore. The chnl_sbwakeup() will issue a flush to
 * awaken all threads waiting on the chnl buffer semaphore. Each thread will
 * run at some point in the future to determine if its conditions for waiting
 * have been fulfilled.
 *
 * The routine checks the state of the chnl structure in an attempt to detect
 * when a chnl has been closed or reused while the thread was asleep. A error
 * code is returned when this state has been detected.
 */
int
chnl_cb_wait(struct chnl *ch, struct chnl_buf *cb)
{
    int rc;

    if (!ch || !cb)
        CNE_ERR_RET_VAL(__errno_set(EINVAL), "ch or cb is NULL\n");

    cb->cb_flags |= CB_WAIT;

    rc = pthread_cond_wait(&cb->cb_cond, &cb->mutex);
    if (rc != 0) {
        if (rc != EWOULDBLOCK)
            CNE_ERR_RET_VAL(__errno_set(EIO), "pthread_cond_wait(): %s\n", strerror(rc));
        else
            CNE_ERR_RET_VAL(__errno_set(ETIMEDOUT), "Would block error\n");
    }

    if (is_set(ch->ch_state, _CHNL_FREE))
        CNE_ERR_RET_VAL(__errno_set(EPIPE), "Channel is closed\n");

    CNE_INFO("Exit rc %d\n", rc);
    return rc;
}

/*
 * The routine wakes up threads waiting on a read, write and/or select states to
 * change allowing the waiting threads to be awoken. The waiting threads are on
 * the chnl buffer condition variable for reading data or space to write
 * data in/out of the chnl buffer.
 *
 * If the _CB_WAIT flag is set then a signal is issued to wakeup a thread
 * on the condition variable.
 *
 * The CB_SEL bit will be used to flag threads are waiting on the 'select'
 * system call. If the CB_SEL is set then broadcast() signal to
 * wakeup all selecting threads.
 */
void
chnl_cb_wakeup(struct chnl *ch, struct chnl_buf *cb, int wakeup_type)
{
    if (cb->cb_flags & CB_WAIT) {
        cb->cb_flags &= ~CB_WAIT;

        if (pthread_cond_signal(&cb->cb_cond))
            cne_panic("pthread_cond_signal() failed\n");
    }

    if (cb->cb_flags & CB_SEL) {
        if (wakeup_type == _SELREAD) {
            if (!ch_readable(ch))
                return;
        } else if (!ch_writeable(ch))
            return;
    }
}

size_t
chnl_copy_data(pktmbuf_t **to, pktmbuf_t **from, int len)
{
    pktmbuf_t *m;
    size_t bytes = 0;

    if (!to || !from || len == 0)
        return 0;

    vec_foreach_ptr (m, from) {
        if (vec_full(to))
            break;
        bytes += pktmbuf_data_len(m);

        vec_add(to, m);
    }

    len = vec_len(from) - vec_len(to);
    memmove(from, &from[vec_len(to)], len * sizeof(char *));
    vec_set_len(from, len);

    return bytes;
}

/*
 * This routine opens a chnl and returns a chnl descriptor.
 * The chnl descriptor is passed to the other chnl routines to identify the
 * channel to process.
 */
struct chnl *
channel(int domain, int type, int proto, chnl_cb_t cb)
{
    struct chnl *ch;

    if ((ch = __chnl_create(domain, type, proto, NULL)) == NULL)
        CNE_NULL_RET("__chnl_create() failed\n");

    ch->ch_state &= ~_NOFDREF;
    ch->callback = cb;

    return ch;
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
        CNE_NULL_RET("chnl_alloc(%p) failed\n", this_stk);
    }

    /* If this is a raw chnl, register it as IPPROTO_IP, and store the
     * protocol number in the PCB.
     */
    ch->ch_proto = cnet_protosw_find(dom, type, ((type == SOCK_RAW) ? IPPROTO_RAW : pro));
    if (ch->ch_proto == NULL) {
        chnl_cleanup(ch);
        __errno_set(EPROTONOSUPPORT);
        CNE_NULL_RET("ch->ch_proto == NULL\n");
    }

    ch->ch_rcv.cb_lowat = 0;
    ch->ch_rcv.cb_hiwat = 4 * 1024;
    ch->ch_snd.cb_lowat = 0;
    ch->ch_snd.cb_hiwat = 4 * 1024;

    /* Call the protocol Init routine and allocate ch_pcb */
    cnet_assert(ch->ch_proto->funcs != NULL && ch->ch_proto->funcs->channel_func != NULL);

    if (ch->ch_proto->funcs->channel_func(ch, dom, type, pro)) {
        chnl_cleanup(ch);
        __errno_set(ENOBUFS);
        CNE_NULL_RET("channel_func() failed\n");
    }

    /* Should have a new PCB assigned to the chnl now */
    pcb     = ch->ch_pcb;
    pcb->ch = ch;

    ch->ch_rcv.cb_timeo = 0;
    ch->ch_snd.cb_timeo = 0;

    if (ppcb) {
        /* Copy the parent PCB information */
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
    } else {
        /* setup the chnl buffer information obtained from protocol */
        ch->ch_rcv.cb_lowat = ch->ch_snd.cb_lowat = 1;
        ch->ch_rcv.cb_hiwat                       = ch->ch_rcv.cb_size;
        ch->ch_snd.cb_hiwat                       = ch->ch_snd.cb_size;
    }

    pcb->ttl = TTL_DEFAULT;
    pcb->tos = TOS_DEFAULT;

    CIN_FAMILY(&pcb->key.laddr) = CIN_FAMILY(&pcb->key.faddr) = dom;
    CIN_LEN(&pcb->key.laddr) = CIN_LEN(&pcb->key.faddr) = 0;

    if (pthread_mutex_lock(&this_stk->mutex)) {
        chnl_cleanup(ch);
        __errno_set(ENAVAIL);
        CNE_NULL_RET("Unable to acquire mutex\n");
    }
    TAILQ_INSERT_TAIL(&this_stk->chnls, ch, ch_entry);
    if (pthread_mutex_unlock(&this_stk->mutex)) {
        chnl_cleanup(ch);
        __errno_set(ENAVAIL);
        CNE_NULL_RET("Unable to release mutex");
    }

    return ch;
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
chnl_shutdown(struct chnl *ch, int how)
{
    struct protosw_entry *psw;
    int status = 0;

    if (!ch || (how < SHUT_RD) || (how > SHUT_RDWR))
        return __errno_set(EINVAL);

    chnl_lock(ch);

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

    chnl_unlock(ch);

    if (chnl_snd_rcv_more(ch, _CANTRECVMORE | _CANTSENDMORE))
        chnl_cleanup(ch);

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
chnl_bind(struct chnl *ch, struct sockaddr *sa, int namelen)
{
    struct in_caddr *name = (struct in_caddr *)sa;
    int rs;

    chnl_lock(ch);

    /* Check that address structure is passed and is not too short.
     * One special case is allowed: a NULL name with a namelen of 0.
     */
    if (((name == NULL) && (namelen != 0)) ||
        ((name != NULL) && (namelen > (int)sizeof(struct sockaddr)))) {
        CNE_ERR("Name Invalid name %p, namelen %d > %ld\n", name, namelen, sizeof(struct in_caddr));
        rs = __errno_set(EINVAL);
        goto leave;
    }

    if ((name != NULL) && (CIN_FAMILY(name) != ch->ch_proto->domain)) {
        CNE_ERR("Error family\n");
        rs = __errno_set(EAFNOSUPPORT);
        goto leave;
    }

    rs = ch->ch_proto->funcs->bind_func(ch, name, namelen);

leave:
    chnl_unlock(ch);
    return rs;
}

/*
 * If <ch> is a stream chnl, this routine establishes a virtual circuit
 * between <ch> and another chnl specified by <name>.  If <ch> is a datagram
 * packet, it permanently specifies the peer to which messages are sent.
 */
int
chnl_connect(struct chnl *ch, struct sockaddr *sa, int namelen)
{
    struct in_caddr *name = (struct in_caddr *)sa;
    int rs                = -1;
    struct protosw_entry *psw;
    struct in_caddr faddr = {0};

    if (!name || (namelen > (int)sizeof(struct in_caddr)) || !ch || !ch->ch_proto) {
        CNE_ERR("Channel name %p or len %d != %ld\n", name, namelen, sizeof(struct in_caddr));
        return __errno_set(EINVAL);
    }

    chnl_lock(ch);

    if (CIN_FAMILY(name) != ch->ch_proto->domain) {
        chnl_unlock(ch);
        CNE_ERR("Channel family does not match %d != %d\n", CIN_FAMILY(name), ch->ch_proto->domain);
        return __errno_set(EAFNOSUPPORT);
    }

    if ((CIN_FAMILY(name) == AF_INET) && (CIN_CADDR(name) == INADDR_ANY)) {
        chnl_unlock(ch);
        CNE_ERR("Channel family does not match %d != %d\n", CIN_FAMILY(name), ch->ch_proto->domain);
        return __errno_set(EADDRNOTAVAIL);
    }

    /* Get a local copy of the user struct in_caddr data, as his may be dirty */
    in_caddr_copy(&faddr, name);

    psw = ch->ch_proto;

    /* If the chnl is not bound, bind it now. */
    if ((CIN_PORT(&ch->ch_pcb->key.laddr) == 0) && (ch->ch_proto->type != SOCK_RAW)) {
        struct in_caddr sa;

        in_caddr_zero(&sa);

        CIN_LEN(&sa)    = CIN_LEN(&faddr);
        CIN_FAMILY(&sa) = CIN_FAMILY(&faddr);

        /* {addr,port} == {INADDR_ANY,0} */

        if (psw->funcs) {
            rs = psw->funcs->bind_func(ch, &sa, CIN_LEN(&sa));
            if (rs) {
                CNE_ERR("Failed bind call\n");
                goto leave;
            }
        }
    }

    in_caddr_copy(&ch->ch_pcb->key.faddr, &faddr);

    if (psw && psw->funcs)
        rs = psw->funcs->connect_func(ch, name, namelen);

leave:
    chnl_unlock(ch);
    return rs;
}

int
chnl_connect2(struct chnl *ch1, struct chnl *ch2)
{
    struct protosw_entry *psw;
    int rs = -1;

    chnl_lock(ch1);
    chnl_lock(ch2);

    psw = ch1->ch_proto;

    if (psw && psw->funcs)
        rs = psw->funcs->connect2_func(ch1, ch2);

    chnl_unlock(ch2);
    chnl_unlock(ch1);

    return rs;
}

/*
 * This routine enables connections to a stream chnl. After enabling
 * connections with listen(), connections are actually accepted by accept().
 */
int
chnl_listen(struct chnl *ch, int backlog)
{
    int rs;

    chnl_lock(ch);

    rs = ch->ch_proto->funcs->listen_func(ch, backlog);

    chnl_unlock(ch);
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
struct chnl *
chnl_accept(struct chnl *ch, struct sockaddr *sa, socklen_t *addrlen)
{
    struct in_caddr *name = (struct in_caddr *)sa;
    struct chnl *new_ch;

    chnl_lock(ch);

    new_ch = ch->ch_proto->funcs->accept_func(ch, name, (int *)addrlen);

    chnl_unlock(ch);

    return new_ch;
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
chnl_getchnlname(struct chnl *ch, struct sockaddr *sa, socklen_t *namelen)
{
    struct in_caddr *name = (struct in_caddr *)sa;

    if ((name == NULL) || (namelen == NULL) || (*namelen > (int)sizeof(struct in_caddr)))
        return __errno_set(EFAULT);

    chnl_lock(ch);

    /* POSIX says: "If the actual length of the address is greater than the
     * length of the supplied sockaddr structure, the stored address shall be
     * truncated."
     */
    *namelen = CNE_MIN(*namelen, CIN_LEN(&ch->ch_pcb->key.laddr));
    memcpy(name, &ch->ch_pcb->key.laddr, *namelen);

    chnl_unlock(ch);

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
chnl_getpeername(struct chnl *ch, struct sockaddr *sa, socklen_t *namelen)
{
    struct in_caddr *name = (struct in_caddr *)sa;

    if ((name == NULL) || (namelen == NULL) || (*namelen > (int)sizeof(struct in_caddr)))
        return __errno_set(EFAULT);

    chnl_lock(ch);

    /* POSIX says: "If the actual length of the address is greater than the
     * length of the supplied sockaddr structure, the stored address shall be
     * truncated."
     */
    *namelen = CNE_MIN(*namelen, CIN_LEN(&ch->ch_pcb->key.faddr));
    memcpy(name, &ch->ch_pcb->key.faddr, *namelen);

    chnl_unlock(ch);

    return 0;
}

static int
sendit(struct chnl *ch, struct sockaddr *sa, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    if (is_set(ch->ch_state, (_CANTSENDMORE | _CHNL_FREE))) {
        __errno_set(EPIPE);
        CNE_ERR_RET("State is free or cant sent more\n");
    }

    if (nb_mbufs == 0)
        return 0;

    if (sa) {
        for (int i = 0; i < nb_mbufs; i++) {
            struct cnet_metadata *md = pktmbuf_metadata(mbufs[i]);
            struct sockaddr_in *addr = (struct sockaddr_in *)&sa[i];

            if (addr->sin_family == AF_INET) {
                md->faddr.cin_family      = addr->sin_family;
                md->faddr.cin_port        = addr->sin_port;
                md->faddr.cin_len         = sizeof(struct sockaddr_in);
                md->faddr.cin_addr.s_addr = addr->sin_addr.s_addr;
            }
        }
    }

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
chnl_send(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    return sendit(ch, NULL, mbufs, nb_mbufs);
}

int
chnl_sendto(struct chnl *ch, struct sockaddr *sa, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    if (!ch || !sa || !mbufs)
        return -1;

    return sendit(ch, sa, mbufs, nb_mbufs);
}

int
chnl_fcntl(struct chnl *ch __cne_unused, int cmd __cne_unused, ...)
{
    return 0;
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

    /* addr == NULL : unbind the chnl and return 0. */
    if (!addr) {
        in_caddr_zero(&ch->ch_pcb->key.laddr);
        CNE_ERR("Address is NULL\n");
        return 0;
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
        uint16_t prevPort = hd->lport;

        /*
         * Check for reuse.  This could happen if someone explicitly bound
         * to a port in the ephemeral range, or if we wrapped.
         */
        do {
            uint16_t eport;

            /* Verify the new port has not wrapped or used all of the ports */
            if (++hd->lport < _IPPORT_RESERVED)
                hd->lport = _IPPORT_RESERVED;

            eport = hd->lport;

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
    ch->ch_state |= _ISCONNECTED;

    if (!ch->ch_pcb->netif)
        ch->ch_pcb->netif = cnet_netif_match_subnet(&to->cin_addr);

    return 0;
}

int
chnl_connect2_common(struct chnl *ch1, struct chnl *ch2)
{
    ch1->ch_state |= _ISCONNECTED;
    ch2->ch_state |= _ISCONNECTED;

    if (!ch1->ch_pcb->netif) {
        struct in_addr *p = (struct in_addr *)&(ch1->ch_pcb->key.laddr.cin_addr);

        ch1->ch_pcb->netif = cnet_netif_match_subnet(p);
        ch2->ch_pcb->netif = ch1->ch_pcb->netif;
        return 0;
    }

    return -1;
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
chnl_list(stk_t *stk)
{
    struct chnl *ch;

    if (!stk)
        stk = this_stk;

    cne_printf("[yellow]CHNL[]: [skyblue]%s[]\n", stk->name);
    TAILQ_FOREACH (ch, &stk->chnls, ch_entry) {
        cne_printf("  Channel %p\n", ch);
        cne_printf("    pcb %p  proto %p\n", ch->ch_pcb, ch->ch_proto);
        cne_printf("    RCV buf flags %04x hiwat %d lowat %d cnt %u cc %d\n", ch->ch_rcv.cb_flags,
                   ch->ch_rcv.cb_hiwat, ch->ch_rcv.cb_lowat,
                   ch->ch_rcv.cb_vec ? vec_len(ch->ch_rcv.cb_vec) : 0, ch->ch_rcv.cb_cc);
        chnl_validate_cb("RCV", &ch->ch_rcv);
        cne_printf("    SND buf flags %04x hiwat %d lowat %d cnt %u cc %d\n", ch->ch_snd.cb_flags,
                   ch->ch_snd.cb_hiwat, ch->ch_snd.cb_lowat,
                   ch->ch_snd.cb_vec ? vec_len(ch->ch_snd.cb_vec) : 0, ch->ch_snd.cb_cc);
        chnl_validate_cb("SND", &ch->ch_snd);
        cne_printf("    Callback count %'ld\n", ch->callback_cnt);
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

/*
 * This is a protocol back-end routine for operations that don't need to do
 * any further work.
 *
 * RETURNS: NULL.
 */
struct chnl *
chnl_NULL(struct chnl *ch __cne_unused)
{
    return NULL;
}

/*
 * This is a protocol back-end routine for operations that are not supported
 * by the protocol.
 *
 * Set the Operation not support in errno and return -1.
 *
 * RETURNS: -1.
 */
int
chnl_ERROR(struct chnl *ch __cne_unused)
{
    return __errno_set(EOPNOTSUPP);
}
