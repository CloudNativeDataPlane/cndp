/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_STK_H
#define __CNET_STK_H

/**
 * @file
 * CNET Stack instance routines and constants.
 */

#include <sys/queue.h>         // for TAILQ_HEAD
#include <pthread.h>           // for pthread_t, pthread_cond_t, pthread_mutex_t
#include <cne_atomic.h>        // for atomic_fetch_sub, atomic_load
#include <stddef.h>            // for NULL
#include <stdint.h>            // for uint32_t, uint16_t, uint64_t, uint8_t
#include <sys/select.h>        // for fd_set
#include <unistd.h>            // for usleep, pid_t
#include <bsd/sys/bitstring.h>

#include <cne_system.h>        // for cne_get_timer_hz
#include <cne_vec.h>           // for vec_at_index, vec_len
#include <hmap.h>              // for hmap_t
#include <cne_timer.h>

#include "cne_common.h"            // for __cne_cache_aligned
#include "cne_per_thread.h"        // for CNE_PER_THREAD, CNE_DECLARE_PER_THREAD
#include "cnet.h"                  // for cnet, cnet_cfg (ptr only), per_thread_cnet
#include "cnet_const.h"            // for iofunc_t, PROTO_IO_MAX
#include "mempool.h"               // for mempool_t
#include "pktmbuf.h"               // for pktmbuf_alloc, pktmbuf_t

#ifdef __cplusplus
extern "C" {
#endif

struct netlink_info;
struct tcp_stats;

typedef struct stk_s {
    pthread_mutex_t mutex;        /**< Stack Mutex */
    uint16_t idx;                 /**< Index number of stack instance */
    uint16_t lid;                 /**< lcore ID for the stack instance */
    pid_t tid;                    /**< Thread process id */
    char name[32];                /**< Name of the network instance */
    struct cne_graph *graph;      /**< Graph structure pointer for this instance */
    struct cne_node *tcp_tx_node; /**< TX node pointer used for sending packets from TCP */
    bitstr_t *tcbs;               /**< Bitmap of active TCB structures based on mempool index */
    uint32_t tcp_now;             /**< TCP now timer tick on slow timeout */
    uint32_t gflags;              /**< Global flags */
    uint64_t ticks;               /**< Number of ticks from start */
    mempool_t *tcb_objs;          /**< List of free TCB structures */
    mempool_t *seg_objs;          /**< List of free Segment structures */
    mempool_t *pcb_objs;          /**< PCB cnet_objpool pointer */
    mempool_t *chnl_objs;         /**< Channel cnet_objpool pointer */
    struct protosw_entry **protosw_vec; /**< protosw vector entries */
    struct icmp_entry *icmp;            /**< ICMP information */
    struct icmp6_entry *icmp6;          /**< ICMP6 information */
    struct ipv4_entry *ipv4;            /**< IPv4 information */
    struct ipv6_entry *ipv6;            /**< IPv6 information */
    struct tcp_entry *tcp;              /**< TCP information */
    struct raw_entry *raw;              /**< Raw information */
    struct udp_entry *udp;              /**< UDP information */
    struct chnl_optsw **chnlopt;        /**< Channel Option pointers */
    struct cne_timer tcp_timer;         /**< TCP Timer structure */
    struct tcp_stats *tcp_stats;        /**< TCP statistics */
} stk_t __cne_cache_aligned;

CNE_DECLARE_PER_THREAD(stk_t *, stk);
#define this_stk CNE_PER_THREAD(stk)

/* Flags values for stk_entry.gflags */
enum {
    TCP_TIMEOUT_ENABLED    = 0x00000001, /**< Enable TCP Timeouts */
    RFC1323_TSTAMP_ENABLED = 0x00004000, /**< Enable RFC1323 Timestamp */
    RFC1323_SCALE_ENABLED  = 0x00008000, /**< Enable RFC1323 window scaling */
};

static inline uint64_t
clks_to_ns(uint64_t clks)
{
    uint64_t ns = cne_get_timer_hz();

    ns = 1000000000ULL / ((ns == 0) ? 1 : ns); /* nsecs per clk */
    ns *= clks;                                /* nsec per clk times clks */

    return ns;
}

static inline uint32_t
stk_get_timer_ticks(void)
{
    return this_stk->tcp_now;
}

static inline void
stk_set(stk_t *stk)
{
    CNE_PER_THREAD(stk) = stk;
}

static inline stk_t *
stk_get(void)
{
    return CNE_PER_THREAD(stk);
}

static inline stk_t *
cnet_stk_find_by_lcore(uint8_t lid)
{
    struct cnet *cnet = this_cnet;
    stk_t *stk;

    vec_foreach_ptr (stk, cnet->stks) {
        if (stk->lid == lid)
            return stk;
    }
    return NULL;
}

static inline int
stk_lock(void)
{
    stk_t *stk = this_stk;

    if (!stk)
        CNE_ERR_RET_VAL(0, "Stack pointer is NULL\n");

    if (pthread_mutex_lock(&stk->mutex) == 0)
        return 1;

    CNE_ERR_RET_VAL(0, "Unable to lock stk(%s) mutex\n", stk->name);
}

static inline void
stk_unlock(void)
{
    stk_t *stk = this_stk;

    if (!stk)
        CNE_RET("Stack pointer is NULL\n");

    if (pthread_mutex_unlock(&stk->mutex))
        CNE_ERR("Unable to unlock (%s) mutex\n", stk->name);
}

/**
 * @brief Initialize the stack instance.
 *
 * @param cnet
 *   The pointer to the cnet structure.
 * @return
 *   -1 on error or 0 on success.
 */
CNDP_API int cnet_stk_initialize(struct cnet *cnet);

/**
 * @brief Stop the stack instance and free resources.
 *
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_stk_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_STK_H */
