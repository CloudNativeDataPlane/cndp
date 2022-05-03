/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <cnet.h>           // for cnet, per_thread_cnet, this_cnet, cnet_c...
#include <cne_vec.h>        // for vec_at_index, vec_add, vec_...
#include <cne_stdio.h>
#include <cnet_stk.h>
#include <cne_inet.h>             // for _in_addr
#include <cnet_drv.h>             // for drv_entry
#include <cnet_netif.h>           // for net_addr, netif, cnet_ipv4_ipaddr_delete
#include <cnet_route4.h>          // for cnet_route4_setup
#include <cnet_reg.h>             // for stk_register_t, cnet_do_stk_calls, stk_func...
#include <arpa/inet.h>            // for inet_pton
#include <bsd/sys/queue.h>        // for TAILQ_INIT
#include <endian.h>               // for htobe32, be32toh
#include <errno.h>                // for errno, ENOMEM
#include <stdio.h>                // for printf, snprintf
#include <stdlib.h>               // for NULL, strtoul, calloc, free, qsort
#include <string.h>               // for strcmp, strrchr, memset, strerror
#include <sys/socket.h>           // for AF_INET
#include <bsd/string.h>
#include <pmd_ring.h>
#include <cnet_netlink.h>
#include <cne_mutex_helper.h>

#include <cne_spinlock.h>

static int
_stk_create(struct cnet *cnet)
{
    stk_t *stk;

    if (!cnet)
        CNE_ERR_RET("CNET pointer is not set\n");

    /* allocate the primary stack structure */
    stk = calloc(1, sizeof(stk_t));
    if (!stk)
        CNE_ERR_RET("Unable to allocate stk structure\n");

    if (cnet_lock()) {
        stk_set(stk); /* Set the this_stk pointer for this thread */

        /* Add this stk pointer to the vector list in CNET */
        stk->idx = vec_add(cnet->stks, stk);

        snprintf(stk->name, sizeof(stk->name), "Stk-%d", stk->idx);

        stk->tid = gettid();       /* Grab the process ID */
        stk->lid = cne_lcore_id(); /* setup a set of values for the stack with defaults */

        if (cne_mutex_create(&stk->mutex, PTHREAD_MUTEX_RECURSIVE)) {
            cnet_unlock();
            CNE_ERR_RET("Unable to initialize mutex\n");
        }

        cnet_unlock();
    }
    return 0;
}

int
cnet_stk_initialize(struct cnet *cnet)
{
    stk_t *stk = this_stk;

    if (!stk) {
        if (_stk_create(cnet) < 0)
            CNE_ERR_RET("Stack is not initialized\n");
        stk = this_stk;
        if (!stk)
            CNE_ERR_RET("Stack pointer is not initialized\n");
    }

    /* Wait for each stack instance to initialize in order */
    do {
        sched_yield();
    } while (atomic_load(&this_cnet->stk_order) != stk->idx);

    /* Now call all of the stack init routines in the correct order */
    if (cnet_do_instance_calls(stk, CNET_INIT))
        CNE_ERR_RET("cnet_do_stk_calls() failed for %s\n", stk->name);

    /* Bump the order value to allow other stk instances to run */
    atomic_fetch_add(&this_cnet->stk_order, 1);

    return 0;
}

int
cnet_stk_stop(void)
{
    struct cnet *cnet = this_cnet;
    stk_t *stk        = this_stk;

    if (!cnet || !stk)
        CNE_ERR_RET("CNET or Stk pointer is NULL\n");

    return cnet_do_instance_calls(stk, CNET_STOP);
}

static int
stk_destroy(void *_stk)
{
    stk_t *stk = _stk;

    if (stk) {
        if (cne_mutex_destroy(&stk->mutex))
            CNE_ERR("cne_mutex_destroy(stk->mutex) failed\n");

        vec_free(stk->chnlopt);
        mempool_destroy(stk->chnl_objs);
        memset(stk, 0, sizeof(*stk));
        free(stk);
    }
    CNE_PER_THREAD(stk) = NULL;

    return 0;
}

CNE_INIT_PRIO(cnet_stk_constructor, STACK)
{
    cnet_add_instance("stk", CNET_STK_PRIO, NULL, stk_destroy);
}
