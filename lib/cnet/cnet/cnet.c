/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <execinfo.h>        // for backtrace, backtrace_symbols
#include <signal.h>          // for signal, SIGHUP, SIGINT, SIGPIPE, SIGSEGV
#include <assert.h>          // for assert
#include <unistd.h>          // for getpid, sleep

#include <cne_stdio.h>
#include <cnet.h>
#include <cne_inet.h>        // for inet_mtoa
#include <cnet_reg.h>        // for cnet_register_t, cnet_do_calls, cnet_do_stk...
#include <cne_vec.h>         // for vec_calc_size, vec_max_len
#include <cnet_drv.h>
#include <cnet_stk.h>          // for stk_entry
#include <cnet_const.h>        // for CNET_STOP, CNET_INIT, cnet_assert
#include <errno.h>             // for ENOMEM, errno
#include <stdlib.h>            // for free, abort, exit, malloc, qsort
#include <string.h>            // for memset

#include <cne_log.h>         // for CNE_LOG, CNE_LOG_ERR
#include <cne_ring.h>        // for cne_ring_create
#include <cne_hash.h>
#include <pktdev_api.h>         // for pktdev_port_count
#include <pktdev_core.h>        // for cne_pktdev, pktdev_data
#include <pmd_ring.h>
#include <uid.h>

#include <cnet_route.h>
#include <cnet_route4.h>
#include <cnet_arp.h>            // for
#include <cnet_netif.h>          // for
#include <cnet_netlink.h>        // for

static struct cnet cnet_data, *__cnet;
static pthread_spinlock_t __cnet_lock;

struct cnet *
cnet_get(void)
{
    return __cnet;
}

int
cnet_lock(void)
{
    if (pthread_spin_lock(&__cnet_lock) == 0)
        return 1;

    CNE_ERR_RET_VAL(0, "Unable to lock CNET: %s\n", strerror(errno));
}

void
cnet_unlock(void)
{
    if (pthread_spin_unlock(&__cnet_lock))
        CNE_ERR("Unable to unlock CNET: %s\n", strerror(errno));
}

struct cnet *
cnet_config_create(uint32_t num_chnls, uint32_t num_routes)
{
    struct cnet *cnet = __cnet;

    if (cnet_lock()) {
        if (num_routes)
            num_routes = cne_align32pow2(num_routes);
        if (num_chnls)
            cnet->num_chnls = cne_align32pow2(num_chnls);

        cnet->nb_ports = pktdev_port_count();

        if (cnet_drv_create(cnet) < 0)
            CNE_ERR_GOTO(leave, "Unable to create OSAL\n");

        if (cnet_route4_create(cnet, num_routes, 0) < 0)
            CNE_ERR_GOTO(leave, "Unable to create route\n");

        if (cnet_arp_create(cnet, 0, 0) < 0)
            CNE_ERR_GOTO(leave, "Unable to create netif\n");

        if (cnet_netlink_create(cnet) < 0)
            CNE_ERR_GOTO(leave, "Unable to create netlink\n");

        if (cnet_netif_attach_ports(cnet) < 0)
            CNE_ERR_GOTO(leave, "Unable to create route\n");

        if (cnet_netlink_start())
            CNE_ERR_GOTO(leave, "Unable to start netlink thread\n");

        cnet_unlock();
    }
    return cnet;
leave:
    cnet_unlock();
    cnet_stop();
    return NULL;
}

struct cnet *
cnet_create(void)
{
    return cnet_config_create(0, 0);
}

void
cnet_stop(void)
{
    struct cnet *cnet = this_cnet;

    if (cnet && cnet_lock()) {
        cnet_drv_destroy(cnet);
        cnet_route4_destroy(cnet);
        cnet_arp_destroy(cnet);
        cnet_netlink_destroy(cnet);

        vec_free(cnet->stks);
        vec_free(cnet->drvs);
        vec_free(cnet->netifs);

        if (uid_unregister(cnet->chnl_uids) < 0)
            CNE_ERR("Unable to unregister UID\n");
        vec_free(cnet->chnl_descriptors);

        __cnet = NULL;
        memset(&cnet_data, 0, sizeof(cnet_data));
        cnet_unlock();

        if (pthread_spin_destroy(&__cnet_lock))
            CNE_ERR("Unable to destroy spinlock\n");
    }
}

void
cnet_dump(void)
{
    struct drv_entry *drv;
    struct netif *netif;
    char mac_str[32];
    stk_t *stk;

    cne_printf("[yellow]CNET[]\n");
    vec_foreach_ptr (drv, __cnet->drvs) {
        if (!drv)
            continue;

        netif = drv->netif;
        cne_printf("  [cyan]drv%d[] --> [green]Attach port [magenta]%d [green]to device "
                   "[magenta]eth%d [green]MAC[]=[cyan]%s[] ([yellow]%s[])\n",
                   netif->lpid, 99, netif->lpid, inet_mtoa(mac_str, sizeof(mac_str), &netif->mac),
                   netif->ifname);
    }

    vec_foreach_ptr (stk, __cnet->stks)
        cne_printf("    [cyan]%s [green]on lcore [magenta]%d[]\n", stk->name, stk->lid);
}

CNE_INIT_PRIO(cnet_initialize, STACK)
{
    struct cnet *cnet = &cnet_data;

    memset(cnet, 0, sizeof(struct cnet));

    if (pthread_spin_init(&__cnet_lock, PTHREAD_PROCESS_PRIVATE))
        CNE_RET("Unable to initialize spinlock\n");

    cnet->flags = ((CNET_ENABLE_PUNTING) ? CNET_PUNT_ENABLED : 0);
    cnet->flags |= ((CNET_ENABLE_TCP) ? CNET_TCP_ENABLED : 0);

    cnet->num_chnls = CNET_NUM_CHANNELS;

    cnet->chnl_uids = uid_register("CHNL_UIDs", cnet->num_chnls);
    if (!cnet->chnl_uids)
        CNE_ERR_GOTO(err, "Unable to allocate UID values\n");

    /* Vector of chnl descriptors indexed by chnl UID number */
    cnet->chnl_descriptors = vec_alloc(cnet->chnl_descriptors, cnet->num_chnls);
    if (cnet->chnl_descriptors == NULL)
        CNE_ERR_GOTO(err, "Unable to allocate channel descriptor array\n");

    cnet->stks = vec_alloc(cnet->stks, STK_VEC_COUNT);
    if (!cnet->stks)
        CNE_ERR_GOTO(err, "Unable to allocate stk vector\n");

    cnet->netifs = vec_alloc(cnet->netifs, CNE_MAX_ETHPORTS);
    if (!cnet->netifs)
        CNE_ERR_GOTO(err, "Unable to allocate netif vector\n");

    cnet->drvs = vec_alloc(cnet->drvs, CNE_MAX_ETHPORTS);
    if (!cnet->drvs)
        CNE_ERR_GOTO(err, "Unable to allocate driver vector\n");

    __cnet = cnet;
    return;

err:
    if (uid_unregister(cnet->chnl_uids) < 0)
        CNE_ERR("Unable to unregister UID\n");
    vec_free(cnet->chnl_descriptors);
    vec_free(cnet->netifs);
    vec_free(cnet->drvs);
    vec_free(cnet->stks);

    if (pthread_spin_destroy(&__cnet_lock))
        CNE_ERR("Unable to destroy spinlock\n");

    memset(cnet, 0, sizeof(struct cnet));
}
