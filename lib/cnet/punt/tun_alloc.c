/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

#include <net/cne_ether.h>        // for ether_addr_copy, cne_ether_hdr, ether_ad...
#include <cnet.h>                 // for cnet_add_instance, cnet, per_thread_cnet
#include <cnet_stk.h>             // for proto_in_ifunc
#include <cne_inet.h>             // for inet_ntop4, CIN_ADDR
#include <cnet_drv.h>             // for drv_entry
#include <cnet_route.h>           // for
#include <cnet_arp.h>             // for arp_entry
#include <cnet_netif.h>           // for netif, cnet_ipv4_compare
#include <netinet/in.h>           // for ntohs
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stddef.h>        // for NULL
#include <sys/types.h>
#include <fcntl.h>
#include <bsd/string.h>

#include <cne_graph.h>               // for
#include <cne_graph_worker.h>        // for
#include <cne_common.h>              // for __cne_unused
#include <net/cne_ip.h>              // for cne_ipv4_hdr
#include <cne_log.h>                 // for CNE_LOG, CNE_LOG_DEBUG
#include <cne_vec.h>                 // for vec_len, vec_ptr_at_index, vec_next_mbuf_pre...
#include <cnet_ipv4.h>               // for IPv4_VER_LEN_VALUE
#include <mempool.h>                 // for mempool_t
#include <pktdev.h>                  // for pktdev_rx_burst
#include <pktmbuf.h>                 // for pktmbuf_t, pktmbuf_data_len
#include <pktmbuf_ptype.h>
#include <cne_vec.h>        // for
#include <cnet_fib_info.h>
#include <cnet_eth.h>
#include <net/cne_udp.h>
#include <hexdump.h>

#include "tun_alloc.h"

static const char *
tap_ioctl_req2str(unsigned long request)
{
    switch (request) {
    case SIOCSIFFLAGS:
        return "SIOCSIFFLAGS";
    case SIOCGIFFLAGS:
        return "SIOCGIFFLAGS";
    case SIOCGIFHWADDR:
        return "SIOCGIFHWADDR";
    case SIOCSIFHWADDR:
        return "SIOCSIFHWADDR";
    case SIOCSIFMTU:
        return "SIOCSIFMTU";
    }
    return "UNKNOWN";
}

static int
tap_ioctl(struct tap_info *ti, unsigned long request, struct ifreq *ifr, int set,
          enum ioctl_mode mode)
{
    short req_flags = ifr->ifr_flags;
    int remote      = ti->remote_if_index && (mode == REMOTE_ONLY || mode == LOCAL_AND_REMOTE);

    if (!ti->remote_if_index && mode == REMOTE_ONLY)
        return 0;
    /*
     * If there is a remote netdevice, apply ioctl on it, then apply it on
     * the tap netdevice.
     */
apply:
    if (remote)
        strlcpy(ifr->ifr_name, ti->remote_iface, sizeof(ifr->ifr_name));
    else if (mode == LOCAL_ONLY || mode == LOCAL_AND_REMOTE)
        strlcpy(ifr->ifr_name, ti->tun_name, sizeof(ifr->ifr_name));
    switch (request) {
    case SIOCSIFFLAGS:
        /* fetch current flags to leave other flags untouched */
        if (ioctl(ti->ioctl_sock, SIOCGIFFLAGS, ifr) < 0)
            goto error;
        if (set)
            ifr->ifr_flags |= req_flags;
        else
            ifr->ifr_flags &= ~req_flags;
        break;
    case SIOCGIFFLAGS:
    case SIOCGIFHWADDR:
    case SIOCSIFHWADDR:
    case SIOCSIFMTU:
        break;
    default:
        CNE_WARN("%s: ioctl() called with wrong arg", ti->tun_name);
        return -EINVAL;
    }
    if (ioctl(ti->ioctl_sock, request, ifr) < 0)
        goto error;
    if (remote-- && mode == LOCAL_AND_REMOTE)
        goto apply;
    return 0;

error:
    CNE_WARN("%s(%s) failed: %s(%d)", ifr->ifr_name, tap_ioctl_req2str(request), strerror(errno),
             errno);
    return -errno;
}

static int
tap_link_set_down(struct tap_info *ti)
{
    struct ifreq ifr = {.ifr_flags = IFF_UP};

    return tap_ioctl(ti, SIOCSIFFLAGS, &ifr, 0, LOCAL_ONLY);
}

static int
tap_link_set_up(struct tap_info *ti)
{
    struct ifreq ifr = {.ifr_flags = IFF_UP};

    return tap_ioctl(ti, SIOCSIFFLAGS, &ifr, 1, LOCAL_ONLY);
}

/**
 * Tun/Tap allocation routine
 *
 * @param ctx
 *   The node context pointer.
 * @param[in] tun_name
 *   Pointer to the TUN device name.
 * @param len
 *   The length of the tun_name buffer.
 * @param[in] is_keepalive
 *   Keepalive flag
 * @return
 *   -1 on failure, fd on success
 */
struct tap_info *
tun_alloc(int tun_flags, const char *if_name)
{
    struct tap_info *ti = NULL;
    struct ifreq ifr    = {0};
    char name[IFNAMSIZ] = {0};
    int flags;

    if (!if_name)
        if_name = name;

    ti = calloc(1, sizeof(struct tap_info));
    if (!ti)
        return NULL;
    ti->tun_fd     = -1;
    ti->ioctl_sock = -1;
    ti->flags      = tun_flags;

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     *        IFF_MULTI_QUEUE - Create a queue of multiqueue device, TBD
     */
    ifr.ifr_flags = ((tun_flags & TAP_DEVICE_TYPE) ? IFF_TAP : IFF_TUN) | IFF_NO_PI;
    strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

    ti->tun_fd = open(TUN_TAP_DEV_PATH, O_RDWR);
    if (ti->tun_fd < 0)
        CNE_ERR_GOTO(error, "[magenta]Unable to open [orange]%s [magenta]interface[]\n",
                     TUN_TAP_DEV_PATH);

#ifdef IFF_MULTI_QUEUE
    /* Grab the TUN features to verify we can work multi-queue */
    if (ioctl(ti->tun_fd, TUNGETFEATURES, &ti->features) < 0)
        CNE_ERR_GOTO(error, "[magenta]unable to get TUN/TAP features[]\n");

    if (ti->features & IFF_MULTI_QUEUE)
        ifr.ifr_flags |= IFF_MULTI_QUEUE;
    else
#endif
        ifr.ifr_flags |= IFF_ONE_QUEUE;

    /* Set the TUN/TAP configuration and set the name if needed */
    if (ioctl(ti->tun_fd, TUNSETIFF, (void *)&ifr) < 0)
        CNE_ERR_GOTO(error, "[magenta]Unable to set TUNSETIFF for [orange]%s[]: [orange]%s[]\n",
                     ifr.ifr_name, strerror(errno));

    /*
     * Name passed to kernel might be wildcard like dtun%d
     * and need to find the resulting device.
     */
    strlcpy(ti->tun_name, ifr.ifr_name, sizeof(ifr.ifr_name));

    if (ti->flags & TAP_KEEP_ALIVE) {
        /*
         * Detach the TUN/TAP keep-alive queue
         * to avoid traffic through it
         */
        ifr.ifr_flags = IFF_DETACH_QUEUE;
        if (ioctl(ti->tun_fd, TUNSETQUEUE, (void *)&ifr) < 0)
            CNE_ERR_GOTO(
                error,
                "[magenta]Unable to detach keep-alive queue for [orange]%s[]: [orange]%s[]\n",
                ifr.ifr_name, strerror(errno));
    }

    flags = fcntl(ti->tun_fd, F_GETFL);
    if (flags == -1)
        CNE_ERR_GOTO(error, "[magenta]Unable to get [orange]%s [magenta]current flags[]\n",
                     ifr.ifr_name);

    /* Always set the file descriptor to non-blocking */
    flags |= O_NONBLOCK;
    if (fcntl(ti->tun_fd, F_SETFL, flags) < 0)
        CNE_ERR_GOTO(error,
                     "[magenta]Unable to set [orange]%s [magenta]to nonblocking[]: [orange]%s[]\n",
                     ifr.ifr_name, strerror(errno));

    if (ti->flags & TAP_DEVICE_TYPE) {
        if (ioctl(ti->tun_fd, SIOCGIFHWADDR, &ifr) < 0)
            CNE_ERR_GOTO(error, "[magenta]Unable to get TAP MAC address[]\n");
        memcpy(&ti->eth_addr, ifr.ifr_hwaddr.sa_data, sizeof(struct ether_addr));
    }

    ti->ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ti->ioctl_sock == -1)
        CNE_ERR_GOTO(error,
                     "[orange]%s [magenta]Unable to get a socket for management[]: [orange]%s[]\n",
                     ti->tun_name, strerror(errno));

    if (tap_link_set_up(ti) < 0)
        CNE_ERR_GOTO(error, "[magenta]Unable to set [orange]%s [magenta]interface up[]\n",
                     ti->tun_name);

    return ti;

error:
    if (ti->tun_fd >= 0)
        close(ti->tun_fd);
    if (ti->ioctl_sock != -1)
        close(ti->ioctl_sock);
    free(ti);
    return NULL;
}

int
tun_free(struct tap_info *ti)
{
    if (tap_link_set_down(ti) < 0)
        CNE_ERR_GOTO(error, "Unable to set %s interface up\n", ti->tun_name);

    free(ti);
    return 0;
error:
    return -1;
}

int
tun_dump(const char *msg, struct tap_info *ti)
{
    char mac_str[32];

    if (!ti)
        return -1;

    if (msg && strlen(msg))
        cne_printf("[green]%-8s[] ", msg);

    if (ti->flags & TAP_DEVICE_TYPE)
        cne_printf("[magenta]Type[]:[yellow]%-4s[] - '[orange]%-12s[]' [magenta]fd [orange]%d "
                   "[magenta]MAC "
                   "Address[]: [orange]%s[]",
                   (ti->flags & TAP_DEVICE_TYPE) ? "TAP" : "TUN", ti->tun_name, ti->tun_fd,
                   inet_mtoa(mac_str, sizeof(mac_str), &ti->eth_addr));
    else
        cne_printf("[magenta]Type[]:[yellow]%-4s[] - '[orange]%-12s[]' [magenta]fd [orange]%d[]",
                   (ti->flags & TAP_DEVICE_TYPE) ? "TAP" : "TUN", ti->tun_name, ti->tun_fd);

    if (ti->features & IFF_MULTI_QUEUE) {
        cne_printf(" [magenta]Multi-queue[]: [orange]%d [magenta]queues[]\n", CNE_TAP_MAX_QUEUES);
    } else
        cne_printf("  [magenta]Multi-queue[]: [orange]1 [magenta]queue[]\n");
    return 0;
}
