/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */

#include <stddef.h>        // for NULL
#include <sys/types.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <bsd/string.h>

#include <cne_stdio.h>
#include <cne_log.h>
#include <net/cne_ether.h>

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
tap_ioctl(struct tap_info *ti, unsigned long request, struct ifreq *ifr, int set)
{
    if (!ti || !ifr)
        CNE_ERR_RET_VAL(-EINVAL,
                        "[cyan]struct tap_info pointer or struct ifreg pointer is NULL[]\n");

    if (ti->sock >= 0) {
        short req_flags = ifr->ifr_flags;

        strlcpy(ifr->ifr_name, ti->name, sizeof(ifr->ifr_name));

        switch (request) {
        case SIOCSIFFLAGS:
            /* fetch current flags to leave other flags untouched */
            if (ioctl(ti->sock, SIOCGIFFLAGS, ifr) < 0)
                CNE_ERR_RET_VAL(
                    -errno, "[orange]%s[] - [cyan]Unable to get [orange]%s[cyan]: [orange]%s[]\n",
                    ti->name, tap_ioctl_req2str(request), strerror(errno));
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
            CNE_ERR_RET_VAL(-EINVAL, "[cyan]ioctl([orange]%s, %s[cyan]) called with wrong arg[]\n",
                            tap_ioctl_req2str(request), ti->name);
        }
        if (ioctl(ti->sock, request, ifr) < 0)
            CNE_ERR_RET_VAL(-errno, "[cyan]Unable to support request[]: [orange]%s[]\n",
                            strerror(errno));
    }
    return 0;
}

static int
tap_link_set_down(struct tap_info *ti)
{
    struct ifreq ifr = {.ifr_flags = IFF_UP};

    return tap_ioctl(ti, SIOCSIFFLAGS, &ifr, 0);
}

static int
tap_link_set_up(struct tap_info *ti)
{
    struct ifreq ifr = {.ifr_flags = IFF_UP};

    return tap_ioctl(ti, SIOCSIFFLAGS, &ifr, 1);
}

struct tap_info *
tun_alloc(int tun_flags, const char *if_name)
{
    struct tap_info *ti     = NULL;
    struct ifreq ifr        = {0};
    char name[IFNAMSIZ + 1] = {0};
    int flags;

    if (!if_name)
        if_name = name;

    ti = calloc(1, sizeof(struct tap_info));
    if (!ti)
        return NULL;

    ti->flags    = tun_flags;
    ti->if_index = -1;
    ti->fd       = -1;
    ti->sock     = -1;

    ti->fd = open(TUN_TAP_DEV_PATH, O_RDWR);
    if (ti->fd < 0)
        CNE_ERR_GOTO(error, "[cyan]Unable to open [orange]%s [cyan]interface[]\n",
                     TUN_TAP_DEV_PATH);

    ifr.ifr_flags = ti->flags;

#ifdef IFF_MULTI_QUEUE
    if (ti->flags & IFF_MULTI_QUEUE) {
        /* Grab the TUN features to verify we can work multi-queue */
        if (ioctl(ti->fd, TUNGETFEATURES, &ti->features) < 0)
            CNE_ERR_GOTO(error, "[cyan]unable to get TUN/TAP features[]\n");

        if (ti->features & IFF_MULTI_QUEUE)
            ifr.ifr_flags |= IFF_MULTI_QUEUE;
        else
            ifr.ifr_flags |= IFF_ONE_QUEUE;
    } else
        ifr.ifr_flags |= IFF_ONE_QUEUE;
#else
    ifr.ifr_flags |= IFF_ONE_QUEUE;
#endif

    strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

    /* Set the TUN/TAP configuration and set the name if needed */
    if (ioctl(ti->fd, TUNSETIFF, (void *)&ifr) < 0)
        CNE_ERR_GOTO(error, "[cyan]Unable to set TUNSETIFF for [orange]%s[]: [orange]%s[]\n",
                     ifr.ifr_name, strerror(errno));
    /*
     * Name passed to kernel might be wildcard like tun%d
     * and need to find the resulting device name.
     */
    strlcpy(ti->name, ifr.ifr_name, sizeof(ifr.ifr_name));

    flags = fcntl(ti->fd, F_GETFL);
    if (flags == -1)
        CNE_ERR_GOTO(error, "[cyan]Unable to get [orange]%s [cyan]current flags[]\n", ifr.ifr_name);

    /* Always set the file descriptor to non-blocking */
    flags |= O_NONBLOCK;
    if (fcntl(ti->fd, F_SETFL, flags) < 0)
        CNE_ERR_GOTO(error, "[cyan]Unable to set [orange]%s [cyan]to nonblocking[]: [orange]%s[]\n",
                     ifr.ifr_name, strerror(errno));

    if (ti->flags & IFF_TAP) {
        if (ioctl(ti->fd, SIOCGIFHWADDR, &ifr) < 0)
            CNE_ERR_GOTO(error, "[cyan]Unable to get TAP MAC address:[orange]%s[]\n",
                         strerror(errno));

        memcpy(&ti->eth_addr, ifr.ifr_hwaddr.sa_data, sizeof(struct ether_addr));
    }

    ti->if_index = if_nametoindex(ti->name);
    if (!ti->if_index)
        CNE_ERR_GOTO(error, "[cyan]Unable to get ifindex for [orange]%s[]\n", ti->name);

    ti->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ti->sock == -1)
        CNE_ERR_GOTO(error,
                     "[orange]%s [cyan]Unable to get a socket for management[]: [orange]%s[]\n",
                     ti->name, strerror(errno));

    if (tap_link_set_up(ti) < 0)
        CNE_ERR_GOTO(error, "[cyan]Unable to set [orange]%s [cyan]interface up[]\n", ti->name);

    return ti;

error:
    if (tun_free(ti) < 0)
        CNE_ERR("[cyan]Unable to free tun/tap interface[]\n");

    return NULL;
}

int
tun_free(struct tap_info *ti)
{
    if (ti) {
        if (tap_link_set_down(ti) < 0)
            CNE_ERR_RET("[cyan]Unable to set [orange]%s [cyan]interface down[]\n", ti->name);

        if (ti->fd >= 0)
            close(ti->fd);
        if (ti->sock != -1)
            close(ti->sock);
        free(ti);
    }
    return 0;
}

int
tun_dump(const char *msg, struct tap_info *ti)
{
    char mac_str[32];

    if (!ti)
        return -1;

    if (msg && strlen(msg))
        cne_printf("[green]%-8s[] ", msg);

    if (ti->flags & IFF_TAP)
        cne_printf("[cyan]Type[]:[yellow]%-4s[] - '[orange]%-12s[]' [cyan]fd [orange]%d "
                   "[cyan]MAC Address[]: [orange]%s[]",
                   (ti->flags & IFF_TAP) ? "TAP" : "TUN", ti->name, ti->fd,
                   inet_mtoa(mac_str, sizeof(mac_str), &ti->eth_addr));
    else
        cne_printf("[cyan]Type[]:[yellow]%-4s[] - '[orange]%-12s[]' [cyan]fd [orange]%d[]",
                   (ti->flags & IFF_TAP) ? "TAP" : "TUN", ti->name, ti->fd);

#ifdef IFF_MULTI_QUEUE
    if (ti->features & IFF_MULTI_QUEUE)
        cne_printf(" [cyan]Multi-queue[]: [orange]%d [cyan]queues[]\n", CNE_TAP_MAX_QUEUES);
    else
#endif
        cne_printf("  [cyan]Multi-queue[]: [orange]1 [cyan]queue[]\n");
    return 0;
}
