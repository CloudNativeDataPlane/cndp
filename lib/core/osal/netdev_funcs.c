/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

// IWYU pragma: no_include <asm/int-ll64.h>

#include <unistd.h>            // for close
#include <limits.h>            // for SCHAR_MAX
#include <string.h>            // for memcpy, memset
#include <netinet/in.h>        // for IPPROTO_IP
#include <net/if.h>            // for ifreq, IFF_PROMISC, IFF_UP, IF_NAMESIZE
#include <linux/if.h>          // for ifr_name, ifr_flags, ifr_data, ifr_hwaddr
#include <sys/socket.h>        // for socket, SOCK_DGRAM, AF_INET, PF_INET
#include <sys/ioctl.h>         // for ioctl
#include <bsd/string.h>        // for strlcpy
#include <errno.h>             // for errno
#include <net/ethernet.h>
#include <linux/ethtool.h>        // for ethtool_link_settings, ethtool_cmd, ETHT...
#include <linux/sockios.h>        // for SIOCETHTOOL, SIOCGIFFLAGS, SIOCGIFHWADDR

#include "netdev_funcs.h"

struct ether_addr;

int
netdev_change_flags(const char *if_name, uint32_t flags, uint32_t mask)
{
    struct ifreq ifr;
    int ret = 0;
    int s;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -errno;

    strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        ret = -errno;
        goto out;
    }
    ifr.ifr_flags &= mask;
    ifr.ifr_flags |= flags;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        ret = -errno;
        goto out;
    }
out:
    close(s);
    return ret;
}

int
netdev_promiscuous_enable(const char *if_name)
{
    return netdev_change_flags(if_name, IFF_PROMISC, ~0);
}

int
netdev_promiscuous_disable(const char *if_name)
{
    return netdev_change_flags(if_name, 0, ~IFF_PROMISC);
}

int
netdev_promiscuous_get(const char *if_name)
{
    struct ifreq ifr;
    int s;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -errno;

    strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        close(s);
        return -errno;
    }

    close(s);

    return (ifr.ifr_flags & IFF_PROMISC) ? 1 : 0;
}

int
netdev_set_link_up(const char *if_name)
{
    return netdev_change_flags(if_name, IFF_UP, ~0);
}

int
netdev_set_link_down(const char *if_name)
{
    return netdev_change_flags(if_name, 0, ~IFF_UP);
}

int
netdev_get_mac_addr(const char *ifname, struct ether_addr *eth_addr)
{
    struct ifreq ifr;
    int fd;

    if (!ifname || ifname[0] == '\0' || !eth_addr)
        return -errno;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0)
        return -errno;

    /* Grab the if_index and mac address values */
    memset(&ifr, 0, sizeof(struct ifreq));

    strlcpy(ifr.ifr_name, ifname, IF_NAMESIZE);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
        memcpy(eth_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    close(fd);

    return 0;
}

int
netdev_get_link(const char *ifname, struct netdev_link *link)
{
    struct {
        struct ethtool_link_settings settings;
        __u32 link_mode_data[3 * SCHAR_MAX];
    } eth_cmd;
    struct ifreq ifr;
    int fd, ret;

    if (!ifname || !link)
        return -1;

    memset(link, 0, sizeof(struct netdev_link));
    memset(&eth_cmd, 0, sizeof(eth_cmd));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    eth_cmd.settings.cmd = ETHTOOL_GLINKSETTINGS;
    ifr.ifr_data         = (void *)&eth_cmd.settings;
    strlcpy(ifr.ifr_name, ifname, IF_NAMESIZE);
    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ret < 0) {

        /* users should always try
         * %ETHTOOL_GLINKSETTINGS first, and if it fails with -ENOTSUPP stick
         * only to %ETHTOOL_GSET and %ETHTOOL_SSET consistently. If it
         * succeeds, then users should stick to %ETHTOOL_GLINKSETTINGS and
         * %ETHTOOL_SLINKSETTINGS (which would support drivers implementing
         * either %ethtool_cmd or %ethtool_link_settings).
         */
        struct ethtool_cmd eth_settings;
        ret              = 0;
        eth_settings.cmd = ETHTOOL_GSET;
        ifr.ifr_data     = (void *)&eth_settings;
        ret              = ioctl(fd, SIOCETHTOOL, &ifr);
        if (ret)
            goto err;
        if (eth_cmd.settings.speed != 0 && eth_cmd.settings.speed != UINT32_MAX) {
            link->link_speed   = eth_settings.speed;
            link->link_duplex  = eth_settings.duplex;
            link->link_autoneg = eth_settings.autoneg;
            /* get link status */
            if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
                goto err;
            link->link_status = ((ifr.ifr_flags & IFF_UP) ? 1 : 0);
        }
    } else {
        eth_cmd.settings.link_mode_masks_nwords *= -1;
        ret = ioctl(fd, SIOCETHTOOL, &ifr);
        if (ret < 0)
            goto err;
        if (eth_cmd.settings.speed != 0 && eth_cmd.settings.speed != UINT32_MAX) {
            link->link_speed   = eth_cmd.settings.speed;
            link->link_duplex  = eth_cmd.settings.duplex;
            link->link_autoneg = eth_cmd.settings.autoneg;
            /* get link status */
            if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
                goto err;
            link->link_status = ((ifr.ifr_flags & IFF_UP) ? 1 : 0);
        }
    }

    close(fd);
    return 0;
err:
    close(fd);
    return -errno;
}

static int
get_device_offloads(const char *ifname, int cmd, uint32_t *value)
{
    struct ifreq ifr;
    int fd;
    struct ethtool_value eth_value;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(struct ifreq));
    strlcpy(ifr.ifr_name, ifname, IF_NAMESIZE);

    eth_value.cmd = cmd;
    ifr.ifr_data  = (void *)&eth_value;
    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
        goto err;

    *value = eth_value.data;

    close(fd);
    return 0;

err:
    close(fd);
    return -errno;
}

int
netdev_get_offloads(const char *ifname, struct offloads *off)
{
    int ret = -1;

    if (!ifname || ifname[0] == '\0' || !off)
        return -errno;

    ret = get_device_offloads(ifname, ETHTOOL_GTXCSUM, &off->tx_checksum_offload);
    if (ret == 0)
        ret = get_device_offloads(ifname, ETHTOOL_GRXCSUM, &off->rx_checksum_offload);

    return ret;
}

int
netdev_get_channels(const char *ifname)
{
    struct ifreq ifr;
    int fd;
    struct ethtool_channels eth_channels;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(struct ifreq));
    strlcpy(ifr.ifr_name, ifname, IF_NAMESIZE);

    eth_channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data     = (void *)&eth_channels;
    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
        goto err;

    close(fd);
    return eth_channels.combined_count;

err:
    close(fd);
    return -errno;
}

int
netdev_set_channels(const char *ifname, uint32_t count)
{
    struct ifreq ifr;
    int fd;
    struct ethtool_channels eth_channels;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(struct ifreq));
    strlcpy(ifr.ifr_name, ifname, IF_NAMESIZE);

    eth_channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data     = (void *)&eth_channels;
    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
        goto err;

    if (eth_channels.combined_count != count) {
        eth_channels.cmd = ETHTOOL_SCHANNELS;
        eth_channels.combined_count = count;
        if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
            goto err;
    }

    close(fd);
    return 0;

err:
    close(fd);
    return -errno;
}

int
netdev_get_ring_params(const char *ifname, uint32_t *rx_nb_desc, uint32_t *tx_nb_desc)
{
    struct ethtool_ringparam eth_ringparam;
    struct ifreq ifr;
    int fd = -1;

    if (!rx_nb_desc && !tx_nb_desc)
        return -EINVAL;

    if (!ifname || ifname[0] == '\0')
        return -EINVAL;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(struct ifreq));
    strlcpy(ifr.ifr_name, ifname, IF_NAMESIZE);

    eth_ringparam.cmd = ETHTOOL_GRINGPARAM;
    ifr.ifr_data      = (void *)&eth_ringparam;
    if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
        goto err;

    if (rx_nb_desc)
        *rx_nb_desc = eth_ringparam.rx_pending;
    if (tx_nb_desc)
        *tx_nb_desc = eth_ringparam.tx_pending;

    close(fd);
    return 0;

err:
    close(fd);
    return -errno;
}
