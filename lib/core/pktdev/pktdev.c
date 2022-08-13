/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */
// IWYU pragma: no_forward_declare cne_mempool

#include <stdint.h>            // for uint16_t, uint32_t, uint64_t
#include <inttypes.h>          // for PRIu16
#include <string.h>            // for memset, strcmp, strncmp, strnlen
#include <bsd/string.h>        // for strlcpy
#include <cne_common.h>        // for CNE_MAX_ETHPORTS, __cne_unused
#include <cne_log.h>           // for CNE_LOG_ERR, CNE_LOG, CNE_LOG_INFO
#include <pktmbuf.h>           // for pktmbuf_free, pktmbuf_t
#include <cne_lport.h>         // for lport_stats_t
#include <errno.h>             // for ENOTSUP, EINVAL, ENODEV, ENOMEM
#include <stddef.h>            // for NULL, size_t
#include <stdlib.h>            // for calloc
#include <unistd.h>            // for usleep

#include "pktdev.h"
#include "pktdev_driver.h"        // for pktdev_allocate, pktdev_allocated, pktdev...
#include "pktdev_api.h"           // for pktdev_close, pktdev_close_all, pktdev_get
#include "pktdev_core.h"          // for cne_pktdev, pktdev_data, pktdev_ops, PKTD...

struct cne_pktdev pktdev_devices[CNE_MAX_ETHPORTS];
static struct pktdev_data pktdev_data[CNE_MAX_ETHPORTS];

#define CALL_PMD(fn, ...) (fn) ? (fn)(__VA_ARGS__) : -ENOTSUP

struct cne_pktdev *
pktdev_allocated(const char *name)
{
    unsigned i;

    for (i = 0; i < CNE_MAX_ETHPORTS; i++) {
        if (pktdev_devices[i].state == PKTDEV_UNUSED)
            continue;
        if (pktdev_devices[i].data == NULL)
            continue;
        if (!strcmp(pktdev_devices[i].data->name, name))
            return &pktdev_devices[i];
    }
    return NULL;
}

static uint16_t
pktdev_find_free_port(void)
{
    unsigned i;

    for (i = 0; i < CNE_MAX_ETHPORTS; i++) {
        /* Using shared name field to find a free lport. */
        if (pktdev_devices[i].state == PKTDEV_UNUSED)
            return i;
    }
    return CNE_MAX_ETHPORTS;
}

struct cne_pktdev *
pktdev_get(uint16_t lport_id)
{
    struct cne_pktdev *dev = NULL;

    if (lport_id < CNE_MAX_ETHPORTS) {
        dev = &pktdev_devices[lport_id];
        if (dev->state != PKTDEV_ACTIVE)
            return NULL;
    }

    return dev;
}

struct cne_pktdev *
pktdev_allocate(const char *name, const char *ifname)
{
    uint16_t lport_id;
    struct cne_pktdev *dev = NULL;
    size_t name_len        = 0;

    name_len = strnlen(name, PKTDEV_NAME_MAX_LEN);
    if (name_len == 0)
        CNE_NULL_RET("Zero length Ethernet device name\n");

    if ((name_len + 1) >= PKTDEV_NAME_MAX_LEN)        // Need space for terminating char
        CNE_NULL_RET("Ethernet device name is too long\n");

    if (pktdev_allocated(name) != NULL)
        CNE_NULL_RET("Device with name %s already allocated\n", name);

    lport_id = pktdev_find_free_port();
    if (lport_id >= CNE_MAX_ETHPORTS)
        CNE_NULL_RET("Reached maximum number of lports\n");

    dev       = &pktdev_devices[lport_id];
    dev->data = &pktdev_data[lport_id];

    strlcpy(dev->data->name, name, sizeof(dev->data->name));
    if (strncmp(dev->data->name, name, name_len) != 0) {
        dev->state = PKTDEV_UNUSED;
        dev->data  = NULL;
        CNE_NULL_RET("Setting the pkt_dev name failed\n");
    }

    if (ifname && ifname[0] != '\0')
        strlcpy(dev->data->ifname, ifname, sizeof(dev->data->ifname));

    dev->data->lport_id  = lport_id;
    dev->data->numa_node = cne_device_socket_id((char *)(uintptr_t)ifname);

    return dev;
}

int
pktdev_is_valid_port(uint16_t lport_id)
{
    struct cne_pktdev *dev = pktdev_get(lport_id);

    return (!dev || dev->state == PKTDEV_UNUSED) ? 0 : 1;
}

int
pktdev_socket_id(uint16_t lport_id)
{
    struct cne_pktdev *dev = pktdev_get(lport_id);

    if (!dev)
        return -1;
    return dev->data->numa_node;
}

uint16_t
pktdev_port_count(void)
{
    uint16_t count;

    count = 0;

    PKTDEV_FOREACH (p) {
        if (pktdev_devices[p].state != PKTDEV_UNUSED)
            count++;
    }

    return count;
}

int
pktdev_start(uint16_t lport_id)
{
    struct cne_pktdev *dev;

    if (lport_id >= CNE_MAX_ETHPORTS)
        return -1;

    dev = &pktdev_devices[lport_id];
    if (!dev->data || !dev->dev_ops)
        return -1;

    if (dev->data->admin_state) {
        CNE_DEBUG("Device with lport_id=%" PRIu16 " already started\n", lport_id);
        return 0;
    }

    dev->data->admin_state = true;

    return 0;
}

int
pktdev_stop(uint16_t lport_id)
{
    struct cne_pktdev *dev;

    if (lport_id >= CNE_MAX_ETHPORTS)
        return -1;

    dev = &pktdev_devices[lport_id];
    if (!dev->data || !dev->dev_ops)
        return -1;

    if (dev->data->admin_state == false) {
        CNE_DEBUG("Device with lport_id=%" PRIu16 " already stopped\n", lport_id);
        return 0;
    }

    dev->data->admin_state = false;
    CALL_PMD(dev->dev_ops->admin_state_down, dev);

    return 0;
}

int
pktdev_buf_alloc(int lport_id, pktmbuf_t **bufs, uint16_t nb_bufs)
{
    struct cne_pktdev *dev = pktdev_get(lport_id);

    if (!dev)
        return -1;
    return CALL_PMD(dev->dev_ops->pkt_alloc, dev, bufs, nb_bufs);
}

int
pktdev_set_admin_state_up(uint16_t lport_id)
{
    struct cne_pktdev *dev;

    if (lport_id >= CNE_MAX_ETHPORTS)
        return -1;

    dev = &pktdev_devices[lport_id];
    if (!dev->data || !dev->dev_ops)
        return -1;
    return CALL_PMD(dev->dev_ops->admin_state_up, dev);
}

int
pktdev_set_admin_state_down(uint16_t lport_id)
{
    struct cne_pktdev *dev;

    if (lport_id >= CNE_MAX_ETHPORTS)
        return -1;

    dev = &pktdev_devices[lport_id];
    if (!dev->data || !dev->dev_ops)
        return -1;
    return CALL_PMD(dev->dev_ops->admin_state_down, dev);
}

int
pktdev_close(uint16_t lport_id)
{
    struct cne_pktdev *dev;

    if (lport_id >= CNE_MAX_ETHPORTS)
        return -EINVAL;

    dev = &pktdev_devices[lport_id];
    if (!dev->data || !dev->dev_ops)
        return -EINVAL;

    pktdev_stop(lport_id);
    CALL_PMD(dev->dev_ops->dev_close, dev);

    pktdev_release_port(dev);

    return 0;
}

int
pktdev_close_all(void)
{
    PKTDEV_FOREACH (i) {
        if (pktdev_close(i) < 0)
            return -1;
    }

    return 0;
}

int
pktdev_stats_get(uint16_t lport_id, lport_stats_t *stats)
{
    struct cne_pktdev *dev;

    if (!stats || lport_id >= CNE_MAX_ETHPORTS)
        return -1;

    dev = &pktdev_devices[lport_id];
    if (!dev->data || !dev->dev_ops)
        return -1;

    memset(stats, 0, sizeof(*stats));

    return CALL_PMD(dev->dev_ops->stats_get, dev, stats);
}

int
pktdev_stats_reset(uint16_t lport_id)
{
    struct cne_pktdev *dev;

    if (lport_id >= CNE_MAX_ETHPORTS)
        return -1;

    dev = &pktdev_devices[lport_id];
    if (!dev->data || !dev->dev_ops)
        return -1;

    return CALL_PMD(dev->dev_ops->stats_reset, dev);
}

int
pktdev_info_get(uint16_t lport_id, struct pktdev_info *dev_info)
{
    struct cne_pktdev *dev;
    int diag;

    if (lport_id >= CNE_MAX_ETHPORTS)
        return -ENODEV;

    /*
     * Init dev_info before lport_id check since caller does not have
     * return status and does not know if get is successful or not.
     */
    memset(dev_info, 0, sizeof(struct pktdev_info));

    dev = &pktdev_devices[lport_id];
    if (!dev->data || !dev->dev_ops)
        return -ENOTSUP;

    diag = CALL_PMD(dev->dev_ops->dev_infos_get, dev, dev_info);
    if (diag != 0) {
        /* Cleanup already filled in device information */
        memset(dev_info, 0, sizeof(struct pktdev_info));
        return diag;
    }

    dev_info->admin_state = dev->data->admin_state;

    return 0;
}

void
pktdev_release_port(struct cne_pktdev *dev)
{
    if (dev == NULL)
        return;

    memset(dev, 0, sizeof(struct cne_pktdev));
}

int
pktdev_get_name_by_port(uint16_t lport_id, char *name, uint32_t len)
{
    uint32_t slen;

    if (lport_id >= CNE_MAX_ETHPORTS) {
        CNE_ERR("lport_id out of range\n");
        return -EINVAL;
    }

    if (name == NULL) {
        CNE_ERR("Null pointer is specified\n");
        return -EINVAL;
    }

    if (pktdev_devices[lport_id].state == PKTDEV_UNUSED) {
        CNE_ERR("pktdev_devices[lport_id].state == PKTDEV_UNUSED\n");
        return -1;
    }

    slen = sizeof(pktdev_devices[lport_id].data->name);
    len  = (slen < len) ? slen : len;
    strlcpy(name, pktdev_devices[lport_id].data->name, len);

    return 0;
}

int
pktdev_get_port_by_name(const char *name, uint16_t *lport_id)
{
    if (name == NULL || lport_id == NULL)
        CNE_ERR_RET_VAL(-EINVAL, "Null pointer is specified\n");

    PKTDEV_FOREACH (pid) {
        if (pktdev_devices[pid].state == PKTDEV_UNUSED)
            continue;

        if (!strcmp(name, pktdev_devices[pid].data->name)) {
            *lport_id = pid;
            return 0;
        }
    }

    return -ENODEV;
}

const char *
pktdev_port_name(uint16_t lport_id)
{
    if (lport_id >= CNE_MAX_ETHPORTS)
        return NULL;

    if (pktdev_devices[lport_id].state != PKTDEV_ACTIVE)
        return NULL;

    return (const char *)pktdev_devices[lport_id].data->name;
}
