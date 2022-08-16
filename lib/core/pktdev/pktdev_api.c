/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */
#include <string.h>              // for strcmp
#include <stdio.h>               // for fprintf, NULL, FILE, stdout
#include <net/ethernet.h>        // ether_addr
#include <sys/queue.h>           // for TAILQ_FOREACH, TAILQ_HEAD_INITIALIZER
#include <pktdev_api.h>

#include "pktdev.h"               // for pktdev_info
#include "pktdev_driver.h"        // for pktdev_driver, pktdev_driver::(anonymous)
#include "pktdev_api.h"           // for pktdev_get_name_by_port, pktdev_info_get
#include "pktdev_core.h"          // for cne_pktdev, pktdev_devices, pktdev_data
#include "cne_log.h"              // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_ERR_RET
#include "cne_lport.h"            // for lport_cfg_t, LPORT_NAME_LEN

static struct pktdev_driver_list pktdev_drv_list = TAILQ_HEAD_INITIALIZER(pktdev_drv_list);

static inline struct pktdev_driver *
find_driver(const char *pmd)
{
    struct pktdev_driver *drv = NULL;

    /* Search for the PMD to initialize */
    TAILQ_FOREACH (drv, &pktdev_drv_list, next) {
        if (!strcmp(pmd, drv->name))
            break;
    }

    return drv;
}

int
pktdev_port_setup(lport_cfg_t *c)
{
    struct pktdev_driver *drv = NULL;
    int lport;

    if (!c)
        CNE_ERR_RET("Configuration pointer is NULL\n");

    drv = find_driver(c->pmd_name);
    if (!drv)
        CNE_ERR_RET("Failed to locate %s PMD\n", c->pmd_name);

    if (!drv->probe)
        CNE_ERR_RET("PMD %s probe routine missing\n", c->pmd_name);

    if ((lport = drv->probe(c)) < 0)
        CNE_ERR_RET("driver probe(%s:%s) failed\n", c->ifname, c->pmd_name);

    if (lport >= CNE_MAX_ETHPORTS)
        CNE_ERR_RET("Invalid port number %d >= CNE_MAX_ETHPORTS\n", lport);
    pktdev_devices[lport].state = PKTDEV_ACTIVE;

    if (pktdev_start(lport) < 0)
        CNE_ERR_RET("pktdev_start(%d) failed\n", lport);

    return lport;
}

/* register a driver */
void
pktdev_register(struct pktdev_driver *driver)
{
    TAILQ_INSERT_TAIL(&pktdev_drv_list, driver, next);
}

int
pktdev_portid(struct cne_pktdev *dev)
{
    return (dev) ? dev - pktdev_devices : -1;
}

int
pktdev_macaddr_get(uint16_t lport_id, struct ether_addr *mac_addr)
{
    struct cne_pktdev *dev;

    if (lport_id >= CNE_MAX_ETHPORTS)
        return -ENODEV;
    if (!mac_addr)
        return -EINVAL;

    dev       = &pktdev_devices[lport_id];
    *mac_addr = *dev->data->mac_addr;

    return 0;
}

int
pktdev_offloads_get(uint16_t lport_id, struct offloads *off)
{
    struct cne_pktdev *dev;

    if (lport_id >= CNE_MAX_ETHPORTS)
        return -ENODEV;
    if (!off)
        return -EINVAL;

    dev = &pktdev_devices[lport_id];

    off->tx_checksum_offload = dev->data->offloads->tx_checksum_offload;
    off->rx_checksum_offload = dev->data->offloads->rx_checksum_offload;

    return 0;
}

void
lport_cfg_dump(FILE *f, lport_cfg_t *c)
{
    if (c) {
        if (!f)
            f = stdout;

        cne_fprintf(f, "lport_cfg_t: %p\n", c);
        cne_fprintf(f, "  name            : %s\n", c->name);
        cne_fprintf(f, "  netdev          : %s\n", c->ifname);
        cne_fprintf(f, "  pmd_name        : %s\n", c->pmd_name);
        cne_fprintf(f, "  qid             : %u\n", c->qid);
        cne_fprintf(f, "  bufcnt          : %u\n", c->bufcnt);
        cne_fprintf(f, "  bufsz           : %u\n", c->bufsz);
    }
}

void *
pktdev_arg_get(uint16_t lport_id)
{
    struct cne_pktdev *dev;

    dev = &pktdev_devices[lport_id];

    return dev->data->dev_private;
}

bool
pktdev_admin_state(uint16_t lport_id)
{
    struct cne_pktdev *dev;

    dev = &pktdev_devices[lport_id];
    if (dev->state != PKTDEV_ACTIVE)
        return false;

    return dev->data->admin_state;
}

int
pktdev_admin_state_set(uint16_t lport_id, bool _state)
{
    struct cne_pktdev *dev;

    dev = &pktdev_devices[lport_id];
    if (dev->state != PKTDEV_ACTIVE)
        return -1;

    dev->data->admin_state = _state;

    return 0;
}
