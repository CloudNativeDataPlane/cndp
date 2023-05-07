/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2023 Intel Corporation
 */

#include <bsd/string.h>
#include <pktdev.h>            // for pktdev_tx_burst, pktdev_info
#include <cnet.h>              // for cnet, cnet_add_singleton
#include <cne_vec.h>           // for vec_len, vec_set_len, vec_at_index, vec_max...
#include <cne_log.h>           // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_ERR, CNE_LO...
#include <cnet_netif.h>        // for netif, netif::(anonymous), _IFF_RUNNING
#include <stdio.h>             // for snprintf, NULL
#include <stdlib.h>            // for calloc, free
#include <string.h>            // for memcpy, strncmp

#include "cnet_reg.h"
#include "cnet_drv.h"
#include "pktdev_api.h"         // for pktdev_info_get
#include "pktdev_core.h"        // for cne_pktdev, pktdev_devices, pktdev_data
#include "pktmbuf.h"            // for pktmbuf_t, pktmbuf_data_len

static int
drv_setup(struct cnet *cnet, int lport)
{
    struct drv_entry *drv = NULL;

    drv = calloc(1, sizeof(struct drv_entry));
    if (!drv)
        CNE_ERR_RET("Failed to allocate struct drv_entry structure\n");

    vec_at_index(cnet->drvs, lport) = drv;
    vec_inc_len(cnet->drvs);

    return 0;
}

int
cnet_drv_create(struct cnet *cnet)
{
    for (int i = 0; i < cnet->nb_ports; i++) {
        if (drv_setup(cnet, i) < 0)
            return -1;
    }

    return 0;
}

int
cnet_drv_destroy(struct cnet *cnet)
{
    if (!cnet || !cnet->drvs)
        return -1;
    for (uint32_t i = 0; i < vec_max_len(cnet->drvs); i++) {
        struct drv_entry *drv;

        drv = vec_at_index(cnet->drvs, i);
        if (drv == NULL)
            continue;
        free(drv);
    }
    return 0;
}
