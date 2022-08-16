/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef __PKTDEV_DRIVER_H_
#define __PKTDEV_DRIVER_H_

/**
 * @file
 *
 * CNE pktdev PMD API
 *
 * These APIs are used by pktdev drivers. Applications should not use them.
 */

#include <sys/queue.h>
#include <cne_atomic.h>
#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Double linked list of virtual device drivers. */
TAILQ_HEAD(pktdev_driver_list, pktdev_driver);

/**
 * Probe function called for each virtual device driver once.
 */
typedef int(pktdev_probe_t)(lport_cfg_t *cfg);

/**
 * Remove function to remove a lport
 */
typedef int(pktdev_remove_t)(struct cne_pktdev *dev);

/**
 * A virtual device driver abstraction.
 */
struct pktdev_driver {
    TAILQ_ENTRY(pktdev_driver) next; /**< Next in list */
    const char *name;                /**< driver name */
    pktdev_probe_t *probe;           /**< device probe function */
};

/**
 * Register a virtual device driver.
 *
 * @param driver
 *   A pointer to a pktdev_driver structure describing the driver
 *   to be registered.
 */
void pktdev_register(struct pktdev_driver *driver);

#define PMD_REGISTER_DEV(nm, vdrv) \
    CNE_INIT(vdrvinit_##vdrv)      \
    {                              \
        (vdrv).name = CNE_STR(nm); \
        pktdev_register(&vdrv);    \
    }

/**
 * @internal
 * Returns a pktdev slot specified by the unique identifier name.
 *
 * @param   name
 *   The pointer to the Unique identifier name for each Ethernet device
 * @return
 *   - The pointer to the pktdev slot, on success. NULL on error
 */
CNDP_API struct cne_pktdev *pktdev_allocated(const char *name);

/**
 * @internal
 * Allocates a new pktdev slot for an ethernet device and returns the pointer
 * to that slot for the driver to use.
 *
 * @param name
 *   Unique identifier name for each Ethernet device
 * @param ifname
 *   The name of the netdev or ifname if needed.
 * @return
 *   - Slot in the cne_dev_devices array for a new device;
 */
CNDP_API struct cne_pktdev *pktdev_allocate(const char *name, const char *ifname);

/**
 * @internal
 * Release device queues and clear its configuration to force the user
 * application to reconfigure it. It is for internal use only.
 *
 * @param dev
 *  Pointer to struct cne_pktdev.
 *
 * @return
 *  void
 */
CNDP_API void _pktdev_reset(struct cne_pktdev *dev);

/**
 * Release the port or pktdev structure
 *
 * @param dev
 *   The pktdev internal release structure pointer
 */
CNDP_API void pktdev_release_port(struct cne_pktdev *dev);

#ifdef __cplusplus
}
#endif

#endif /* __PKTDEV_DRIVER_H_ */
