/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef __PKTDEV_API_H
#define __PKTDEV_API_H

/**
 * @file
 *
 * pktdev structures and APIs.
 */

#include <stdbool.h>        // for bool, false, true
#include <stdint.h>         // for uint16_t
#include <stdio.h>          // for NULL, FILE

#include <cne_common.h>          // for CNDP_API
#include <cne_lport.h>           // for lport_cfg_t, lport_stats_t
#include <netdev_funcs.h>        // for struct offloads
#include <pktmbuf.h>             // for pktmbuf_t

struct ether_addr;
struct cne_pktdev;
struct pktdev_info;

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CFG_CREATE_NONE = 0,
    CFG_CREATE_RX,
    CFG_CREATE_TX,
    CFG_CREATE_MASK,
    CFG_SHARE_MEMPOOL,
};

/* Macros to check for invalid function pointers */
#define FUNC_PTR_OR_ERR_RET(func, retval) \
    do {                                  \
        if ((func) == NULL)               \
            return retval;                \
    } while (0)

#define FUNC_PTR_OR_RET(func) \
    do {                      \
        if ((func) == NULL)   \
            return;           \
    } while (0)

#define PKTDEV_STARTED (1 << 1) /**< Device state: STARTED(1) / STOPPED(0). */

/**
 * Function type used for RX packet processing packet callbacks.
 *
 * The callback function is called on RX with a burst of packets that have
 * been received on the given lport and queue.
 *
 * @param lport_id
 *   The Ethernet lport on which RX is being performed.
 * @param pkts
 *   The burst of packets that have just been received.
 * @param nb_pkts
 *   The number of packets in the burst pointed to by "pkts".
 * @param max_pkts
 *   The max number of packets that can be stored in the "pkts" array.
 * @param user_param
 *   The arbitrary user parameter passed in by the application when the callback
 *   was originally configured.
 * @return
 *   The number of packets returned to the user.
 */
typedef uint16_t (*cne_rx_callback_fn)(uint16_t lport_id, pktmbuf_t *pkts[], uint16_t nb_pkts,
                                       uint16_t max_pkts, void *user_param);

/**
 * Function type used for TX packet processing packet callbacks.
 *
 * The callback function is called on TX with a burst of packets immediately
 * before the packets are put onto the hardware queue for transmission.
 *
 * @param lport_id
 *   The Ethernet lport on which TX is being performed.
 * @param pkts
 *   The burst of packets that are about to be transmitted.
 * @param nb_pkts
 *   The number of packets in the burst pointed to by "pkts".
 * @param user_param
 *   The arbitrary user parameter passed in by the application when the callback
 *   was originally configured.
 * @return
 *   The number of packets to be written to the NIC.
 */
typedef uint16_t (*cne_tx_callback_fn)(uint16_t lport_id, pktmbuf_t *pkts[], uint16_t nb_pkts,
                                       void *user_param);

/**
 * Get the number of lports which are usable for the application.
 *
 * @return
 *   The count of available Ethernet devices.
 */
CNDP_API uint16_t pktdev_port_count(void);

/**
 * Start an Ethernet device.
 *
 * The device start step is the last one and consists of setting the configured
 * offload features and in starting the transmit and the receive units of the
 * device.
 *
 * On success, all basic functions exported by the Ethernet API (link status,
 * receive/transmit, and so on) can be invoked.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @return
 *   - 0: Success, Ethernet device started.
 *   - <0: Error code of the driver device start function.
 */
CNDP_API int pktdev_start(uint16_t lport_id);

/**
 * Stop an Ethernet device. The device can be restarted with a call to
 * pktdev_start()
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @return
 *   - 0: Success, Ethernet device stopped.
 *   - <0: Error code of the driver device stop function.
 */
CNDP_API int pktdev_stop(uint16_t lport_id);

/**
 * Set admin state to UP
 *
 * Set admin state up will re-enable the stream
 * functionality after it is previously set down.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @return
 *   - 0: Success, Admni state linked up.
 *   - <0: Error code of the driver admin state up function.
 */
CNDP_API int pktdev_set_admin_state_up(uint16_t lport_id);

/**
 * Set admin state to DOWN
 *
 * The stream functionality will be disabled if success,
 * and it can be re-enabled with a call to
 * pktdev_set_admin_state_up()
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int pktdev_set_admin_state_down(uint16_t lport_id);

/**
 * Close a stopped Ethernet device. The device cannot be restarted!
 *
 * The function frees all lport resources if the driver supports
 * the flag PKTDEV_DEV_CLOSE_REMOVE.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @return
 *   0 on success or -EINVAL on invalid lport_id or not configured.
 */
CNDP_API int pktdev_close(uint16_t lport_id);

/**
 * Close all devices
 *
 * @return
 *   0 on success or -EINVAL on error from pktdev_close().
 */
CNDP_API int pktdev_close_all(void);

/**
 * Retrieve the general I/O statistics of an Ethernet device.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @param stats
 *   A pointer to a structure of type *lport_stats* to be filled with
 *   the values of device counters for the following set of statistics:
 *   - *ipackets* with the total of successfully received packets.
 *   - *opackets* with the total of successfully transmitted packets.
 *   - *ibytes*   with the total of successfully received bytes.
 *   - *obytes*   with the total of successfully transmitted bytes.
 *   - *ierrors*  with the total of erroneous received packets.
 *   - *oerrors*  with the total of failed transmitted packets.
 * @return
 *   Zero if successful. Non-zero otherwise.
 */
CNDP_API int pktdev_stats_get(uint16_t lport_id, lport_stats_t *stats);

/**
 * Reset the general I/O statistics of an Ethernet device.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @return
 *   - (0) if device notified to reset stats.
 *   - (-ENOTSUP) if hardware doesn't support.
 *   - (-ENODEV) if *lport_id* invalid.
 *   - (<0): Error code of the driver stats reset function.
 */
CNDP_API int pktdev_stats_reset(uint16_t lport_id);

/**
 * Retrieve the Ethernet address of an Ethernet device.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @param mac_addr
 *   A pointer to a structure of type *ether_addr* to be filled with
 *   the Ethernet address of the Ethernet device.
 * @return
 *   - (0) if successful
 *   - (-ENODEV) if *lport_id* invalid.
 *   - (-EINVAL) if *mac_addr* invalid.
 */
CNDP_API int pktdev_macaddr_get(uint16_t lport_id, struct ether_addr *mac_addr);

/**
 * Retrieve the offloads configuration of a netdevice.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @param off
 *   A pointer to a structure of type *struct offloads* to be filled with
 *   the offloads configuration of the netdevice
 * @return
 *   - (0) if successful
 *   - (-ENODEV) if *lport_id* invalid.
 *   - (-EINVAL) if *off* invalid.
 */
CNDP_API int pktdev_offloads_get(uint16_t lport_id, struct offloads *off);

/**
 * Retrieve the contextual information of an Ethernet device.
 *
 * As part of this function, a number of of fields in dev_info will be
 * initialized as follows:
 *
 * device = dev->device
 * min_mtu = CNE_ETHER_MIN_MTU
 * max_mtu = UINT16_MAX
 *
 * The following fields will be populated if support for dev_infos_get()
 * exists for the device and the cne_pktdev 'dev' has been populated
 * successfully with a call to it:
 *
 * driver_name = dev->device->driver->name
 * nb_rx_queues = dev->data->nb_rx_queues
 * nb_tx_queues = dev->data->nb_tx_queues
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @param dev_info
 *   A pointer to a structure of type *pktdev_info* to be filled with
 *   the contextual information of the Ethernet device.
 * @return
 *   - (0) if successful.
 *   - (-ENOTSUP) if support for dev_infos_get() does not exist for the device.
 *   - (-ENODEV) if *lport_id* invalid.
 */
CNDP_API int pktdev_info_get(uint16_t lport_id, struct pktdev_info *dev_info);

/**
 * Retrieve the MTU of an Ethernet device.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @param mtu
 *   A pointer to a uint16_t where the retrieved MTU is to be stored.
 * @return
 *   - (0) if successful.
 *   - (-ENODEV) if *lport_id* invalid.
 */
CNDP_API int pktdev_get_mtu(uint16_t lport_id, uint16_t *mtu);

/**
 * Change the MTU of an Ethernet device.
 *
 * @param lport_id
 *   The lport identifier of the Ethernet device.
 * @param mtu
 *   A uint16_t for the MTU to be applied.
 * @return
 *   - (0) if successful.
 *   - (-ENOTSUP) if operation is not supported.
 *   - (-ENODEV) if *lport_id* invalid.
 *   - (-EIO) if device is removed.
 *   - (-EINVAL) if *mtu* invalid, validation of mtu can occur within
 *     pktdev_set_mtu if dev_infos_get is supported by the device or
 *     when the mtu is set using dev->dev_ops->mtu_set.
 *   - (-EBUSY) if operation is not allowed when the lport is running
 */
CNDP_API int pktdev_set_mtu(uint16_t lport_id, uint16_t mtu);

/**
 * Get the lport name by lport id
 *
 * @param lport_id
 *   The lport id or index into the pktdev_devices array
 * @param name
 *   Pointer to a string array to put the name, will be null terminated.
 * @param len
 *   Length of the name buffer pointer
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int pktdev_get_name_by_port(uint16_t lport_id, char *name, uint32_t len);

/**
 * Get lport id by name of lport
 *
 * @param name
 *   Pointer to lport name string
 * @param lport_id
 *   Pointer to uint16_t value to return lport id
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int pktdev_get_port_by_name(const char *name, uint16_t *lport_id);

/**
 * Return constructed lport name from lport id
 *
 * @param lport_id
 *   The lport id to create lport name
 * @return
 *   NULL on error or pointer to lport name string
 */
CNDP_API const char *pktdev_port_name(uint16_t lport_id);

/**
 * Test if lport is a valid lport id
 *
 * @param lport_id
 *   The lport id to test
 * @return
 *   1 if lport id is valid or zero on not-valid
 */
CNDP_API int pktdev_is_valid_port(uint16_t lport_id);

/**
 * return socket id of the lport
 *
 * @param lport_id
 *   The lport to access for socket id
 * @return
 *   -1 on error or socket id value
 */
CNDP_API int pktdev_socket_id(uint16_t lport_id);

/**
 * Return the pktdev_devices[lport_id] pointer
 *
 * @param lport_id
 *   The lport id to use to locate cne_pktdev structure
 * @return
 *   NULL on error or pointer to pktdev_devices[]
 */
CNDP_API struct cne_pktdev *pktdev_get(uint16_t lport_id);

/**
 * Returns the pktdev lportid index
 *
 * @param dev
 *    Pointer to a valid pktdev_devices structure.
 * @return
 *    The lportid or index of the device structure or -1 on error
 */
CNDP_API int pktdev_portid(struct cne_pktdev *dev);

/**
 * Port setup helper routine to simplify bring up a lport using the defaults
 *
 * @param c
 *   The structure to use for setting up the lport. See the structure and driver
 *   docs to see how this structure is used.
 * @return
 *   The lport number or -1 on error
 */
CNDP_API int pktdev_port_setup(lport_cfg_t *c);

/**
 * Remove or destroy a lport which releases its resources.
 * Please make sure to stop a lport with pktdev_stop() before
 * removing it.
 *
 * @param lport_id
 *   The lport ID to use for the removal of the lport from the system
 */
CNDP_API int pktdev_port_remove(int lport_id);

/**
 * Dump out a lport_cfg_t structure.
 *
 * @param f
 *   The FILE descriptor to use or NULL for stdout.
 * @param c
 *   The lport_cfg_t pointer
 */
CNDP_API void lport_cfg_dump(FILE *f, lport_cfg_t *c);

/**
 * Get the packet stream state flag for the given lport.
 *
 * @param lport_id
 *   The lport id to use to locate cne_pktdev structure
 * @return
 *    pkt_admin_state
 */
CNDP_API bool pktdev_admin_state(uint16_t lport_id);

/**
 * Set the packet stream state flag for the given lport.
 *
 * @param lport_id
 *   The lport id to use to locate cne_pktdev structure
 * @param state
 *    Packet stream state flag
 * @return
 *    Zero on success or -1 on error
 */
CNDP_API int pktdev_admin_state_set(uint16_t lport_id, bool state);

/**
 * Macros to enable/disable admin state of a port.
 */
#define pktdev_admin_state_up(_pid)   pktdev_admin_state_set(_pid, true)
#define pktdev_admin_state_down(_pid) pktdev_admin_state_set(_pid, false)

/**
 * Get the argument value for alloc/free routines.
 *
 * @param lport_id
 *   The lport ID value.
 * @return
 *   The argument value is returned.
 */
CNDP_API void *pktdev_arg_get(uint16_t lport_id);

/**
 * Allocate a set of buffers using the user supplied allocate/free routines
 *
 * @param lport_id
 *   The lport ID value
 * @param bufs
 *   The array of buffer pointers to be allocated.
 * @param nb_bufs
 *   The number of buffers to be allocated
 * @return
 *   The number of buffers allocated or -1 on error
 */
CNDP_API int pktdev_buf_alloc(int lport_id, pktmbuf_t **bufs, uint16_t nb_bufs);

#ifdef __cplusplus
}
#endif

#endif /* __PKTDEV_API_H */
