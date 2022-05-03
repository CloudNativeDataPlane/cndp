/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_H
#define __CNET_H

/**
 * @file
 * CNET configuration routines.
 */

#include <cne_version.h>
#include <cne_log.h>
#include <cne_per_thread.h>        // for CNE_PER_THREAD, CNE_DECLARE_PER_THREAD
#include <cne_cycles.h>
#include <cnet_const.h>        // for cfunc_t, sfunc_t, cnet_assert, iofunc_t
#include <cne_atomic.h>        // for atomic_uint_least16_t, atomic_fetch_add
#include <stdint.h>            // for uint16_t, int32_t

#include <cne_common.h>        // for CNE_MAX_ETHPORTS, __cne_cache_aligned
#include <uid.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stk_s;
struct drv_entry;
struct cne_mempool;
struct fib_info;

struct cnet {
    CNE_ATOMIC(uint_fast16_t) stk_order; /**< Order of the stack initializations */
    uint16_t nb_ports;                   /**< Number of ports in the system */
    uint32_t num_chnls;                  /**< Number of channels in system */
    uint32_t num_routes;                 /**< Number of routes */
    uint32_t num_arps;                   /**< Number of ARP entries */
    uint16_t flags;                      /**< Flags enable Punting, TCP, ... */
    u_id_t chnl_uids;                    /**< UID for channel descriptor like values */
    void **chnl_descriptors;             /**< List of channel descriptors pointers */
    void *netlink_info;                  /**< Netlink information structure */
    struct stk_s **stks;                 /**< Vector list of stk_entry pointers */
    struct drv_entry **drvs;             /**< Vector list of drv_entry pointers */
    struct netif **netifs;               /**< List of active netif structures */
    struct cne_mempool *rt4_obj;         /**< Route IPv4 table pointer */
    struct cne_mempool *arp_obj;         /**< ARP object structures */
    struct fib_info *rt4_finfo;          /**< Pointer to the IPv4 FIB information structure */
    struct fib_info *arp_finfo;          /**< ARP FIB table pointer */
    struct fib_info *pcb_finfo;          /**< PCB FIB table pointer */
    struct fib_info *tcb_finfo;          /**< TCB FIB table pointer */
} __cne_cache_aligned;

enum {
    CNET_PUNT_ENABLED = 0x0001, /**< Enable Punting packets to Linux stack */
    CNET_TCP_ENABLED  = 0x0002, /**< Enable TCP packet processing */
};

/**
 * @brief Get the current cnet structure pointer.
 *
 * @return
 *   Pointer to struct cnet* or NULL on error.
 */
struct cnet *cnet_get(void);
#define this_cnet cnet_get()

/**
 * @brief Lock the cnet structure.
 *
 * @return
 *   0 on error or 1 on success
 */
CNDP_API int cnet_lock(void);

/**
 * @brief Lock the cnet structure data.
 *
 * @return
 *   N/A
 */
CNDP_API void cnet_unlock(void);

/**
 * @brief preload shared libraries for CNDP and CNET.
 *
 * @param libs
 *   An array of shared library names or directories to load into memory.
 * @param cnt
 *   The number of entries in the libs array.
 * @param flag
 *   The flag values to be used when loading the libraries.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_preload(char **libs, int cnt, int flag);

/**
 * @brief Configure and create the base cnet structure using a couple params.
 *
 * @param num_chnls
 *   The number of channels allowed in the system. If zero use the default value.
 * @param num_routes
 *   The number of routes to allowed in the system. If zero use the default value.
 * @return
 *   NULL on failure or pointer to cnet structure created.
 */
CNDP_API struct cnet *cnet_config_create(uint32_t num_chnls, uint32_t num_routes);

/**
 * @brief Create cnet structure and use default value, will call cnet_config_create().
 *
 * @return
 *   NULL on failure or pointer to cnet structure created.
 */
CNDP_API struct cnet *cnet_create(void);

/**
 * @brief Stop and free resources of the cnet structure.
 *
 * @return
 *  N/A
 */
CNDP_API void cnet_stop(void);

/**
 * @brief Dump out the CNET structure information
 *
 * @return
 *   N/A
 */
CNDP_API void cnet_dump(void);

/**
 * @brief Called to initialize the CLI commands for the CNET structure.
 *
 * @return
 *   -1 on failure or 0 on success
 */
CNDP_API int cnet_add_cli_cmds(void);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_H */
