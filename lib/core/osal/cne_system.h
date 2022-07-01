/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CNE_SYSTEM_H_
#define _CNE_SYSTEM_H_

/**
 * @file
 * API for lcore and socket manipulation
 */

#include <sys/syscall.h>
#include <stdint.h>        // for uint16_t, uint64_t

#include <cne_common.h>        // for CNDP_API

#ifdef __cplusplus
extern "C" {
#endif

#define CNE_LCORE_INVALID 0xFFFF

/**
 * Get cpu core_id base in lcore ID value from /sys/.../cpuX path.
 *
 * This function is private to the CNE.
 *
 * @param lcore_id
 *    The lcore ID value to location.
 */
CNDP_API unsigned cne_core_id(unsigned lcore_id);

/**
 * Return the number of execution units (lcores) on the system.
 *
 * @return
 *   the number of execution units (lcores) on the system.
 */
CNDP_API unsigned int cne_max_lcores(void);

/**
 * Return the number of NUMA zones.
 *
 * @return
 *   The number of numa zones.
 */
CNDP_API int cne_max_numa_nodes(void);

/**
 * Return the lcore ID of the current running thread.
 *
 * @return
 *   -1 on error or lcore id
 */
CNDP_API int cne_lcore_id(void);

/**
 * Return the lcore ID of the given thread id.
 *
 * @param thread_idx
 *   Thread id to get find the lcore id
 * @return
 *   -1 on error or lcore id value
 */
CNDP_API int cne_lcore_id_by_thread(int thread_idx);

/**
 * Return the ID of the physical socket of the logical core we are
 * running on.
 *
 * @param lcore_id
 *   The lcore ID value to use to return the socket ID.
 * @return
 *   The ID of current lcore id's physical socket
 */
CNDP_API unsigned int cne_socket_id(unsigned lcore_id);

/**
 * Return the socket id for the current lcore
 *
 * @return
 *   The ID of the socket for the current lcore
 */
CNDP_API unsigned int cne_socket_id_self(void);

/**
 * Return the socket id for the given netdev name
 *
 * @param netdev
 *   The netdev name string.
 * @return
 *   The ID of the socket for the given netdev name or -1 if not found.
 */
CNDP_API uint16_t cne_device_socket_id(char *netdev);

/**
 * Return number of physical sockets detected on the system.
 *
 * Note that number of nodes may not be correspondent to their physical id's:
 * for example, a system may report two socket id's, but the actual socket id's
 * may be 0 and 8.
 *
 * @return
 *   the number of physical sockets as recognized by CNE
 */
CNDP_API unsigned int cne_socket_count(void);

/**
 * Get the measured frequency of the RDTSC counter
 *
 * @return
 *   The TSC frequency for this lcore
 */
CNDP_API uint64_t cne_get_timer_hz(void);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_SYSTEM_H_ */
