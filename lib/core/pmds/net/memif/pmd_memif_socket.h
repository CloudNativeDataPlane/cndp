/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2021 Cisco Systems, Inc.  All rights reserved.
 */

#ifndef _CNE_ETH_MEMIF_H_
#define _CNE_ETH_MEMIF_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* GNU_SOURCE */

#include <sys/queue.h>

#include <cne_spinlock.h>
#include <cne_event.h>
#include "pktdev_api.h"          // for pktdev_get_name_by_port, pktdev_portid
#include "pktdev_core.h"         // for cne_pktdev, pktdev_data, pktdev_ops
#include "netdev_funcs.h"        // for netdev_get_mac_addr
#include "memif_socket.h"

#define PMD_NET_MEMIF_NAME "net_memif_socket"

#define CNE_ETH_MEMIF_DEFAULT_SOCKET_FILENAME "/var/run/memif.sock"
#define CNE_ETH_MEMIF_DEFAULT_RING_SIZE       10
#define CNE_ETH_MEMIF_DEFAULT_PKT_BUFFER_SIZE 2048

#define CNE_ETH_MEMIF_MAX_NUM_Q_PAIRS    1
#define CNE_ETH_MEMIF_MAX_LOG2_RING_SIZE 14
#define CNE_ETH_MEMIF_MAX_REGION_NUM     256

#define CNE_ETH_MEMIF_SHM_NAME_SIZE    32
#define CNE_ETH_MEMIF_DISC_STRING_SIZE 96
#define CNE_ETH_MEMIF_SECRET_SIZE      24

extern int cne_memif_logtype;

#define MIF_LOG(level, fmt, args...) cne_log(CNE_LOG_##level, __func__, __LINE__, fmt, ##args)

enum cne_memif_role_t {
    CNE_MEMIF_ROLE_SERVER,
    CNE_MEMIF_ROLE_CLIENT,
};

struct cne_memif_region {
    void *addr;                          /**< shared memory address */
    cne_memif_region_size_t region_size; /**< shared memory size */
    int fd;                              /**< shared memory file descriptor */
    uint32_t pkt_buffer_offset;
    /**< offset from 'addr' to first packet buffer */
};

struct pmd_internals {
    cne_memif_interface_id_t id; /**< unique id */
    enum cne_memif_role_t role;  /**< device role */
    uint32_t flags;              /**< device status flags */
#define CNE_ETH_MEMIF_FLAG_CONNECTING (1 << 0)
/**< device is connecting */
#define CNE_ETH_MEMIF_FLAG_CONNECTED (1 << 1)
/**< device is connected */
#define CNE_ETH_MEMIF_FLAG_ZERO_COPY (1 << 2)
/**< device is zero-copy enabled */
#define CNE_ETH_MEMIF_FLAG_DISABLED (1 << 3)
/**< device has not been configured and can not accept connection requests */
#define CNE_ETH_MEMIF_FLAG_SOCKET_ABSTRACT (1 << 4)
    /**< use abstract socket address */

    char *socket_filename;                  /**< pointer to socket filename */
    struct cne_memif_socket *socket;        /**< pointer to created socket */
    char secret[CNE_ETH_MEMIF_SECRET_SIZE]; /**< secret (optional security parameter) */
    pktmbuf_info_t *pi;                     /** mempool info structure */
    struct cne_memif_control_channel *cc;   /**< control channel */
    cne_spinlock_t cc_lock;                 /**< control channel lock */

    /* remote info */
    char remote_name[PKTDEV_NAME_MAX_LEN];    /**< remote app name */
    char remote_if_name[PKTDEV_NAME_MAX_LEN]; /**< remote peer name */
    char pmd_name[PKTDEV_NAME_MAX_LEN];

    struct {
        cne_memif_log2_ring_size_t log2_ring_size; /**< log2 of ring size */
        uint8_t num_c2s_rings;                     /**< number of client to server rings */
        uint8_t num_s2c_rings;                     /**< number of server to client rings */
        uint16_t pkt_buffer_size;                  /**< buffer size */
    } cfg;                                         /**< Configured parameters (max values) */

    struct {
        cne_memif_log2_ring_size_t log2_ring_size; /**< log2 of ring size */
        uint8_t num_c2s_rings;                     /**< number of client to server rings */
        uint8_t num_s2c_rings;                     /**< number of server to client rings */
        uint16_t pkt_buffer_size;                  /**< buffer size */
    } run;
    /**< Parameters used in active connection */

    char local_disc_string[CNE_ETH_MEMIF_DISC_STRING_SIZE];
    /**< local disconnect reason */
    char remote_disc_string[CNE_ETH_MEMIF_DISC_STRING_SIZE];
    /**< remote disconnect reason */
};

struct cne_memif_queue {
    pktmbuf_info_t *pi;        /**< mempool info for RX packets */
    struct pmd_internals *pmd; /**< device internals */

    cne_memif_ring_type_t type;      /**< ring type */
    cne_memif_region_index_t region; /**< shared memory region index */

    uint16_t in_port; /**< port id */

    cne_memif_region_offset_t ring_offset;
    /**< ring offset from start of shm region (ring - memif_region.addr) */

    uint16_t last_head; /**< last ring head */
    uint16_t last_tail; /**< last ring tail */

    struct cne_mbuf **buffers;
    /**< Stored mbufs. Used in zero-copy tx. Client stores transmitted
     * mbufs to free them once server has received them.
     */

    /* rx/tx info */
    uint64_t n_pkts;  /**< number of rx/tx packets */
    uint64_t n_bytes; /**< number of rx/tx bytes */

    struct cne_ev_handle ev_handle; /**< interrupt handle */

    cne_memif_log2_ring_size_t log2_ring_size; /**< log2 of ring size */
};

struct pmd_process_private {
    struct cne_memif_region *regions[CNE_ETH_MEMIF_MAX_REGION_NUM];
    /**< shared memory regions */
    cne_memif_region_index_t regions_num; /**< number of regions */
};

/**
 * Unmap shared memory and free regions from memory.
 *
 * @param proc_private
 *   device process private data
 */
void cne_memif_free_regions(struct cne_pktdev *dev);

/**
 * Finalize connection establishment process. Map shared memory file
 * (server role), initialize ring queue, set link status up.
 *
 * @param dev
 *   memif device
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int cne_memif_connect(struct cne_pktdev *dev);

int cne_memif_connect_start(struct cne_pktdev *dev);

/**
 * Create shared memory file and initialize ring queue.
 * Only called by client when establishing connection
 *
 * @param dev
 *   memif device
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int cne_memif_init_regions_and_queues(struct cne_pktdev *dev);

/**
 * Get memif version string.
 *
 * @return
 *   - memif version string
 */
const char *cne_memif_version(void);

#ifndef MFD_HUGETLB
#ifndef __NR_memfd_create

#if defined __x86_64__
#define __NR_memfd_create 319
#else
#error "__NR_memfd_create unknown for this architecture"
#endif

#endif /* __NR_memfd_create */

static inline int
memfd_create(const char *name, unsigned int flags)
{
    return syscall(__NR_memfd_create, name, flags);
}
#endif /* MFD_HUGETLB */

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL   0x0001 /* prevent further seals from being set */
#define F_SEAL_SHRINK 0x0002 /* prevent file from shrinking */
#define F_SEAL_GROW   0x0004 /* prevent file from growing */
#define F_SEAL_WRITE  0x0008 /* prevent writes */
#endif

#endif /* CNE_ETH_MEMIF_H */
