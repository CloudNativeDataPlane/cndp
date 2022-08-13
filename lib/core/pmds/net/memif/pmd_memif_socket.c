/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */
// IWYU pragma: no_include <asm/int-ll64.h>
#include <errno.h>                // for ENODEV
#include <stdlib.h>               // for NULL, calloc, free, size_t
#include <string.h>               // for memset
#include <poll.h>                 // for pollfd
#include <net/if.h>               // for if_nametoindex, IF_NAMESIZE
#include <fcntl.h>                // for faccesstat
#include <sys/mman.h>             // for mmap
#include <sys/eventfd.h>          // for eventfd
#include <bsd/string.h>           // for strlcpy
#include <stdint.h>               // for uint16_t, uint64_t
#include <net/ethernet.h>         // for ether_addr
#include <cne_common.h>           // for CNE_PRIORITY_LAST
#include <cne_log.h>              // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_ERR
#include <pktmbuf.h>              // for pktmbuf_t
#include <pktdev.h>               // for pktdev_info, pktdev_portconf
#include <pktdev_driver.h>        // for pktdev_allocate, pktdev_allocated, pkt...
#include <cne_lport.h>            // for lport_cfg_t, lport_stats_t
#include <cne_mmap.h>             // for mmap_alloc

#include "pmd_memif_socket.h"

/* check if directory exists and if we have permission to read/write */
static int
cne_memif_check_socket_filename(const char *filename)
{
    char *dir = NULL, *tmp;
    uint32_t idx;
    int ret = 0;

    if (strlen(filename) >= UNIX_PATH_MAX) {
        MIF_LOG(ERR, "Unix socket address too long (max 108).");
        return -1;
    }

    tmp = strrchr(filename, '/');
    if (tmp != NULL) {
        idx = tmp - filename;
        dir = calloc(1, sizeof(char) * (idx + 1));
        if (dir == NULL) {
            MIF_LOG(ERR, "Failed to allocate memory.");
            return -1;
        }
        strlcpy(dir, filename, sizeof(char) * (idx + 1));
    }

    if (dir == NULL || (faccessat(-1, dir, F_OK | R_OK | W_OK, AT_EACCESS) < 0)) {
        MIF_LOG(ERR, "Invalid socket directory.");
        ret = -EINVAL;
    }

    if (dir != NULL)
        free(dir);

    return ret;
}

static cne_memif_ring_t *
cne_memif_get_ring(struct pmd_internals *pmd, struct pmd_process_private *proc_private,
                   cne_memif_ring_type_t type, uint16_t ring_num)
{
    /* rings only in region 0 */
    void *p = proc_private->regions[0]->addr;
    int ring_size =
        sizeof(cne_memif_ring_t) + sizeof(cne_memif_desc_t) * (1 << pmd->run.log2_ring_size);

    p = (uint8_t *)p + (ring_num + type * pmd->run.num_c2s_rings) * ring_size;

    return (cne_memif_ring_t *)p;
}

static cne_memif_region_offset_t
cne_memif_get_ring_offset(struct cne_pktdev *dev, struct cne_memif_queue *mq,
                          cne_memif_ring_type_t type, uint16_t num)
{
    struct pmd_internals *pmd                = dev->data->dev_private;
    struct pmd_process_private *proc_private = dev->process_private;

    return ((uint8_t *)cne_memif_get_ring(pmd, proc_private, type, num) -
            (uint8_t *)proc_private->regions[mq->region]->addr);
}

static cne_memif_ring_t *
cne_memif_get_ring_from_queue(struct pmd_process_private *proc_private, struct cne_memif_queue *mq)
{
    struct cne_memif_region *r;

    r = proc_private->regions[mq->region];
    if (r == NULL)
        return NULL;

    return (cne_memif_ring_t *)((uint8_t *)r->addr + mq->ring_offset);
}

static void *
memif_get_buffer(struct pmd_process_private *proc_private, cne_memif_desc_t *d)
{
    return ((uint8_t *)proc_private->regions[d->region]->addr + d->offset);
}

static int
cne_memif_region_init_shm(struct cne_pktdev *dev, uint8_t has_buffers)
{
    struct pmd_internals *pmd                = dev->data->dev_private;
    struct pmd_process_private *proc_private = dev->process_private;
    char shm_name[CNE_ETH_MEMIF_SHM_NAME_SIZE];
    int ret = 0;
    struct cne_memif_region *r;

    if (proc_private->regions_num >= CNE_ETH_MEMIF_MAX_REGION_NUM) {
        MIF_LOG(ERR, "Too many regions.");
        return -1;
    }

    r = calloc(1, sizeof(struct cne_memif_region));
    if (r == NULL) {
        MIF_LOG(ERR, "Failed to alloc memif region.");
        return -ENOMEM;
    }

    /* calculate buffer offset */
    r->pkt_buffer_offset =
        (pmd->run.num_c2s_rings + pmd->run.num_s2c_rings) *
        (sizeof(cne_memif_ring_t) + sizeof(cne_memif_desc_t) * (1 << pmd->run.log2_ring_size));

    r->region_size = r->pkt_buffer_offset;
    /* if region has buffers, add buffers size to region_size */
    if (has_buffers == 1)
        r->region_size += (uint32_t)(pmd->run.pkt_buffer_size * (1 << pmd->run.log2_ring_size) *
                                     (pmd->run.num_c2s_rings + pmd->run.num_s2c_rings));

    memset(shm_name, 0, sizeof(char) * CNE_ETH_MEMIF_SHM_NAME_SIZE);
    snprintf(shm_name, CNE_ETH_MEMIF_SHM_NAME_SIZE, "memif_region_%d", proc_private->regions_num);

    r->fd = memfd_create(shm_name, MFD_ALLOW_SEALING);
    if (r->fd < 0) {
        MIF_LOG(ERR, "Failed to create shm file: %s.", strerror(errno));
        ret = -1;
        goto error;
    }

    ret = fcntl(r->fd, F_ADD_SEALS, F_SEAL_SHRINK);
    if (ret < 0) {
        MIF_LOG(ERR, "Failed to add seals to shm file: %s.", strerror(errno));
        goto error;
    }

    ret = ftruncate(r->fd, r->region_size);
    if (ret < 0) {
        MIF_LOG(ERR, "Failed to truncate shm file: %s.", strerror(errno));
        goto error;
    }

    r->addr = mmap(NULL, r->region_size, PROT_READ | PROT_WRITE, MAP_SHARED, r->fd, 0);
    if (r->addr == MAP_FAILED) {
        MIF_LOG(ERR, "Failed to mmap shm region: %s.", strerror(ret));
        ret = -1;
        goto error;
    }

    proc_private->regions[proc_private->regions_num] = r;
    proc_private->regions_num++;

    return ret;

error:
    if (r->fd > 0)
        close(r->fd);
    r->fd = -1;
    free(r);

    return ret;
}

static int
cne_memif_regions_init(struct cne_pktdev *dev)
{
    int ret;

    /* Todo Zero Copy */
    /* create one memory region containing rings and buffers */
    ret = cne_memif_region_init_shm(dev, /* has buffers */ 1);
    if (ret < 0)
        return ret;

    return 0;
}

static void
cne_memif_init_rings(struct cne_pktdev *dev)
{
    struct pmd_internals *pmd                = dev->data->dev_private;
    struct pmd_process_private *proc_private = dev->process_private;
    cne_memif_ring_t *ring;
    int i, j;
    uint16_t slot;

    for (i = 0; i < pmd->run.num_c2s_rings; i++) {
        ring = cne_memif_get_ring(pmd, proc_private, CNE_MEMIF_RING_C2S, i);
        __atomic_store_n(&ring->head, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&ring->tail, 0, __ATOMIC_RELAXED);
        ring->cookie = CNE_MEMIF_COOKIE;
        ring->flags  = 0;

        if (pmd->flags & CNE_ETH_MEMIF_FLAG_ZERO_COPY)
            continue;

        for (j = 0; j < (1 << pmd->run.log2_ring_size); j++) {
            slot                 = i * (1 << pmd->run.log2_ring_size) + j;
            ring->desc[j].region = 0;
            ring->desc[j].offset = proc_private->regions[0]->pkt_buffer_offset +
                                   (uint32_t)(slot * pmd->run.pkt_buffer_size);
            ring->desc[j].length = pmd->run.pkt_buffer_size;
        }
    }

    for (i = 0; i < pmd->run.num_s2c_rings; i++) {
        ring = cne_memif_get_ring(pmd, proc_private, CNE_MEMIF_RING_S2C, i);
        __atomic_store_n(&ring->head, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&ring->tail, 0, __ATOMIC_RELAXED);
        ring->cookie = CNE_MEMIF_COOKIE;
        ring->flags  = 0;

        if (pmd->flags & CNE_ETH_MEMIF_FLAG_ZERO_COPY)
            continue;

        for (j = 0; j < (1 << pmd->run.log2_ring_size); j++) {
            slot = (i + pmd->run.num_c2s_rings) * (1 << pmd->run.log2_ring_size) + j;
            ring->desc[j].region = 0;
            ring->desc[j].offset = proc_private->regions[0]->pkt_buffer_offset +
                                   (uint32_t)(slot * pmd->run.pkt_buffer_size);
            ring->desc[j].length = pmd->run.pkt_buffer_size;
        }
    }
}

/* called only by client */
static int
cne_memif_init_queues(struct cne_pktdev *dev)
{
    struct pmd_internals *pmd = dev->data->dev_private;
    struct cne_memif_queue *mq;
    int i;

    for (i = 0; i < pmd->run.num_c2s_rings; i++) {
        mq                 = dev->data->tx_queue;
        mq->log2_ring_size = pmd->run.log2_ring_size;
        /* queues located only in region 0 */
        mq->region       = 0;
        mq->ring_offset  = cne_memif_get_ring_offset(dev, mq, CNE_MEMIF_RING_C2S, i);
        mq->last_head    = 0;
        mq->last_tail    = 0;
        mq->ev_handle.fd = eventfd(0, EFD_NONBLOCK);
        if (mq->ev_handle.fd < 0) {
            MIF_LOG(WARNING, "Failed to create eventfd for tx queue %d: %s.", i, strerror(errno));
        }
        mq->buffers = NULL;
        if (pmd->flags & CNE_ETH_MEMIF_FLAG_ZERO_COPY) {
            mq->buffers = calloc((1 << mq->log2_ring_size), sizeof(pktmbuf_t *));
            if (mq->buffers == NULL)
                return -ENOMEM;
        }
    }

    for (i = 0; i < pmd->run.num_s2c_rings; i++) {
        mq                 = dev->data->rx_queue;
        mq->log2_ring_size = pmd->run.log2_ring_size;
        /* queues located only in region 0 */
        mq->region       = 0;
        mq->ring_offset  = cne_memif_get_ring_offset(dev, mq, CNE_MEMIF_RING_S2C, i);
        mq->last_head    = 0;
        mq->last_tail    = 0;
        mq->ev_handle.fd = eventfd(0, EFD_NONBLOCK);
        if (mq->ev_handle.fd < 0) {
            MIF_LOG(WARNING, "Failed to create eventfd for rx queue %d: %s.", i, strerror(errno));
        }
        mq->buffers = NULL;
        if (pmd->flags & CNE_ETH_MEMIF_FLAG_ZERO_COPY) {
            mq->buffers = calloc((1 << mq->log2_ring_size), sizeof(pktmbuf_t *));
            if (mq->buffers == NULL)
                return -ENOMEM;
        }
    }
    return 0;
}

int
cne_memif_init_regions_and_queues(struct cne_pktdev *dev)
{
    int ret;

    ret = cne_memif_regions_init(dev);
    if (ret < 0)
        return ret;

    cne_memif_init_rings(dev);

    ret = cne_memif_init_queues(dev);
    if (ret < 0)
        return ret;

    return 0;
}
void
cne_memif_free_regions(struct cne_pktdev *dev)
{
    struct pmd_process_private *proc_private = dev->process_private;
    struct pmd_internals *pmd                = dev->data->dev_private;
    int i;
    struct cne_memif_region *r;

    /* regions are allocated contiguously, so it's
     * enough to loop until 'proc_private->regions_num'
     */
    for (i = 0; i < proc_private->regions_num; i++) {
        r = proc_private->regions[i];
        if (r != NULL) {
            if (i > 0 && (pmd->flags & CNE_ETH_MEMIF_FLAG_ZERO_COPY)) {
                r->addr = NULL;
                if (r->fd > 0)
                    close(r->fd);
            }
            if (r->addr != NULL) {
                munmap(r->addr, r->region_size);
                if (r->fd > 0) {
                    close(r->fd);
                    r->fd = -1;
                }
            }
            free(r);
            proc_private->regions[i] = NULL;
        }
    }
    proc_private->regions_num = 0;
}

int
cne_memif_connect(struct cne_pktdev *dev)
{

    struct pmd_internals *pmd                = dev->data->dev_private;
    struct pmd_process_private *proc_private = dev->process_private;

    struct cne_memif_region *mr;
    struct cne_memif_queue *mq;
    cne_memif_ring_t *ring;
    int i;

    for (i = 0; i < proc_private->regions_num; i++) {
        mr = proc_private->regions[i];
        if (mr != NULL) {
            if (mr->addr == NULL) {
                if (mr->fd < 0)
                    return -1;
                mr->addr =
                    mmap(NULL, mr->region_size, PROT_READ | PROT_WRITE, MAP_SHARED, mr->fd, 0);
                if (mr->addr == MAP_FAILED) {
                    MIF_LOG(ERR, "mmap failed: %s\n", strerror(errno));
                    return -1;
                }
            }
        }
    }

    for (i = 0; i < pmd->run.num_c2s_rings; i++) {
        mq   = (pmd->role == CNE_MEMIF_ROLE_CLIENT) ? dev->data->tx_queue : dev->data->rx_queue;
        ring = cne_memif_get_ring_from_queue(proc_private, mq);
        if (ring == NULL || ring->cookie != CNE_MEMIF_COOKIE) {
            MIF_LOG(ERR, "Wrong ring");
            return -1;
        }
        __atomic_store_n(&ring->head, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&ring->tail, 0, __ATOMIC_RELAXED);
        mq->last_head = 0;
        mq->last_tail = 0;
        /* enable polling mode */
        if (pmd->role == CNE_MEMIF_ROLE_SERVER)
            ring->flags = CNE_MEMIF_RING_FLAG_MASK_INT;
    }
    for (i = 0; i < pmd->run.num_s2c_rings; i++) {
        mq   = (pmd->role == CNE_MEMIF_ROLE_CLIENT) ? dev->data->rx_queue : dev->data->tx_queue;
        ring = cne_memif_get_ring_from_queue(proc_private, mq);
        if (ring == NULL || ring->cookie != CNE_MEMIF_COOKIE) {
            MIF_LOG(ERR, "Wrong ring");
            return -1;
        }
        __atomic_store_n(&ring->head, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&ring->tail, 0, __ATOMIC_RELAXED);
        mq->last_head = 0;
        mq->last_tail = 0;
        /* enable polling mode */
        if (pmd->role == CNE_MEMIF_ROLE_CLIENT)
            ring->flags = CNE_MEMIF_RING_FLAG_MASK_INT;
    }

    pmd->flags &= ~CNE_ETH_MEMIF_FLAG_CONNECTING;
    pmd->flags |= CNE_ETH_MEMIF_FLAG_CONNECTED;
    // dev->data->dev_link.link_status = ETH_LINK_UP;

    MIF_LOG(DEBUG, "Connected.");
    return 0;
}

int
cne_memif_connect_start(struct cne_pktdev *dev)
{
    struct pmd_internals *pmd = dev->data->dev_private;

    int ret = 0;

    switch (pmd->role) {
    case CNE_MEMIF_ROLE_CLIENT:
        ret = cne_memif_connect_client(dev);
        break;
    case CNE_MEMIF_ROLE_SERVER:
        ret = cne_memif_connect_server(dev);
        break;
    default:
        MIF_LOG(ERR, "Unknown role: %d.", pmd->role);
        ret = -1;
        break;
    }

    return ret;
}

static int
cne_memif_tx_queue_setup(struct cne_pktdev *dev)
{
    struct pmd_internals *pmd = dev->data->dev_private;
    struct cne_memif_queue *mq;

    mq = calloc(1, sizeof(struct cne_memif_queue));
    if (mq == NULL) {
        MIF_LOG(ERR, "Failed to allocate tx queue ");
        return -ENOMEM;
    }

    mq->type    = (pmd->role == CNE_MEMIF_ROLE_CLIENT) ? CNE_MEMIF_RING_C2S : CNE_MEMIF_RING_S2C;
    mq->n_pkts  = 0;
    mq->n_bytes = 0;
    mq->ev_handle.fd    = -1;
    mq->in_port         = dev->data->lport_id;
    dev->data->tx_queue = mq;

    return 0;
}

static int
cne_memif_rx_queue_setup(struct cne_pktdev *dev, pktmbuf_info_t *pi)
{
    struct pmd_internals *pmd = dev->data->dev_private;
    struct cne_memif_queue *mq;

    mq = calloc(1, sizeof(struct cne_memif_queue));
    if (mq == NULL) {
        MIF_LOG(ERR, "Failed to allocate rx queue ");
        return -ENOMEM;
    }

    mq->type    = (pmd->role == CNE_MEMIF_ROLE_CLIENT) ? CNE_MEMIF_RING_S2C : CNE_MEMIF_RING_C2S;
    mq->n_pkts  = 0;
    mq->n_bytes = 0;
    mq->ev_handle.fd    = -1;
    mq->pi              = pi;
    mq->in_port         = dev->data->lport_id;
    dev->data->rx_queue = mq;

    return 0;
}

static void
cne_memif_queue_release(void *queue)
{
    struct cne_memif_queue *mq = (struct cne_memif_queue *)queue;

    if (!mq)
        return;

    free(mq);
}

static int
cne_memif_queue_init(struct cne_pktdev *dev)
{
    struct pmd_internals *pmd = dev->data->dev_private;

    cne_memif_rx_queue_setup(dev, pmd->pi);

    cne_memif_tx_queue_setup(dev);

    return 0;
}

static uint16_t
cne_pmd_memif_socket_rx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    struct cne_memif_queue *mq               = queue;
    struct pmd_internals *pmd                = pktdev_devices[mq->in_port].data->dev_private;
    struct pmd_process_private *proc_private = pktdev_devices[mq->in_port].process_private;

    cne_memif_ring_t *ring = cne_memif_get_ring_from_queue(proc_private, mq);
    uint16_t cur_slot, last_slot, n_slots, ring_size, mask, s0;
    uint16_t n_rx_pkts = 0;
    uint16_t mbuf_size =
        pktmbuf_data_room_size((struct cne_mempool *)pmd->pi->pd) - CNE_PKTMBUF_HEADROOM;
    uint16_t src_len, src_off, dst_len, dst_off, cp_len;
    cne_memif_ring_type_t type = mq->type;
    cne_memif_desc_t *d0;
    pktmbuf_t *mbuf, *mbuf_head;
    uint64_t b;
    ssize_t size __cne_unused;
    uint16_t head;

    if (!ring || unlikely((pmd->flags & CNE_ETH_MEMIF_FLAG_CONNECTED) == 0))
        return 0;
    /* Todo add the link status check */

    /* consume interrupt */
    if ((ring->flags & CNE_MEMIF_RING_FLAG_MASK_INT) == 0)
        size = read(mq->ev_handle.fd, &b, sizeof(b));

    ring_size = 1 << mq->log2_ring_size;
    mask      = ring_size - 1;

    if (type == CNE_MEMIF_RING_C2S) {
        cur_slot  = mq->last_head;
        last_slot = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);
    } else {
        cur_slot  = mq->last_tail;
        last_slot = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
    }

    if (cur_slot == last_slot)
        goto refill;
    n_slots = last_slot - cur_slot;

    while (n_slots && n_rx_pkts < nb_pkts) {
        mbuf_head = pktmbuf_alloc(pmd->pi);
        if (unlikely(mbuf_head == NULL))
            goto no_free_bufs;
        mbuf        = mbuf_head;
        mbuf->lport = mq->in_port;
        dst_off     = 0;

    next_slot:
        s0 = cur_slot & mask;
        d0 = &ring->desc[s0];

        src_len = d0->length;
        src_off = 0;

        do {
            dst_len = mbuf_size - dst_off;
            if (dst_len == 0) {
                MIF_LOG(ERR, "CNDP MTU-overflow");
            }
            cp_len = CNE_MIN(dst_len, src_len);

            pktmbuf_data_len(mbuf) += cp_len;
            pktmbuf_buf_len(mbuf) = pktmbuf_data_len(mbuf);
            if (mbuf != mbuf_head)
                pktmbuf_buf_len(mbuf_head) += cp_len;

            memcpy(pktmbuf_mtod_offset(mbuf, void *, dst_off),
                   (uint8_t *)memif_get_buffer(proc_private, d0) + src_off, cp_len);

            src_off += cp_len;
            dst_off += cp_len;
            src_len -= cp_len;
        } while (src_len);

        cur_slot++;
        n_slots--;

        if (d0->flags & CNE_MEMIF_DESC_FLAG_NEXT)
            goto next_slot;

        mq->n_bytes += pktmbuf_buf_len(mbuf_head);
        *bufs++ = mbuf_head;
        n_rx_pkts++;
    }

no_free_bufs:
    if (type == CNE_MEMIF_RING_C2S) {
        __atomic_store_n(&ring->tail, cur_slot, __ATOMIC_RELEASE);
        mq->last_head = cur_slot;
    } else {
        mq->last_tail = cur_slot;
    }

refill:
    if (type == CNE_MEMIF_RING_S2C) {
        /* ring->head is updated by the receiver and this function
         * is called in the context of receiver thread. The loads in
         * the receiver do not need to synchronize with its own stores.
         */
        head    = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
        n_slots = ring_size - head + mq->last_tail;

        while (n_slots--) {
            s0         = head++ & mask;
            d0         = &ring->desc[s0];
            d0->length = pmd->run.pkt_buffer_size;
        }
        __atomic_store_n(&ring->head, head, __ATOMIC_RELEASE);
    }

    mq->n_pkts += n_rx_pkts;
    return n_rx_pkts;
}

static uint16_t
cne_pmd_memif_socket_tx(void *queue, pktmbuf_t **bufs, uint16_t nb_pkts)
{
    struct cne_memif_queue *mq               = queue;
    struct pmd_internals *pmd                = pktdev_devices[mq->in_port].data->dev_private;
    struct pmd_process_private *proc_private = pktdev_devices[mq->in_port].process_private;
    cne_memif_ring_t *ring                   = cne_memif_get_ring_from_queue(proc_private, mq);
    uint16_t slot, saved_slot, n_free, ring_size, mask, n_tx_pkts = 0;
    uint16_t src_len, src_off, dst_len, dst_off, cp_len;
    cne_memif_ring_type_t type = mq->type;
    cne_memif_desc_t *d0;
    pktmbuf_t *mbuf, *mbuf_head;
    uint64_t a;
    ssize_t size;

    if (unlikely((pmd->flags & CNE_ETH_MEMIF_FLAG_CONNECTED) == 0))
        return 0;
    if (unlikely(ring == NULL))
        return 0;

    ring_size = 1 << mq->log2_ring_size;
    mask      = ring_size - 1;

    if (type == CNE_MEMIF_RING_C2S) {
        /* For C2S queues ring->head is updated by the sender and
         * this function is called in the context of sending thread.
         * The loads in the sender do not need to synchronize with
         * its own stores. Hence, the following load can be a
         * relaxed load.
         */
        slot   = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
        n_free = ring_size - slot + __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
    } else {
        /* For S2C queues ring->tail is updated by the sender and
         * this function is called in the context of sending thread.
         * The loads in the sender do not need to synchronize with
         * its own stores. Hence, the following load can be a
         * relaxed load.
         */
        slot   = __atomic_load_n(&ring->tail, __ATOMIC_RELAXED);
        n_free = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE) - slot;
    }

    while (n_tx_pkts < nb_pkts && n_free) {
        mbuf_head = *bufs++;
        mbuf      = mbuf_head;

        saved_slot = slot;
        d0         = &ring->desc[slot & mask];
        dst_off    = 0;
        dst_len    = (type == CNE_MEMIF_RING_C2S) ? pmd->run.pkt_buffer_size : d0->length;

        src_off = 0;
        src_len = pktmbuf_data_len(mbuf);

        while (src_len) {
            if (dst_len == 0) {
                if (n_free) {
                    slot++;
                    n_free--;
                    d0->flags |= CNE_MEMIF_DESC_FLAG_NEXT;
                    d0      = &ring->desc[slot & mask];
                    dst_off = 0;
                    dst_len = (type == CNE_MEMIF_RING_C2S) ? pmd->run.pkt_buffer_size : d0->length;
                    d0->flags = 0;
                } else {
                    slot = saved_slot;
                    goto no_free_slots;
                }
            }
            cp_len = CNE_MIN(dst_len, src_len);

            memcpy((uint8_t *)memif_get_buffer(proc_private, d0) + dst_off,
                   pktmbuf_mtod_offset(mbuf, void *, src_off), cp_len);

            mq->n_bytes += cp_len;
            src_off += cp_len;
            dst_off += cp_len;
            src_len -= cp_len;
            dst_len -= cp_len;

            d0->length = dst_off;
        }

        /* CNDP has no chain support */

        n_tx_pkts++;
        slot++;
        n_free--;
        pktmbuf_free(mbuf_head);
    }

no_free_slots:
    if (type == CNE_MEMIF_RING_C2S)
        __atomic_store_n(&ring->head, slot, __ATOMIC_RELEASE);
    else
        __atomic_store_n(&ring->tail, slot, __ATOMIC_RELEASE);

    if ((ring->flags & CNE_MEMIF_RING_FLAG_MASK_INT) == 0) {
        a    = 1;
        size = write(mq->ev_handle.fd, &a, sizeof(a));
        if (unlikely(size < 0)) {
            MIF_LOG(WARNING, "Failed to send interrupt. %s", strerror(errno));
        }
    }

    mq->n_pkts += n_tx_pkts;
    return n_tx_pkts;
}

static int
pmd_dev_info(struct cne_pktdev *dev, struct pktdev_info *dev_info)
{
    struct pmd_internals *internals = dev->data->dev_private;

    dev_info->driver_name    = internals->pmd_name;
    dev_info->max_rx_pktlen  = (uint32_t)-1;
    dev_info->min_rx_bufsize = 0;

    return 0;
}

static int
pmd_stats_get(struct cne_pktdev *dev, lport_stats_t *stats)
{
    struct cne_memif_queue *mq;

    stats->ipackets = 0;
    stats->ibytes   = 0;
    stats->opackets = 0;
    stats->obytes   = 0;

    /* RX stats */
    mq = dev->data->rx_queue;
    stats->ipackets += mq->n_pkts;
    stats->ibytes += mq->n_bytes;

    /* TX stats */
    mq = dev->data->tx_queue;
    stats->opackets += mq->n_pkts;
    stats->obytes += mq->n_bytes;

    return 0;
}

static int
pmd_stats_reset(struct cne_pktdev *dev)
{
    struct cne_memif_queue *mq;

    mq          = dev->data->rx_queue;
    mq->n_pkts  = 0;
    mq->n_bytes = 0;

    mq          = dev->data->tx_queue;
    mq->n_pkts  = 0;
    mq->n_bytes = 0;

    return 0;
}

static void
pmd_dev_close(struct cne_pktdev *dev)
{
    struct pmd_internals *pmd = dev->data->dev_private;

    if (pmd->cc)
        cne_memif_msg_enq_disconnect(pmd->cc, "Device closed", 0);
    cne_memif_disconnect(dev);

    cne_memif_queue_release(dev->data->rx_queue);
    cne_memif_queue_release(dev->data->tx_queue);

    cne_memif_socket_remove_device(dev);

    free(dev->process_private);
}

static int
pmd_pkt_alloc(struct cne_pktdev *dev, pktmbuf_t **pkts, uint16_t nb_pkts)
{
    struct pmd_internals *pmd = dev->data->dev_private;
    return pktmbuf_alloc_bulk(pmd->pi, pkts, nb_pkts);
}

static const struct pktdev_ops ops = {
    .dev_close     = pmd_dev_close,
    .dev_infos_get = pmd_dev_info,
    .stats_get     = pmd_stats_get,
    .stats_reset   = pmd_stats_reset,
    .pkt_alloc     = pmd_pkt_alloc,
};

static int cne_pmd_memif_socket_probe(lport_cfg_t *c);

static struct pktdev_driver memif_socket_drv = {
    .probe = cne_pmd_memif_socket_probe,
};

PMD_REGISTER_DEV(net_memif_socket, memif_socket_drv);

static int
cne_memif_create(struct cne_pktdev *dev, enum cne_memif_role_t role, cne_memif_interface_id_t id,
                 uint32_t flags, const char *socket_filename,
                 cne_memif_log2_ring_size_t log2_ring_size, uint16_t pkt_buffer_size,
                 const char *secret, pktmbuf_info_t *pi)
{

    int ret = 0;
    struct pktdev_data *data;
    struct pmd_internals *internals;

    internals = calloc(1, sizeof(*internals));

    if (!internals) {
        ret = ENOMEM;
        goto error;
    }

    internals->id    = id;
    internals->flags = flags;
    internals->flags |= CNE_ETH_MEMIF_FLAG_DISABLED;
    internals->role = role;
    internals->pi   = pi;

    /* Zero-copy flag irrelevant to server. */
    if (internals->role == CNE_MEMIF_ROLE_SERVER)
        internals->flags &= ~CNE_ETH_MEMIF_FLAG_ZERO_COPY;

    memset(internals->secret, 0, sizeof(char) * CNE_ETH_MEMIF_SECRET_SIZE);

    if (secret != NULL)
        strlcpy(internals->secret, secret, sizeof(internals->secret));

    internals->cfg.log2_ring_size = log2_ring_size;
    /* set in to 2 due to only 1 rx queue and 1 tx queue */
    internals->cfg.num_c2s_rings = 2;
    internals->cfg.num_s2c_rings = 2;

    internals->cfg.pkt_buffer_size = pkt_buffer_size;
    cne_spinlock_init(&internals->cc_lock);

    data              = dev->data;
    data->dev_private = internals;

    dev->dev_ops = &ops;

    dev->rx_pkt_burst = cne_pmd_memif_socket_rx;
    dev->tx_pkt_burst = cne_pmd_memif_socket_tx;

    ret = cne_memif_socket_init(dev, socket_filename);

    if (ret < 0) {
        goto error;
    }

    return ret;

error:
    free(internals);

    return ret;
}

static int
cne_pmd_memif_socket_probe(lport_cfg_t *c)
{
    struct cne_pktdev *dev;
    CNE_BUILD_BUG_ON(sizeof(cne_memif_msg_t) != 128);
    CNE_BUILD_BUG_ON(sizeof(cne_memif_desc_t) != 16);
    int ret                                   = 0;
    enum cne_memif_role_t role                = CNE_MEMIF_ROLE_SERVER;
    cne_memif_interface_id_t id               = 0;
    uint16_t pkt_buffer_size                  = CNE_ETH_MEMIF_DEFAULT_PKT_BUFFER_SIZE;
    cne_memif_log2_ring_size_t log2_ring_size = CNE_ETH_MEMIF_DEFAULT_RING_SIZE;
    const char *socket_filename               = CNE_ETH_MEMIF_DEFAULT_SOCKET_FILENAME;
    uint32_t flags                            = 0;
    const char *secret                        = NULL;

    if (!c)
        CNE_ERR_RET("Invalid Configure Pointer\n");

    if (!strcasecmp(c->pmd_opts, "client"))
        role = CNE_MEMIF_ROLE_CLIENT;
    else if (!strcasecmp(c->pmd_opts, "server"))
        role = CNE_MEMIF_ROLE_SERVER;
    else
        CNE_ERR_RET("Not Support Mode\n");

    CNE_LOG(DEBUG, "Initializing memif_socket for %s\n", c->ifname);

    dev = pktdev_allocate(c->name, c->ifname);
    if (!dev)
        CNE_ERR_GOTO(exit, "Failed to init lport\n");

    dev->drv = &memif_socket_drv;

    /* use abstract address by default */
    flags |= CNE_ETH_MEMIF_FLAG_SOCKET_ABSTRACT;

    if (!(flags & CNE_ETH_MEMIF_FLAG_SOCKET_ABSTRACT)) {
        ret = cne_memif_check_socket_filename(socket_filename);
        if (ret < 0)
            goto exit;
    }

    dev->process_private = calloc(1, sizeof(struct pmd_process_private));

    /* create interface */
    ret = cne_memif_create(dev, role, id, flags, socket_filename, log2_ring_size, pkt_buffer_size,
                           secret, c->pi);

    cne_memif_queue_init(dev);

    cne_memif_connect_start(dev);

    return (pktdev_portid(dev));
exit:
    pktdev_release_port(dev);

    return ret;
}
