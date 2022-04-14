/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

#include <errno.h>                        // for errno, ENODEV, ENOMEM, EINVAL
#include <fcntl.h>                        // for open, O_RDWR
#include <pthread.h>                      // for pthread_mutex_unlock, pthread_mut...
#include <stdio.h>                        // for NULL, snprintf
#include <stdint.h>                       // for uint16_t, uintptr_t, uint32_t
#include <string.h>                       // for strerror, memset
#include <sys/mman.h>                     // for munmap, mmap, MAP_FAILED, MAP_SHARED
#include <cne_branch_prediction.h>        // for unlikely
#include <cne_isa.h>                      // for cne_movdir64b
#include <cne_log.h>                      // for CNE_ERR, CNE_INFO, CNE_LOG_ERR
#include <cne_prefetch.h>                 // for cne_prefetch0
#include <limits.h>                       // for PATH_MAX
#include <stdlib.h>                       // for free, calloc, aligned_alloc
#include <unistd.h>                       // for close
#include <xmmintrin.h>                    // IWYU pragma: keep

#include "cne_dsa.h"
#include "dsa_priv.h"          // for dsa, idxd_hw_desc, dsa_user_hdl
#include "cne_common.h"        // for phys_addr_t, CNE_CACHE_LINE_SIZE

#define MAX_DSA_DEVICES 32
static struct dsa *dsa_devs[MAX_DSA_DEVICES];
static pthread_mutex_t dsa_devs_lock = PTHREAD_MUTEX_INITIALIZER;

#define DSA_DEV(i) ((i) < MAX_DSA_DEVICES ? dsa_devs[i] : NULL)

uint16_t
dsa_burst_capacity(uint16_t dev)
{
    uint16_t write_idx, used_space, free_space;
    struct dsa *idxd = DSA_DEV(dev);

    if (!idxd)
        return 0;

    write_idx = idxd->batch_start + idxd->batch_size;

    /* Check for space in the batch ring */
    if ((idxd->batch_idx_read == 0 && idxd->batch_idx_write == idxd->max_batches) ||
        idxd->batch_idx_write + 1 == idxd->batch_idx_read)
        return 0;

    /* for descriptors, check for wrap-around on write but not read */
    if (idxd->hdls_read > write_idx)
        write_idx += idxd->desc_ring_mask + 1;
    used_space = write_idx - idxd->hdls_read;

    /* Return amount of free space in the descriptor ring
     * subtract 1 for space for batch descriptor and 1 for possible null desc
     */
    free_space = idxd->desc_ring_mask - used_space;
    if (free_space < 2)
        return 0;
    return free_space - 2;
}

static inline uint64_t
__desc_idx_to_iova(struct dsa *idxd, uint16_t n)
{
    return idxd->desc_iova + (n * sizeof(struct idxd_hw_desc));
}

static inline int
__idxd_write_desc(struct dsa *idxd, const uint32_t op_flags, const uint64_t src, const uint64_t dst,
                  const uint32_t size, const struct dsa_user_hdl *hdl)
{
    uint16_t write_idx = idxd->batch_start + idxd->batch_size;
    uint16_t mask      = idxd->desc_ring_mask;

    /* first check batch ring space then desc ring space */
    if ((idxd->batch_idx_read == 0 && idxd->batch_idx_write == idxd->max_batches) ||
        idxd->batch_idx_write + 1 == idxd->batch_idx_read)
        goto failed;

    /* for descriptor ring, we always need a slot for batch completion */
    if (((write_idx + 2) & mask) == idxd->hdls_read || ((write_idx + 1) & mask) == idxd->hdls_read)
        goto failed;

    /* write desc and handle. Note, descriptors don't wrap */
    idxd->desc_ring[write_idx].pasid      = 0;
    idxd->desc_ring[write_idx].op_flags   = op_flags | IDXD_FLAG_COMPLETION_ADDR_VALID;
    idxd->desc_ring[write_idx].completion = __desc_idx_to_iova(idxd, write_idx & mask);
    idxd->desc_ring[write_idx].src        = src;
    idxd->desc_ring[write_idx].dst        = dst;
    idxd->desc_ring[write_idx].size       = size;

    if (!hdl)
        idxd->hdl_ring_flags[write_idx & mask] = DSA_HDL_INVALID;
    else
        idxd->hdl_ring[write_idx & mask] = *hdl;
    idxd->batch_size++;

    idxd->stats.enqueued++;

    cne_prefetch0(&idxd->desc_ring[write_idx + 1]);
    return 1;

failed:
    idxd->stats.enqueue_failed++;
    errno = ENOSPC;
    return 0;
}

int
dsa_enqueue_fill(uint16_t dev, uint64_t pattern, phys_addr_t dst, uint32_t length,
                 uintptr_t dst_hdl)
{
    const struct dsa_user_hdl hdl = {.dst = dst_hdl};
    struct dsa *idxd              = DSA_DEV(dev);

    if (!idxd) {
        errno = ENODEV;
        return 0;
    }

    return __idxd_write_desc(idxd, (idxd_op_fill << IDXD_CMD_OP_SHIFT) | IDXD_FLAG_CACHE_CONTROL,
                             pattern, dst, length, &hdl);
}

int
dsa_enqueue_copy(uint16_t dev, phys_addr_t src, phys_addr_t dst, uint32_t length, uintptr_t src_hdl,
                 uintptr_t dst_hdl)
{
    const struct dsa_user_hdl hdl = {.src = src_hdl, .dst = dst_hdl};
    struct dsa *idxd              = DSA_DEV(dev);

    if (!idxd) {
        errno = ENODEV;
        return 0;
    }

    return __idxd_write_desc(idxd, (idxd_op_memmove << IDXD_CMD_OP_SHIFT) | IDXD_FLAG_CACHE_CONTROL,
                             src, dst, length, &hdl);
}

/* Used by dsa_fence() and dsa_perform_ops() after validating dsa param */
static inline int
__idxd_fence(struct dsa *idxd)
{
    /* only op field needs filling - zero src, dst and length */
    return __idxd_write_desc(idxd, IDXD_FLAG_FENCE, 0, 0, 0, NULL);
}

int
dsa_fence(uint16_t dev)
{
    struct dsa *idxd = DSA_DEV(dev);

    if (!idxd) {
        errno = ENODEV;
        return 0;
    }

    return __idxd_fence(idxd);
}

int
dsa_perform_ops(uint16_t dev)
{
    struct dsa *idxd = DSA_DEV(dev);
    uint16_t comp_idx;

    if (!idxd) {
        errno = ENODEV;
        return -1;
    }

    if (idxd->batch_size == 0)
        return 0;

    if (idxd->batch_size == 1)
        /* use a fence as a null descriptor, so batch_size >= 2 */
        if (__idxd_fence(idxd) != 1)
            return -1;

    /* write completion beyond last desc in the batch */
    comp_idx = (idxd->batch_start + idxd->batch_size) & idxd->desc_ring_mask;
    *((uint64_t *)&idxd->desc_ring[comp_idx]) = 0; /* zero start of desc */
    idxd->hdl_ring_flags[comp_idx]            = DSA_HDL_INVALID;

    const struct idxd_hw_desc batch_desc = {
        .op_flags = (idxd_op_batch << IDXD_CMD_OP_SHIFT) | IDXD_FLAG_COMPLETION_ADDR_VALID |
                    IDXD_FLAG_REQUEST_COMPLETION,
        .desc_addr  = __desc_idx_to_iova(idxd, idxd->batch_start),
        .completion = __desc_idx_to_iova(idxd, comp_idx),
        .size       = idxd->batch_size,
    };

    _mm_sfence(); /* fence before writing desc to device */
    if (idxd->portal)
        cne_movdir64b(idxd->portal, &batch_desc);
    else
        dsa_perform_ops_in_software(idxd, &batch_desc);
    idxd->stats.started += idxd->batch_size;

    idxd->batch_start += idxd->batch_size + 1;
    idxd->batch_start &= idxd->desc_ring_mask;
    idxd->batch_size = 0;

    idxd->batch_idx_ring[idxd->batch_idx_write++] = comp_idx;
    if (idxd->batch_idx_write > idxd->max_batches)
        idxd->batch_idx_write = 0;

    return 0;
}

int
dsa_completed_ops(uint16_t dev, uint8_t max_ops, uint32_t *status, uint8_t *num_unsuccessful,
                  uintptr_t *src_hdls, uintptr_t *dst_hdls)
{
    struct dsa *idxd = DSA_DEV(dev);
    uint16_t n, h_idx;

    if (!idxd) {
        errno = ENODEV;
        return -1;
    }

    if (num_unsuccessful)
        *num_unsuccessful = 0;

    while (idxd->batch_idx_read != idxd->batch_idx_write) {
        uint16_t idx_to_chk = idxd->batch_idx_ring[idxd->batch_idx_read];
        volatile struct idxd_completion *comp_to_chk =
            (struct idxd_completion *)&idxd->desc_ring[idx_to_chk];
        uint8_t batch_status = comp_to_chk->status;

        if (batch_status == 0)
            break;

        comp_to_chk->status = 0;
        if (unlikely(batch_status > 1)) {
            /* error occurred somewhere in batch, start where last checked */
            uint16_t desc_count  = comp_to_chk->completed_size;
            uint16_t batch_start = idxd->hdls_avail;
            uint16_t batch_end   = idx_to_chk;

            if (batch_start > batch_end)
                batch_end += idxd->desc_ring_mask + 1;

            /* go through each batch entry and see status */
            for (n = 0; n < desc_count; n++) {
                uint16_t idx = (batch_start + n) & idxd->desc_ring_mask;
                volatile struct idxd_completion *comp =
                    (struct idxd_completion *)&idxd->desc_ring[idx];

                if (comp->status != 0 && idxd->hdl_ring_flags[idx] == DSA_HDL_NORMAL) {
                    idxd->hdl_ring_flags[idx] = DSA_HDL_OP_FAILED;
                    idxd->hdl_ring_flags[idx] |= (comp->status << 8);
                    comp->status = 0; /* clear error for next time */
                }
            }

            /* if batch is incomplete, mark rest as skipped */
            for (; n < batch_end - batch_start; n++) {
                uint16_t idx = (batch_start + n) & idxd->desc_ring_mask;

                if (idxd->hdl_ring_flags[idx] == DSA_HDL_NORMAL)
                    idxd->hdl_ring_flags[idx] = DSA_HDL_OP_SKIPPED;
            }
        }

        /* avail points to one after the last one written */
        idxd->hdls_avail = (idx_to_chk + 1) & idxd->desc_ring_mask;
        idxd->batch_idx_read++;
        if (idxd->batch_idx_read > idxd->max_batches)
            idxd->batch_idx_read = 0;
    }

    n     = 0;
    h_idx = idxd->hdls_read;
    while (h_idx != idxd->hdls_avail) {
        uint16_t flag = idxd->hdl_ring_flags[h_idx];

        if (flag != DSA_HDL_INVALID) {
            if (src_hdls)
                src_hdls[n] = idxd->hdl_ring[h_idx].src;

            if (dst_hdls)
                dst_hdls[n] = idxd->hdl_ring[h_idx].dst;

            if (unlikely(flag != DSA_HDL_NORMAL)) {
                if (status) {
                    if (flag == DSA_HDL_OP_SKIPPED)
                        status[n] = DSA_OP_SKIPPED;
                    else
                        /* failure case, return err code */
                        status[n] = idxd->hdl_ring_flags[h_idx] >> 8;
                }
                if (num_unsuccessful)
                    *num_unsuccessful += 1;
            }
            n++;
        }

        idxd->hdl_ring_flags[h_idx] = DSA_HDL_NORMAL;
        if (++h_idx > idxd->desc_ring_mask)
            h_idx = 0;
        if (n >= max_ops)
            break;
    }

    /* skip over any remaining blank elements, e.g. batch completion */
    while (idxd->hdl_ring_flags[h_idx] == DSA_HDL_INVALID && h_idx != idxd->hdls_avail) {
        idxd->hdl_ring_flags[h_idx] = DSA_HDL_NORMAL;
        if (++h_idx > idxd->desc_ring_mask)
            h_idx = 0;
    }
    idxd->hdls_read = h_idx;

    idxd->stats.completed += n;
    return n;
}

static void
free_dsa(struct dsa *idxd)
{
    if (!idxd)
        return;
    free(idxd->hdl_ring_flags);
    free(idxd->hdl_ring);
    free(idxd->desc_ring);
    free(idxd->batch_idx_ring);
    free(idxd);
}

static struct dsa *
alloc_dsa(void)
{
    struct dsa *idxd = calloc(1, sizeof(*idxd));

    if (!idxd)
        goto err_out;

    /* The +1 is because we can never fully use the ring, otherwise read == write means
     * both full and empty.
     */
    idxd->batch_idx_ring = calloc(DSA_MAX_BATCHES + 1, sizeof(*idxd->batch_idx_ring));
    if (!idxd->batch_idx_ring)
        goto err_out;

    /* The desc_ring must be 32B aligned for completions as per DSA spec 3.6 "Descriptor
     * Completion". The cache line alignment works. Allocate the descriptor ring
     * at 2x size as batches cannot wrap.
     */
    idxd->desc_ring =
        aligned_alloc(CNE_CACHE_LINE_SIZE, DSA_NUM_DESC * 2 * sizeof(*idxd->desc_ring));
    if (!idxd->desc_ring)
        goto err_out;

    memset(idxd->desc_ring, 0, DSA_NUM_DESC * 2 * sizeof(*idxd->desc_ring));

    idxd->hdl_ring = calloc(DSA_NUM_DESC, sizeof(*idxd->hdl_ring));
    if (!idxd->hdl_ring)
        goto err_out;

    idxd->hdl_ring_flags = calloc(DSA_NUM_DESC, sizeof(*idxd->hdl_ring_flags));
    if (!idxd->hdl_ring_flags)
        goto err_out;

    return idxd;

err_out:
    free_dsa(idxd);
    return NULL;
}

int
dsa_get_stats(uint16_t dev, struct dsa_stats *stats)
{
    struct dsa *idxd = DSA_DEV(dev);

    if (!idxd) {
        errno = ENODEV;
        return -1;
    }

    if (!stats) {
        errno = EINVAL;
        return -1;
    }

    *stats = idxd->stats;
    return 0;
}

int16_t
dsa_open(const char *name)
{
    char path[PATH_MAX];
    void *addr = NULL;
    struct dsa *idxd;
    int fd, err = 0;
    uint16_t i;

    if (pthread_mutex_lock(&dsa_devs_lock))
        return -1;

    /* Look for free slot in device list */
    for (i = 0; i < MAX_DSA_DEVICES; i++)
        if (!dsa_devs[i])
            break;

    if (i == MAX_DSA_DEVICES) {
        /* No free slot */
        err = ENOMEM;
        goto err_out;
    }

    if (name) {
        snprintf(path, sizeof(path), "/dev/dsa/%s", name);
        fd = open(path, O_RDWR);
        if (fd < 0) {
            CNE_INFO("Failed to open /dev/dsa/%s (%s), falling back to software mode\n", name,
                     strerror(errno));
        } else {
            /* The mmap size is 4KB as per DSA spec 3.3 "Work Queues". */
            addr = mmap(NULL, 0x1000, PROT_WRITE, MAP_SHARED, fd, 0);
            close(fd);

            if (addr == MAP_FAILED) {
                CNE_INFO("Failed to mmap /dev/dsa/%s (%s), falling back to software mode\n", name,
                         strerror(errno));
                addr = NULL;
            }
        }
    } else
        CNE_INFO("Invalid name, falling back to software mode\n");

    idxd = alloc_dsa();
    if (!idxd) {
        err = ENOMEM;
        goto err_out;
    }

    idxd->portal         = addr;
    idxd->desc_iova      = (uintptr_t)idxd->desc_ring;
    idxd->max_batches    = DSA_MAX_BATCHES;
    idxd->desc_ring_mask = DSA_NUM_DESC - 1;
    dsa_devs[i]          = idxd;

    if (pthread_mutex_unlock(&dsa_devs_lock))
        CNE_ERR("pthread_mutex_unlock() failed: %s\n", strerror(errno));

    return i;

err_out:
    if (addr)
        (void)munmap(addr, 0x1000);
    if (pthread_mutex_unlock(&dsa_devs_lock))
        CNE_ERR("pthread_mutex_unlock() failed: %s\n", strerror(errno));
    errno = err;
    return -1;
}

int
dsa_close(uint16_t dev)
{
    int ret = -1, err = 0;
    struct dsa *idxd;

    if (pthread_mutex_lock(&dsa_devs_lock))
        return ret;

    idxd = DSA_DEV(dev);
    if (!idxd) {
        err = ENODEV;
        goto leave;
    }

    if (idxd->portal) {
        if (munmap(idxd->portal, 0x1000)) {
            err = errno;
            goto leave;
        }
    }

    free_dsa(idxd);
    dsa_devs[dev] = NULL;

    ret = 0;

leave:
    if (pthread_mutex_unlock(&dsa_devs_lock))
        CNE_ERR("pthread_mutex_unlock() failed: %s\n", strerror(errno));
    errno = err;
    return ret;
}
