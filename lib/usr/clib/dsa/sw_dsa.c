/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */

#include <stdbool.h>        // for bool, false, true
#include <stdint.h>         // for uint8_t, uintptr_t, uint32_t, uint16_t
#include <string.h>         // for memmove

#include "dsa_priv.h"        // for idxd_hw_desc, dsa, idxd_completion, idxd_hw_de...

/**
 * @file
 *
 * Emulate an Intel(R) Data Streaming Accelerator (DSA) in software.
 * Prefix macros and functions with "__" so they do not class with the "real" device
 * names.
 */

/** Status codes reported by the device, which this file emulates */
#define __IDXD_STS_SUCCESS     0x1  /**< Success */
#define __IDXD_STS_ADDR_ERR    0x3  /**< Page Fault */
#define __IDXD_STS_BATCH_FAIL  0x5  /**< One or more op failed in a batch */
#define __IDXD_STS_UNSUPPORTED 0x10 /**< Opcode is not supported */

/**
 * Write completion record status
 *
 * Status is written on error or if a completion is requested in descriptor flags.
 * @param desc
 *   The request descriptor, with op_flags and completion populated.
 * @param status
 *   The status to write in the completion record pointed to by the request descriptor.
 * @return
 *   0 if status is successful, otherwise -1.
 */
static inline int
write_completion_status(const struct idxd_hw_desc *desc, uint8_t status)
{
    struct idxd_completion *comp = (struct idxd_completion *)(uintptr_t)desc->completion;

    if (comp && (status != __IDXD_STS_SUCCESS || desc->op_flags & IDXD_FLAG_REQUEST_COMPLETION))
        comp->status = status;

    return status == __IDXD_STS_SUCCESS ? 0 : -1;
}

static inline int
__dsa_perform_op_nop(struct idxd_hw_desc *desc)
{
    return write_completion_status(desc, __IDXD_STS_SUCCESS);
}

static inline int
__dsa_perform_op_batch(const struct idxd_hw_desc *desc, uint32_t completed_size, bool success)
{
    struct idxd_completion *comp = (struct idxd_completion *)(uintptr_t)desc->completion;
    uint8_t status               = __IDXD_STS_SUCCESS;

    if (!success)
        status = __IDXD_STS_BATCH_FAIL;

    if (comp)
        comp->completed_size = completed_size;

    return write_completion_status(desc, status);
}

static inline int
__dsa_perform_op_memmove(struct idxd_hw_desc *desc)
{
    uint8_t status = __IDXD_STS_SUCCESS;
    void *dst      = (void *)(uintptr_t)desc->dst;
    void *src      = (void *)(uintptr_t)desc->src;

    /* error if src/dst is NULL, or memmove() fails */
    if (dst && src) {
        if (memmove(dst, src, desc->size) != dst)
            status = __IDXD_STS_ADDR_ERR;
    } else
        status = __IDXD_STS_ADDR_ERR;

    return write_completion_status(desc, status);
}

static inline int
__dsa_perform_op_fill(struct idxd_hw_desc *desc)
{
    uint8_t status = __IDXD_STS_SUCCESS;
    uint8_t *dst   = (uint8_t *)(uintptr_t)desc->dst;
    uint8_t *src   = (uint8_t *)&desc->src;
    uint32_t i;

    if (dst)
        for (i = 0; i < desc->size; i++)
            dst[i] = src[i % 8];
    else
        status = __IDXD_STS_ADDR_ERR;

    return write_completion_status(desc, status);
}

static inline int
__dsa_perform_op_unsupported(struct idxd_hw_desc *desc)
{
    return write_completion_status(desc, __IDXD_STS_UNSUPPORTED);
}

void
dsa_perform_ops_in_software(struct dsa *idxd, const struct idxd_hw_desc *batch_desc)
{
    bool success = true, fence = false;
    struct idxd_hw_desc *desc;
    uint16_t i;
    int err;

    for (i = idxd->batch_start; i < idxd->batch_start + idxd->batch_size; i++) {
        desc = &idxd->desc_ring[i];
        switch (desc->op_flags >> IDXD_CMD_OP_SHIFT) {
        case idxd_op_nop:
            err = __dsa_perform_op_nop(desc);
            break;
        case idxd_op_memmove:
            err = __dsa_perform_op_memmove(desc);
            break;
        case idxd_op_fill:
            err = __dsa_perform_op_fill(desc);
            break;
        default:
            err = __dsa_perform_op_unsupported(desc);
            break;
        }
        if (desc->op_flags & IDXD_FLAG_FENCE)
            fence = true;
        if (err)
            success = false;
        if (fence && !success)
            break;
    }

    __dsa_perform_op_batch(batch_desc, i - idxd->batch_start, success);
}
