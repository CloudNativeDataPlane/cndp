/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */

#ifndef _DSA_PRIV_H_
#define _DSA_PRIV_H_

#include <stdbool.h>
#include <stdint.h>
#include <cne_common.h>

#include "cne_dsa.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Variable names are chosen such that anything that is a hardware structure or enumeration is
 * prefixed with "idxd". Anything that is a software construct is prefixed with "dsa".
 */

/*
 * Defines used in the data path for interacting with IDXD hardware.
 */
#define IDXD_CMD_OP_SHIFT 24
enum idxd_ops { idxd_op_nop = 0, idxd_op_batch, idxd_op_drain, idxd_op_memmove, idxd_op_fill };

#define IDXD_FLAG_FENCE                 (1 << 0)
#define IDXD_FLAG_COMPLETION_ADDR_VALID (1 << 2)
#define IDXD_FLAG_REQUEST_COMPLETION    (1 << 3)
#define IDXD_FLAG_CACHE_CONTROL         (1 << 8)

/**
 * Hardware descriptor used by DSA, for both burst and individual operations.
 */
struct idxd_hw_desc {
    uint32_t pasid;
    uint32_t op_flags;
    uint64_t completion;

    CNE_STD_C11
    union {
        uint64_t src;       /* source address for copy ops etc. */
        uint64_t desc_addr; /* descriptor pointer for batch */
    };
    uint64_t dst;

    uint32_t size; /* length of data for op, or batch size */

    uint16_t intr_handle; /* completion interrupt handle */

    /* remaining 26 bytes are reserved */
    uint16_t __reserved[13];
} __cne_aligned(64);

/**
 * Completion record structure written back by DSA
 */
struct idxd_completion {
    uint8_t status;
    uint8_t result;
    /* 16-bits pad here */
    uint32_t completed_size; /* data length, or descriptors for batch */

    uint64_t fault_address;
    uint32_t invalid_flags;
} __cne_aligned(32);

/* Maximum batches to submit to hardware */
#define DSA_MAX_BATCHES 32

/* Maximum descriptors in the request/completion ring */
#define DSA_NUM_DESC 1024

/**
 * structure used to save the "handles" provided by the user to be
 * returned to the user on job completion.
 */
struct dsa_user_hdl {
    uint64_t src;
    uint64_t dst;
};

/**
 * Structure representing an IDXD device instance
 */
struct dsa {
    struct dsa_stats stats;

    /* address to write the batch descriptor */
    void *portal;

    /* base address of desc ring, needed for completions */
    uint64_t desc_iova;

    /* counters to track the batches */
    uint16_t max_batches;
    uint16_t batch_idx_read;
    uint16_t batch_idx_write;

    /* store where each batch ends */
    uint16_t *batch_idx_ring;

    /* track descriptors and handles */
    uint16_t desc_ring_mask;
    uint16_t hdls_avail;  /**< handles for ops completed */
    uint16_t hdls_read;   /**< the read pointer for hdls/desc rings */
    uint16_t batch_start; /**< start+size == write pointer for hdls/desc */
    uint16_t batch_size;

    struct idxd_hw_desc *desc_ring;
    struct dsa_user_hdl *hdl_ring;

    /* flags to indicate handle validity. Kept separate from ring to avoid
     * using 8 bytes per flag. Upper 8 bits holds error code if any.
     */
    uint16_t *hdl_ring_flags;
};

#define DSA_HDL_NORMAL     0
#define DSA_HDL_INVALID    (1 << 0) /* no handle stored for this element */
#define DSA_HDL_OP_FAILED  (1 << 1) /* return failure for this one */
#define DSA_HDL_OP_SKIPPED (1 << 2) /* this op was skipped */

/**
 * DSA device software emulator
 *
 * @param idxd
 *   Pointer to the DSA device structure
 * @param batch_desc
 *   Pointer to the batch descriptor
 */
void dsa_perform_ops_in_software(struct dsa *idxd, const struct idxd_hw_desc *batch_desc);

#ifdef __cplusplus
}
#endif
#endif /* _DSA_PRIV_H_ */
