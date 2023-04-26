/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#ifndef _CNE_DSA_H_
#define _CNE_DSA_H_

/**
 * @file
 *
 * Interact with Intel(R) Data Streaming Accelerator (DSA).
 */

#include <stdint.h>
#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Status codes for operations. See dsa_completed_ops(). Values >1 indicate a failure
 * condition as reported by the device. Those error codes are from Intel(R) Data
 * Streaming Accelerator Architecture Specification, section 5.7.
 */
#define DSA_OP_SUCCESS          0x0  /**< Operation completed successfully */
#define DSA_OP_SKIPPED          0x1  /**< Operation not attempted (Earlier fence failed) */
#define DSA_OP_ADDRESS_ERR      0x03 /**< Page fault or invalid address */
#define DSA_OP_INVALID_LEN      0x13 /**< Invalid/too big length field passed */
#define DSA_OP_OVERLAPPING_BUFS 0x16 /**< Overlapping buffers error */

/** The structure populated by dsa_get_stats() function. */
struct dsa_stats {
    uint64_t enqueue_failed; /**< failed enqueue operations */
    uint64_t enqueued;       /**< successful enqueue operations */
    uint64_t started;        /**< start operations */
    uint64_t completed;      /**< completed operations */
};

/**
 * Open a device
 *
 * @param name
 *   the device name in "/dev/dsa"
 * @return
 *   dsa device id to use in future api calls or -1 with errno set accordingly
 */
CNDP_API int16_t dsa_open(const char *name);

/**
 * Close a device previously opened with dsa_open()
 *
 * @param dev
 *   The dsa device id returned by dsa_open()
 * @return
 *   0 on success or -1 on error with errno set accordingly
 */
CNDP_API int dsa_close(uint16_t dev);

/**
 * Get device statistics
 *
 * @param dev
 *   The dsa device id returned by dsa_open()
 * @param stats
 *   A pointer to store statistics
 * @return
 *   0 on success or -1 on error with errno set accordingly
 */
CNDP_API int dsa_get_stats(uint16_t dev, struct dsa_stats *stats);

/**
 * Return the number of available hardware descriptors
 *
 * @param dev
 *   The dsa device id returned by dsa_open()
 * @return
 *   Number of descriptors available to use.
 */
CNDP_API uint16_t dsa_burst_capacity(uint16_t dev);

/**
 * Enqueue a fill operation onto the device
 *
 * This queues up a fill operation to be performed by hardware, but does not
 * trigger hardware to begin that operation.
 *
 * @param dev
 *   The dsa device id returned by dsa_open()
 * @param pattern
 *   The pattern with which to populate the destination buffer
 * @param dst
 *   The address of the destination buffer
 * @param length
 *   The length of the destination buffer
 * @param dst_hdl
 *   An opaque handle for the destination data, to be returned when this
 *   operation has been completed and the user polls for the completion details.
 * @return
 *   Number of operations enqueued, either 0 or 1
 */
CNDP_API int dsa_enqueue_fill(uint16_t dev, uint64_t pattern, phys_addr_t dst, uint32_t length,
                              uintptr_t dst_hdl);

/**
 * Enqueue a copy operation onto the device
 *
 * This queues up a copy operation to be performed by hardware, but does not
 * trigger hardware to begin that operation.
 *
 * @param dev
 *   The dsa device id returned by dsa_open()
 * @param src
 *   The address of the source buffer
 * @param dst
 *   The address of the destination buffer
 * @param length
 *   The length of the data to copy
 * @param src_hdl
 *   An opaque handle for the source data, to be returned when this operation
 *   has been completed and the user polls for the completion details.
 * @param dst_hdl
 *   An opaque handle for the destination data, to be returned when this
 *   operation has been completed and the user polls for the completion details.
 * @return
 *   Number of operations enqueued, either 0 or 1
 */
CNDP_API int dsa_enqueue_copy(uint16_t dev, phys_addr_t src, phys_addr_t dst, uint32_t length,
                              uintptr_t src_hdl, uintptr_t dst_hdl);

/**
 * Add a fence to force ordering between operations
 *
 * This adds a fence to a sequence of operations to enforce ordering, such that
 * all operations enqueued before the fence must be completed before operations
 * after the fence.
 * NOTE: Since this fence may be added as a flag to the last operation enqueued,
 * this API may not function correctly when called immediately after an
 * dsa_perform_ops() call i.e. before any new operations are enqueued.
 *
 * @param dev
 *   The dsa device id returned by dsa_open()
 * @return
 *   Number of fences enqueued, either 0 or 1
 */
CNDP_API int dsa_fence(uint16_t dev);

/**
 * Trigger hardware to begin performing enqueued operations
 *
 * This API is used to write the "doorbell" to the hardware to trigger it
 * to begin the operations previously enqueued by dsa_enqueue_*()
 *
 * @param dev
 *   The dsa device id returned by dsa_open()
 * @return
 *   0 on success or -1 on error with errno set accordingly
 */
CNDP_API int dsa_perform_ops(uint16_t dev);

/**
 * Returns details of operations that have been completed
 *
 * The status of each operation is returned in the status array parameter.
 * The function will return to the caller the user-provided "handles" for
 * the copy operations completed by the hardware, and not already returned
 * by a previous call to this API. If the src_hdls or dst_hdls parameters
 * are NULL, they will be ignored, and the function returns the number of
 * newly-completed operations.
 * If status is also NULL, then max_copies parameter is also ignored and the
 * function returns a count of the number of newly-completed operations.
 *
 * @param dev
 *   The dsa device id returned by dsa_open()
 * @param max_copies
 *   The number of entries which can fit in the status, src_hdls and dst_hdls
 *   arrays, i.e. max number of completed operations to report.
 * @param status
 *   Array to hold the status of each completed operation. Array should be
 *   set to zeros on input, as the driver will only write error status values.
 *   A value of 1 implies an operation was not attempted, and any other non-zero
 *   value indicates operation failure.
 *   Parameter may be NULL if no status value checking is required.
 * @param num_unsuccessful
 *   Returns the number of elements in status where the value is non-zero,
 *   i.e. the operation either failed or was not attempted due to an earlier
 *   failure. If this value is returned as zero (the expected case), the
 *   status array will not have been modified by the function and need not be
 *   checked by software
 * @param src_hdls
 *   Array to hold the source handle parameters of the completed ops. Can be NULL.
 * @param dst_hdls
 *   Array to hold the destination handle parameters of the completed ops. Can be NULL.
 * @return
 *   -1 on device error, with errno set appropriately and parameters unmodified.
 *   Otherwise number of returned operations i.e. number of valid entries
 *   in the status, src_hdls and dst_hdls array parameters. If status is NULL,
 *   this value may be greater than max_copies parameter.
 */
CNDP_API int dsa_completed_ops(uint16_t dev, uint8_t max_copies, uint32_t *status,
                               uint8_t *num_unsuccessful, uintptr_t *src_hdls, uintptr_t *dst_hdls);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_DSA_H_ */
