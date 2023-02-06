/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#ifndef _CNE_BYTEORDER_H_
#define _CNE_BYTEORDER_H_

/**
 * @file
 *
 * This file defines generic types for values with a specific endianness.
 */

#include <stdint.h>
#include <endian.h>
/*
 * The following types should be used when handling values according to a
 * specific byte ordering, which may differ from that of the host CPU.
 *
 * Libraries, public APIs and applications are encouraged to use them for
 * documentation purposes.
 */
typedef uint16_t cne_be16_t; /**< 16-bit big-endian value. */
typedef uint32_t cne_be32_t; /**< 32-bit big-endian value. */
typedef uint64_t cne_be64_t; /**< 64-bit big-endian value. */
typedef uint16_t cne_le16_t; /**< 16-bit little-endian value. */
typedef uint32_t cne_le32_t; /**< 32-bit little-endian value. */
typedef uint64_t cne_le64_t; /**< 64-bit little-endian value. */

#endif /* _CNE_BYTEORDER_H_ */
