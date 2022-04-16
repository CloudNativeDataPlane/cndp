/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cndpgo

type PortStats struct {
	InPackets  uint64
	InBytes    uint64
	InErrors   uint64
	InMissed   uint64
	RxInvalid  uint64
	OutPackets uint64
	OutBytes   uint64
	OutErrors  uint64
	OutDropped uint64
	TxInvalid  uint64
}
