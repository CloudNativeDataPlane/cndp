/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cndpgo

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp

#include <pktdev.h>
*/
import "C"
import (
	"unsafe"
)

type Port struct {
	lportId C.int
}

func newPort(lportId C.int) *Port {
	var p Port
	p.lportId = lportId
	return &p
}

func (p *Port) RxBurst(packets []*Packet) int {
	if packets == nil || len(packets) == 0 {
		return -1
	}

	cRxPackets := (**C.pktmbuf_t)(unsafe.Pointer(&packets[0]))
	return int(C.pktdev_rx_burst(C.ushort(p.lportId), cRxPackets, C.ushort(len(packets))))
}

func (p *Port) PrepareTxPackets(packets []*Packet) int {
	if packets == nil || len(packets) == 0 {
		return -1
	}

	cTxPackets := (**C.pktmbuf_t)(unsafe.Pointer(&packets[0]))
	return int(C.pktdev_buf_alloc(C.int(p.lportId), cTxPackets, C.ushort(len(packets))))
}

func (p *Port) TxBurst(packets []*Packet) int {
	if packets == nil || len(packets) == 0 {
		return -1
	}
	cTxPackets := (**C.pktmbuf_t)(unsafe.Pointer(&packets[0]))
	if *cTxPackets == nil {
		return -1
	}

	return int(C.pktdev_tx_burst(C.ushort(p.lportId), cTxPackets, C.ushort(len(packets))))
}

func (p *Port) GetPortStats(ps *PortStats) int {
	return int(C.pktdev_stats_get(C.ushort(p.lportId), ps.stats))
}

func (p *Port) ResetPortStats() int {
	return int(C.pktdev_stats_reset(C.ushort(p.lportId)))
}
