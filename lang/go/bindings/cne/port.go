/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp

#include <pktdev.h>
#include <cne_lport.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type Port struct {
	lportId C.int
}

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

func (p *Port) GetPortStats() (*PortStats, error) {
	var stats C.lport_stats_t

	ret := C.pktdev_stats_get(C.ushort(p.lportId), &stats)
	if ret < 0 {
		return nil, fmt.Errorf("GetPortStats failed with error code %d", ret)
	}

	ps := &PortStats{}
	ps.InPackets = uint64(stats.ipackets)
	ps.InBytes = uint64(stats.ibytes)
	ps.InErrors = uint64(stats.ierrors)
	ps.InMissed = uint64(stats.imissed)
	ps.RxInvalid = uint64(stats.rx_invalid)
	ps.OutPackets = uint64(stats.opackets)
	ps.OutBytes = uint64(stats.obytes)
	ps.OutErrors = uint64(stats.oerrors)
	ps.OutDropped = uint64(stats.odropped)
	ps.TxInvalid = uint64(stats.tx_invalid)

	return ps, nil
}

func (p *Port) ResetPortStats() error {
	ret := C.pktdev_stats_reset(C.ushort(p.lportId))
	if ret < 0 {
		fmt.Errorf("ResetPortStats failed with error code %d", ret)
	}

	return nil
}
