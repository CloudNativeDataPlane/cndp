/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cndpgo

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp

#include <cne_lport.h>
#include <stdio.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type PortStats struct {
	stats *C.lport_stats_t
}

func NewPortStats() *PortStats {
	var ps PortStats
	ps.stats = (*C.lport_stats_t)(C.calloc(1, C.ulong(unsafe.Sizeof(*ps.stats))))
	return &ps
}

func (ps *PortStats) FreePortStats() {
	C.free(unsafe.Pointer(ps.stats))
}

func (ps *PortStats) PrintPortStats() {
	if ps.stats == nil {
		return
	}

	fmt.Printf("\nRX stats\n")
	fmt.Printf("Pkts:%d\n", ps.stats.ipackets)
	fmt.Printf("MBs:%d\n", ps.stats.ibytes)
	fmt.Printf("Errors:%d\n", ps.stats.ierrors)
	fmt.Printf("Missed:%d\n", ps.stats.imissed)
	fmt.Printf("Invalid:%d\n", ps.stats.rx_invalid)

	fmt.Printf("\nTX stats\n")
	fmt.Printf("Pkts:%d\n", ps.stats.opackets)
	fmt.Printf("MBs:%d\n", ps.stats.obytes)
	fmt.Printf("Errors:%d\n", ps.stats.oerrors)
	fmt.Printf("Missed:%d\n", ps.stats.odropped)
	fmt.Printf("Invalid:%d\n", ps.stats.tx_invalid)
}

func (ps *PortStats) GetIPackets() float64 {
	if ps.stats == nil {
		return 0
	}
	return float64(ps.stats.ipackets)
}

func (ps *PortStats) GetOPackets() float64 {
	if ps.stats == nil {
		return 0
	}
	return float64(ps.stats.opackets)
}

func (ps *PortStats) GetIBytes() int {
	if ps.stats == nil {
		return 0
	}
	return int(ps.stats.ibytes)
}

func (ps *PortStats) GetOBytes() int {
	if ps.stats == nil {
		return 0
	}
	return int(ps.stats.obytes)
}
