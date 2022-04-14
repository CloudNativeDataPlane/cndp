/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cndpgo

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp

#include <pktmbuf.h>
*/
import "C"
import (
	"reflect"
	"unsafe"
)

type Packet C.pktmbuf_t

func FreePacketBuffer(packets []*Packet) {
	if packets == nil || len(packets) == 0 {
		return
	}

	cPackets := (**C.pktmbuf_t)(unsafe.Pointer(&packets[0]))
	if *cPackets == nil {
		return
	}

	C.pktmbuf_free_bulk(cPackets, C.uint(len(packets)))
}

func (pkt *Packet) GetHeaderMetaData() *PacketHeaderMetaData {
	var mData PacketHeaderMetaData
	mData.PacketLength = (*uint16)(&pkt.buf_len)
	mData.DataLength = (*uint16)(&pkt.data_len)
	mData.L2 = (unsafe.Pointer)(uintptr(pkt.buf_addr) + uintptr(pkt.data_off))
	mData.Data = (unsafe.Pointer)(uintptr(pkt.buf_addr) + uintptr(pkt.data_off))
	mData.L3 = (unsafe.Pointer)(uintptr(mData.L2) + uintptr(EtherLen))

	return &(mData)
}

func (pkt *Packet) GetData() []byte {
	dataPtr := (unsafe.Pointer)(uintptr(pkt.buf_addr) + uintptr(pkt.data_off))
	if dataPtr == nil {
		return nil
	}

	return makeByteSlice(uintptr(unsafe.Pointer(dataPtr)), int(pkt.data_len))
}

func (pkt *Packet) SetData(data []byte) unsafe.Pointer {
	if data == nil || len(data) == 0 {
		return nil
	}

	return C.pktmbuf_write(unsafe.Pointer(&data[0]), C.uint(len(data)), (*C.pktmbuf_t)(pkt), C.uint(0))
}

func makePacketSlice(start uintptr, length int) (packets []*Packet) {
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&packets))
	slice.Data = start
	slice.Len = length
	slice.Cap = length
	return
}
