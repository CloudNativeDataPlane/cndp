/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

package cne

import (
	"unsafe"
)

type PacketHeaderMetaData struct {
	L2           unsafe.Pointer
	L3           unsafe.Pointer
	Data         unsafe.Pointer
	PacketLength *uint16
	DataLength   *uint16
}

func (mData *PacketHeaderMetaData) SetData(data []byte) {
	*mData.DataLength = (uint16)(len(data))
	slice := makeByteSlice(uintptr(mData.Data), int(*mData.DataLength))
	copy(slice, data)
}

func (mData *PacketHeaderMetaData) GetEtherHdr() *EthernetHeader {
	return (*EthernetHeader)(mData.L2)
}

func (mData *PacketHeaderMetaData) SwapMacAddress() {
	ether := (*EthernetHeader)(mData.L2)
	tmp := ether.SAddr
	ether.SAddr = ether.DAddr
	ether.DAddr = tmp
}

func (mData *PacketHeaderMetaData) GetIPv4() *IPv4Hdr {
	if mData.GetEtherHdr() != nil && mData.GetEtherHdr().EtherType == SwapBytesUint16(ETHER_TYPE_IPV4) {
		return (*IPv4Hdr)(mData.L3)
	}
	return nil
}

func (mData *PacketHeaderMetaData) GetIPv6() *IPv6Hdr {
	if mData.GetEtherHdr() != nil && mData.GetEtherHdr().EtherType == SwapBytesUint16(ETHER_TYPE_IPV6) {
		return (*IPv6Hdr)(mData.L3)
	}
	return nil
}

func (mData *PacketHeaderMetaData) GetUDP() *UDPHdr {
	if mData.GetIPv4() != nil && mData.GetIPv4().NextProtoID == UDPNumber {
		l4 := unsafe.Pointer(uintptr(mData.L3) + uintptr((mData.GetIPv4().VersionIhl&0x0f)<<2))
		return (*UDPHdr)(l4)
	}
	if mData.GetIPv6() != nil && mData.GetIPv6().Proto == UDPNumber {
		l4 := unsafe.Pointer(uintptr(mData.L3) + uintptr(IPv6Len))
		return (*UDPHdr)(l4)
	}
	return nil
}

func (mData *PacketHeaderMetaData) GetTCP() *TCPHdr {
	if mData.GetIPv4() != nil && mData.GetIPv4().NextProtoID == TCPNumber {
		l4 := unsafe.Pointer(uintptr(mData.L3) + uintptr((mData.GetIPv4().VersionIhl&0x0f)<<2))
		return (*TCPHdr)(l4)
	}
	if mData.GetIPv6() != nil && mData.GetIPv6().Proto == TCPNumber {
		l4 := unsafe.Pointer(uintptr(mData.L3) + uintptr(IPv6Len))
		return (*TCPHdr)(l4)
	}
	return nil
}
