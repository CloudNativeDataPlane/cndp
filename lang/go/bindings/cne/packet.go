/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp

#include <cne_common.h>
#include <pktmbuf.h>
#include <pktdev.h>
#include <pktmbuf_ptype.h>

uint16_t
ipv4_cksum(const struct cne_ipv4_hdr *hdr)
{
	return cne_ipv4_cksum(hdr);
}

uint16_t
ipv6_phdr_cksum(const struct cne_ipv6_hdr *hdr)
{
	return cne_ipv6_phdr_cksum(hdr, 0);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type Packet C.pktmbuf_t // Packet is the interface type for C.pktmbuf_t structure

// PktBufferAlloc will allocate a set of pktmbuf structures or buffers
// Returns the number of packets allocated or -1 on error
func PktBufferAlloc(lportId int, packets []*Packet) int {

	if packets == nil {
		return -1
	}

	var nbpkts int = 0

	if len(packets) > 0 {
		cTxPackets := (**C.pktmbuf_t)(unsafe.Pointer(&packets[0]))

		nbpkts = int(C.pktdev_buf_alloc(C.int(lportId), cTxPackets, C.ushort(len(packets))))
	}
	return nbpkts
}

// PktBufferFree will free a set of pktmbuf structures or buffers
func PktBufferFree(packets []*Packet) {

	if packets != nil {
		cnt := len(packets)

		if cnt > 0 {
			cPackets := (**C.pktmbuf_t)(unsafe.Pointer(&packets[0]))

			C.pktmbuf_free_bulk(cPackets, C.uint(cnt))
		}
	}
}

// RxBurst will attempt to receive packets from the given lportID value
// Returns -1 on error or number of packets received
func RxBurst(lportId int, packets []*Packet) int {

	if packets == nil || lportId < 0 || lportId >= C.CNE_MAX_ETHPORTS {
		return -1
	}

	var nbpkts C.ushort = 0

	if len(packets) > 0 {
		cRxPackets := (**C.pktmbuf_t)(unsafe.Pointer(&packets[0]))

		nbpkts = C.pktdev_rx_burst(C.ushort(lportId), cRxPackets, C.ushort(len(packets)))
		if nbpkts == C.PKTDEV_ADMIN_STATE_DOWN {
			nbpkts = 0
		}
	}
	return int(nbpkts)
}

// TxBurst transmits packets to the given lportId value
//
// If sendAll is true the routine will attempt to send all of the packets as the TX ring
// could get full.
// If sendAll flag is false the routine will not attempt to send all of the packet.
// Returns the number of packets sent or -1 on error
func TxBurst(lportId int, packets []*Packet, sendAll bool) int {

	if packets == nil || lportId < 0 || lportId >= C.CNE_MAX_ETHPORTS {
		return -1
	}

	nbpkts := len(packets)
	if nbpkts > 0 {
		cTxPackets := (**C.pktmbuf_t)(unsafe.Pointer(&packets[0]))

		if sendAll {
			for sent := 0; sent < nbpkts; {
				nbtx := int(C.pktdev_tx_burst(C.ushort(lportId), cTxPackets, C.ushort(len(packets))))
				if nbtx == C.PKTDEV_ADMIN_STATE_DOWN {
					nbpkts = 0
					break
				}
				sent += nbtx
			}
		} else {
			nbpkts = int(C.pktdev_tx_burst(C.ushort(lportId), cTxPackets, C.ushort(len(packets))))
			if nbpkts == C.PKTDEV_ADMIN_STATE_DOWN {
				nbpkts = 0
			}
		}
	}

	return nbpkts
}

// PktData returns a byte slice of the packet data associated with the Packet
func PktData(pkt *Packet) []byte {

	dataPtr := (unsafe.Pointer)(uintptr(pkt.buf_addr) + uintptr(pkt.data_off))
	if dataPtr == nil {
		return nil
	}

	return MakeByteSlice(uintptr(unsafe.Pointer(dataPtr)), int(pkt.data_len))
}

// WritePktData writes a byte slice of the packet data into the packet buffer.
// Return nil or the pointer to the data in the packet buffer
func WritePktData(pkt *Packet, offset int, data []byte) unsafe.Pointer {

	if len(data) == 0 || pkt == nil {
		return nil
	}
	return C.pktmbuf_write(unsafe.Pointer(&data[0]), C.uint(len(data)), (*C.pktmbuf_t)(pkt), C.uint(offset))
}

// WritePktDataList take a slice of *Packet objects and writes the data to each packet at the given offset
func WritePktDataList(pkts []*Packet, offset int, data []byte) error {

	if len(data) == 0 {
		return fmt.Errorf("invalid packet data or length")
	}

	for _, pkt := range pkts {
		if WritePktData(pkt, offset, data) == nil {
			return fmt.Errorf("unable to write data to packets")
		}
	}
	return nil
}

// SwapMacAddr will swap the MAC addresses of the packet
// The packet must have a valid EthernetHeader at the start or the packet data
func SwapMacAddr(pkt *Packet) {

	ether := (*EthernetHeader)((unsafe.Pointer)(uintptr(pkt.buf_addr) + uintptr(pkt.data_off)))

	ether.DAddr, ether.SAddr = ether.SAddr, ether.DAddr
}

// SwapMacAddrs will swap the MAC address of the set of packet buffers.
func SwapMacAddrs(pkt []*Packet) {

	for _, p := range pkt {
		SwapMacAddr(p)
	}
}

// PktType will process the packet and return the pType value a bitwise value describing the packet type
func PktType(pkt *Packet) uint32 {

	if pkt != nil {
		var hdrLen C.struct_cne_net_hdr_lens

		ptype := uint32(C.cne_get_ptype((*C.pktmbuf_t)(unsafe.Pointer(pkt)), &hdrLen, C.CNE_PTYPE_ALL_MASK))

		return ptype
	}
	return 0
}

// PktTypes will return a list of ptype values for each packet processed
func PktTypes(pkts []*Packet) []uint32 {

	var ptypes []uint32

	for _, pkt := range pkts {
		ptypes = append(ptypes, PktType(pkt))
	}
	return ptypes
}

// IPv4Checksum will return the IPv4 checksum calculation
// The returned value could be zero in the case when verifying the checksum.
func IPv4Checksum(ip4Hdr *IPv4Hdr) uint16 {

	return uint16(C.ipv4_cksum((*C.struct_cne_ipv4_hdr)(unsafe.Pointer(ip4Hdr))))
}

// IPv6Checksum will return the IPv6 checksum calculation
// The returned value could be zero in the case when verifying the checksum.
func IPv6Checksum(ip6Hdr *IPv6Hdr) uint16 {

	return uint16(C.ipv6_phdr_cksum((*C.struct_cne_ipv6_hdr)(unsafe.Pointer(ip6Hdr))))
}

// GetEtherHdr will return a pointer to the ether header or nil on error
func GetEtherHdr(pkt *Packet) *EthernetHeader {

	if pkt != nil {
		return (*EthernetHeader)((unsafe.Pointer)(uintptr(pkt.buf_addr) + uintptr(pkt.data_off)))
	}
	return nil
}

// GetIPv4 will return the IPv4 header pointer or nil on error
func GetIPv4(pkt *Packet) *IPv4Hdr {

	if pkt != nil {
		ether := GetEtherHdr(pkt)

		if ether != nil && ether.EtherType == SwapUint16(EtherTypeIPV4) {
			return (*IPv4Hdr)((unsafe.Pointer)(uintptr(unsafe.Pointer(ether)) + uintptr(EtherHdrLen)))
		}
	}

	return nil
}

// GetIPv6 will return the IPv6 header pointer or nil on error
func GetIPv6(pkt *Packet) *IPv6Hdr {

	if pkt != nil {
		ether := GetEtherHdr(pkt)

		if ether != nil && ether.EtherType == SwapUint16(EtherTypeIPV6) {
			return (*IPv6Hdr)((unsafe.Pointer)(uintptr(unsafe.Pointer(ether)) + uintptr(EtherHdrLen)))
		}
	}

	return nil
}

// GetUDP will return the UDP header pointer for IPv4 or IPv6 packets or nil on error
func GetUDP(pkt *Packet) *UDPHdr {

	ipv4 := GetIPv4(pkt)
	if ipv4 != nil && ipv4.NextProtoID == UDPProtoNumber {
		l4 := unsafe.Pointer(uintptr(unsafe.Pointer(ipv4)) + uintptr((ipv4.VersionIhl&0x0f)<<2))
		return (*UDPHdr)(l4)
	}

	ipv6 := GetIPv6(pkt)
	if ipv6 != nil && ipv6.Proto == UDPProtoNumber {
		l4 := unsafe.Pointer(uintptr(unsafe.Pointer(ipv6)) + uintptr(IPv6HdrLen))
		return (*UDPHdr)(l4)
	}

	return nil
}

// GetTCP will return the TCP header pointer for IPv4 or IPv6 packets or nil on error
func GetTCP(pkt *Packet) *TCPHdr {

	ipv4 := GetIPv4(pkt)
	if ipv4 != nil && ipv4.NextProtoID == TCPProtoNumber {
		l4 := unsafe.Pointer(uintptr(unsafe.Pointer(ipv4)) + uintptr((ipv4.VersionIhl&0x0f)<<2))
		return (*TCPHdr)(l4)
	}

	ipv6 := GetIPv6(pkt)
	if ipv6 != nil && ipv6.Proto == TCPProtoNumber {
		l4 := unsafe.Pointer(uintptr(unsafe.Pointer(ipv6)) + uintptr(IPv6HdrLen))
		return (*TCPHdr)(l4)
	}

	return nil
}
