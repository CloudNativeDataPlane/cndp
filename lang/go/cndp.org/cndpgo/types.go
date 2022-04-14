/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

package cndpgo

import (
	"fmt"
)

type MACAddress [EtherAddrLen]uint8
type EthernetHeader struct {
	DAddr     MACAddress // Destination address
	SAddr     MACAddress // Source address
	EtherType uint16     // Frame type
}

type IPv4Address uint32
type IPv4Hdr struct {
	VersionIhl     uint8       // version and header length
	TypeOfService  uint8       // type of service
	TotalLength    uint16      // length of packet
	PacketID       uint16      // packet ID
	FragmentOffset uint16      // fragmentation offset
	TimeToLive     uint8       // time to live
	NextProtoID    uint8       // protocol ID
	HdrChecksum    uint16      // header checksum
	SrcAddr        IPv4Address // source address
	DstAddr        IPv4Address // destination address
}
type IPv6Address [IPv6AddrLen]uint8
type IPv6Hdr struct {
	VtcFlow    uint32      // IP version, traffic class & flow label
	PayloadLen uint16      // IP packet length - includes sizeof(ip_header)
	Proto      uint8       // Protocol, next header
	HopLimits  uint8       // Hop limits
	SrcAddr    IPv6Address // IP address of source host
	DstAddr    IPv6Address // IP address of destination host(s)
}

type UDPHdr struct {
	SrcPort    uint16 // UDP source port
	DstPort    uint16 // UDP destination port
	DgramLen   uint16 // UDP datagram length
	DgramCksum uint16 // UDP datagram checksum
}

type TCPFlags uint8
type TCPHdr struct {
	SrcPort  uint16   // TCP source port
	DstPort  uint16   // TCP destination port
	SentSeq  uint32   // TX data sequence number
	RecvAck  uint32   // RX data acknowledgement sequence number
	DataOff  uint8    // Data offset
	TCPFlags TCPFlags // TCP flags
	RxWin    uint16   // RX flow control window
	Cksum    uint16   // TCP checksum
	TCPUrp   uint16   // TCP urgent pointer, if any
}

var (
	//not thread safe
	etherTypeNameMap = map[uint16]string{
		ETHER_TYPE_IPV4:            " IPv4 Protocol",
		ETHER_TYPE_IPV6:            " IPv6 Protocol",
		ETHER_TYPE_ARP:             " Arp Protocol",
		ETHER_TYPE_RARP:            " Reverse Arp Protocol",
		ETHER_TYPE_VLAN:            " IEEE 802.1Q VLAN tagging",
		ETHER_TYPE_QINQ:            " IEEE 802.1ad QinQ tagging",
		ETHER_TYPE_PPPOE_DISCOVERY: " PPPoE Discovery Stage",
		ETHER_TYPE_PPPOE_SESSION:   " PPPoE Session Stage",
		ETHER_TYPE_ETAG:            " IEEE 802.1BR E-Tag",
		ETHER_TYPE_1588:            "Ether Type 1588",
		ETHER_TYPE_SLOW:            " Slow protocols (LACP and Marker)",
		ETHER_TYPE_TEB:             " Transparent Ethernet Bridging",
		ETHER_TYPE_LLDP:            " LLDP Protocol",
		ETHER_TYPE_MPLS:            " MPLS ethertype",
		ETHER_TYPE_MPLSM:           " MPLS multicast ethertype",
	}
)

func getEtherTypeName(et uint16) string {
	ret, ok := etherTypeNameMap[et]
	if !ok {
		return "Unknown"
	}
	return ret
}

func (mac *MACAddress) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func (ethHdr *EthernetHeader) String() string {
	return fmt.Sprintf(`L2 protocol: Ethernet, EtherType: 0x%04x (%s)
Ethernet Source: %s
Ethernet Destination: %s
`,
		ethHdr.EtherType, getEtherTypeName(ethHdr.EtherType),
		ethHdr.SAddr.String(),
		ethHdr.DAddr.String())
}

func (addr *IPv4Address) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(*addr), byte(*addr>>8), byte(*addr>>16), byte(*addr>>24))
}

func (hdr *IPv4Hdr) String() string {
	r0 := "    L3 protocol: IPv4\n"
	r1 := "    IPv4 Source: " + hdr.SrcAddr.String() + "\n"
	r2 := "    IPv4 Destination: " + hdr.DstAddr.String() + "\n"
	return r0 + r1 + r2
}

func (addr IPv6Address) String() string {
	return fmt.Sprintf("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
		addr[0], addr[1], addr[2], addr[3],
		addr[4], addr[5], addr[6], addr[7],
		addr[8], addr[9], addr[10], addr[11],
		addr[12], addr[13], addr[14], addr[15])
}

func (hdr *IPv6Hdr) String() string {
	return fmt.Sprintf(`    L3 protocol: IPv6
    IPv6 Source: %s
    IPv6 Destination %s
`, hdr.SrcAddr.String(), hdr.DstAddr.String())
}

func (hdr *UDPHdr) String() string {
	r0 := "        L4 protocol: UDP\n"
	r1 := fmt.Sprintf("        L4 Source: %d\n", SwapBytesUint16(hdr.SrcPort))
	r2 := fmt.Sprintf("        L4 Destination: %d\n", SwapBytesUint16(hdr.DstPort))
	return r0 + r1 + r2
}
