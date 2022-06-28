/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

package cne

import (
	"fmt"
)

// MACAddress represents a MAC address octets
type MACAddress [EtherAddrLen]uint8

// EthernetHeader represents a Ethernet header
type EthernetHeader struct {
	DAddr     MACAddress // Destination address
	SAddr     MACAddress // Source address
	EtherType uint16     // Frame type
}

// IPv4Address represents a IPv4 address octets
type IPv4Address uint32

// IPv4Hdr represents a IPv4 header
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

// IPv6Address represents a IPv6 address octets
type IPv6Address [IPv6AddrLen]uint8

// IPv6Hdr represents a IPv6 header
type IPv6Hdr struct {
	VtcFlow    uint32      // IP version, traffic class & flow label
	PayloadLen uint16      // IP packet length - includes sizeof(ip_header)
	Proto      uint8       // Protocol, next header
	HopLimits  uint8       // Hop limits
	SrcAddr    IPv6Address // IP address of source host
	DstAddr    IPv6Address // IP address of destination host(s)
}

// UDPHdr represents the UDP header
type UDPHdr struct {
	SrcPort    uint16 // UDP source port
	DstPort    uint16 // UDP destination port
	DgramLen   uint16 // UDP datagram length
	DgramCksum uint16 // UDP datagram checksum
}

// TCPFlags represents the TCP flags
type TCPFlags uint8

// TCPHdr represents the TCP header
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
		EtherTypeIPV4:           " IPv4 Protocol",
		EtherTypeIPV6:           " IPv6 Protocol",
		EtherTypeARP:            " Arp Protocol",
		EtherTypeRARP:           " Reverse Arp Protocol",
		EtherTypeVLAN:           " IEEE 802.1Q VLAN tagging",
		EtherTypeQINQ:           " IEEE 802.1ad QinQ tagging",
		EtherTypePPPOEDiscovery: " PPPoE Discovery Stage",
		EtherTypePPPOESession:   " PPPoE Session Stage",
		EtherTypeETAG:           " IEEE 802.1BR E-Tag",
		EtherType1588:           " Ether Type 1588",
		EtherTypeSLOW:           " Slow protocols (LACP and Marker)",
		EtherTypeTEB:            " Transparent Ethernet Bridging",
		EtherTypeLLDP:           " LLDP Protocol",
		EtherTypeMPLS:           " MPLS ethertype",
		EtherTypeMPLSM:          " MPLS multicast ethertype",
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
	r1 := fmt.Sprintf("        L4 Source: %d\n", SwapUint16(hdr.SrcPort))
	r2 := fmt.Sprintf("        L4 Destination: %d\n", SwapUint16(hdr.DstPort))
	return r0 + r1 + r2
}
