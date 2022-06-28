/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

package cne

// Length of protocol addresses.
const (
	EtherAddrLen = 6  // Length of a MAC address
	IPv4AddrLen  = 4  // Length of a IPv4 address
	IPv6AddrLen  = 16 // Length of a IPv6 address
)

// These constants keep length of supported headers in bytes.
//
// IPv6Len - minimum length of IPv6 header in bytes. It can be higher and it
// is not determined inside packet. Only default minimum size is used.
const (
	EtherHdrLen = 14 // Length of a ethernet header
	IPv4HdrLen  = 20 // Length of a IPv4 header without options
	IPv6HdrLen  = 40 // Length of a IPv6 header without options
)

// Supported L4 types
const (
	IPProtoNumber  = 0x04 // IPv4 protocol number
	TCPProtoNumber = 0x06 // TCP protocol number
	UDPProtoNumber = 0x11 // UDP protocol number
)

// Supported EtherType for L2
const (
	EtherTypeIPV4           = 0x0800 // IPv4 Protocol
	EtherTypeIPV6           = 0x86DD // IPv6 Protocol
	EtherTypeARP            = 0x0806 // Arp Protocol
	EtherTypeRARP           = 0x8035 // Reverse Arp Protocol
	EtherTypeVLAN           = 0x8100 // IEEE 802.1Q VLAN tagging
	EtherTypeQINQ           = 0x88A8 // IEEE 802.1ad QinQ tagging
	EtherTypePPPOEDiscovery = 0x8863 // PPPoE Discovery Stage
	EtherTypePPPOESession   = 0x8864 // PPPoE Session Stage
	EtherTypeETAG           = 0x893F // IEEE 802.1BR E-Tag
	EtherType1588           = 0x88F7 // RFC-1588 Timestamp Format
	EtherTypeSLOW           = 0x8809 // Slow protocols (LACP and Marker)
	EtherTypeTEB            = 0x6558 // Transparent Ethernet Bridging
	EtherTypeLLDP           = 0x88CC // LLDP Protocol
	EtherTypeMPLS           = 0x8847 // MPLS ethertype
	EtherTypeMPLSM          = 0x8848 // MPLS multicast ethertype
)

// Constants for values of TCP flags.
const (
	TCPFlagFin = 0x01 // TCP FIN flag
	TCPFlagSyn = 0x02 // TCP SYN flag
	TCPFlagRst = 0x04 // TCP RST flag
	TCPFlagPsh = 0x08 // TCP Push flag
	TCPFlagAck = 0x10 // TCP ACK flag
	TCPFlagUrg = 0x20 // TCP URG (Urgent) flag
	TCPFlagEcn = 0x40 // TCP ECN (ECN-Echo) flag
	TCPFlagCwr = 0x80 // TCP CWR (Congestion Window Reduced) flag
)
