/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

package cndpgo

// Length of addresses.
const (
	EtherAddrLen = 6
	IPv4AddrLen  = 4
	IPv6AddrLen  = 16
)

// These constants keep length of supported headers in bytes.
//
// IPv6Len - minimum length of IPv6 header in bytes. It can be higher and it
// is not determined inside packet. Only default minimum size is used.
const (
	EtherLen = 14
	IPv6Len  = 40
)

// Supported L4 types
const (
	IPNumber  = 0x04
	TCPNumber = 0x06
	UDPNumber = 0x11
)

// Supported EtherType for L2
const (
	ETHER_TYPE_IPV4            = 0x0800 /**< IPv4 Protocol. */
	ETHER_TYPE_IPV6            = 0x86DD /**< IPv6 Protocol. */
	ETHER_TYPE_ARP             = 0x0806 /**< Arp Protocol. */
	ETHER_TYPE_RARP            = 0x8035 /**< Reverse Arp Protocol. */
	ETHER_TYPE_VLAN            = 0x8100 /**< IEEE 802.1Q VLAN tagging. */
	ETHER_TYPE_QINQ            = 0x88A8 /**< IEEE 802.1ad QinQ tagging. */
	ETHER_TYPE_PPPOE_DISCOVERY = 0x8863 /**< PPPoE Discovery Stage. */
	ETHER_TYPE_PPPOE_SESSION   = 0x8864 /**< PPPoE Session Stage. */
	ETHER_TYPE_ETAG            = 0x893F /**< IEEE 802.1BR E-Tag. */
	ETHER_TYPE_1588            = 0x88F7
	ETHER_TYPE_SLOW            = 0x8809 /**< Slow protocols (LACP and Marker). */
	ETHER_TYPE_TEB             = 0x6558 /**< Transparent Ethernet Bridging. */
	ETHER_TYPE_LLDP            = 0x88CC /**< LLDP Protocol. */
	ETHER_TYPE_MPLS            = 0x8847 /**< MPLS ethertype. */
	ETHER_TYPE_MPLSM           = 0x8848 /**< MPLS multicast ethertype. */
)

// Constants for valuues of TCP flags.
const (
	TCPFlagFin = 0x01
	TCPFlagSyn = 0x02
	TCPFlagRst = 0x04
	TCPFlagPsh = 0x08
	TCPFlagAck = 0x10
	TCPFlagUrg = 0x20
	TCPFlagEce = 0x40
	TCPFlagCwr = 0x80
)
