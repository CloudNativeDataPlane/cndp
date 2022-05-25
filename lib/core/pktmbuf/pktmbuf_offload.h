/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation.
 * Copyright (c) 2014 6WIND S.A.
 */

#ifndef _PKTMBUF_OFFLOAD_H_
#define _PKTMBUF_OFFLOAD_H_

/**
 * @file
 * This file contains definion of CNE pktmbuf structure itself,
 * packet offload flags and some related macros.
 * For majority of CNDP entities, it is not recommended to include
 * this file directly, use include <pktmbuf.h> instead.
 *
 * New fields and flags should fit in the "dynamic space".
 */

#include <stdint.h>

#include <cne_common.h>
#include <cne_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Packet Offload Features Flags. It also carry packet type information.
 * Critical resources. Both rx/tx shared these bits. Be cautious on any change
 *
 * - RX flags start at bit position zero, and get added to the left of previous
 *   flags.
 * - The most-significant 3 bits are reserved for generic mbuf flags
 * - TX flags therefore start at bit position 60 (i.e. 63-3), and new flags get
 *   added to the right of the previously defined flags i.e. they should count
 *   downwards, not upwards.
 *
 * Keep these flags synchronized with cne_get_rx_ol_flag_name() and
 * cne_get_tx_ol_flag_name().
 */

/**
 * The RX packet is a 802.1q VLAN packet, and the tci has been
 * saved in in mbuf->vlan_tci.
 * If the flag CNE_MBUF_F_RX_VLAN_STRIPPED is also present, the VLAN
 * header has been stripped from mbuf data, else it is still
 * present.
 */
#define CNE_MBUF_F_RX_VLAN (1ULL << 0)

/** RX packet with RSS hash result. */
#define CNE_MBUF_F_RX_RSS_HASH (1ULL << 1)

/** RX packet with FDIR match indicate. */
#define CNE_MBUF_F_RX_FDIR (1ULL << 2)

/**
 * This flag is set when the outermost IP header checksum is detected as
 * wrong by the hardware.
 */
#define CNE_MBUF_F_RX_OUTER_IP_CKSUM_BAD (1ULL << 5)

/**
 * A vlan has been stripped by the hardware and its tci is saved in
 * mbuf->vlan_tci. This can only happen if vlan stripping is enabled
 * in the RX configuration of the PMD.
 * When CNE_MBUF_F_RX_VLAN_STRIPPED is set, CNE_MBUF_F_RX_VLAN must also be set.
 */
#define CNE_MBUF_F_RX_VLAN_STRIPPED (1ULL << 6)

/**
 * Mask of bits used to determine the status of RX IP checksum.
 * - CNE_MBUF_F_RX_IP_CKSUM_UNKNOWN: no information about the RX IP checksum
 * - CNE_MBUF_F_RX_IP_CKSUM_BAD: the IP checksum in the packet is wrong
 * - CNE_MBUF_F_RX_IP_CKSUM_GOOD: the IP checksum in the packet is valid
 * - CNE_MBUF_F_RX_IP_CKSUM_NONE: the IP checksum is not correct in the packet
 *   data, but the integrity of the IP header is verified.
 */
#define CNE_MBUF_F_RX_IP_CKSUM_MASK ((1ULL << 4) | (1ULL << 7))

#define CNE_MBUF_F_RX_IP_CKSUM_UNKNOWN 0
#define CNE_MBUF_F_RX_IP_CKSUM_BAD     (1ULL << 4)
#define CNE_MBUF_F_RX_IP_CKSUM_GOOD    (1ULL << 7)
#define CNE_MBUF_F_RX_IP_CKSUM_NONE    ((1ULL << 4) | (1ULL << 7))

/**
 * Mask of bits used to determine the status of RX L4 checksum.
 * - CNE_MBUF_F_RX_L4_CKSUM_UNKNOWN: no information about the RX L4 checksum
 * - CNE_MBUF_F_RX_L4_CKSUM_BAD: the L4 checksum in the packet is wrong
 * - CNE_MBUF_F_RX_L4_CKSUM_GOOD: the L4 checksum in the packet is valid
 * - CNE_MBUF_F_RX_L4_CKSUM_NONE: the L4 checksum is not correct in the packet
 *   data, but the integrity of the L4 data is verified.
 */
#define CNE_MBUF_F_RX_L4_CKSUM_MASK ((1ULL << 3) | (1ULL << 8))

#define CNE_MBUF_F_RX_L4_CKSUM_UNKNOWN 0
#define CNE_MBUF_F_RX_L4_CKSUM_BAD     (1ULL << 3)
#define CNE_MBUF_F_RX_L4_CKSUM_GOOD    (1ULL << 8)
#define CNE_MBUF_F_RX_L4_CKSUM_NONE    ((1ULL << 3) | (1ULL << 8))

/** RX IEEE1588 L2 Ethernet PT Packet. */
#define CNE_MBUF_F_RX_IEEE1588_PTP (1ULL << 9)

/** RX IEEE1588 L2/L4 timestamped packet.*/
#define CNE_MBUF_F_RX_IEEE1588_TMST (1ULL << 10)

/** FD id reported if FDIR match. */
#define CNE_MBUF_F_RX_FDIR_ID (1ULL << 13)

/** Flexible bytes reported if FDIR match. */
#define CNE_MBUF_F_RX_FDIR_FLX (1ULL << 14)

/**
 * The outer VLAN has been stripped by the hardware and its TCI is
 * saved in mbuf->vlan_tci_outer.
 * This can only happen if VLAN stripping is enabled in the Rx
 * configuration of the PMD.
 * When CNE_MBUF_F_RX_QINQ_STRIPPED is set, the flags CNE_MBUF_F_RX_VLAN
 * and CNE_MBUF_F_RX_QINQ must also be set.
 *
 * - If both CNE_MBUF_F_RX_QINQ_STRIPPED and CNE_MBUF_F_RX_VLAN_STRIPPED are
 *   set, the 2 VLANs have been stripped by the hardware and their TCIs are
 *   saved in mbuf->vlan_tci (inner) and mbuf->vlan_tci_outer (outer).
 * - If CNE_MBUF_F_RX_QINQ_STRIPPED is set and CNE_MBUF_F_RX_VLAN_STRIPPED
 *   is unset, only the outer VLAN is removed from packet data, but both tci
 *   are saved in mbuf->vlan_tci (inner) and mbuf->vlan_tci_outer (outer).
 */
#define CNE_MBUF_F_RX_QINQ_STRIPPED (1ULL << 15)

/**
 * When packets are coalesced by a hardware or virtual driver, this flag
 * can be set in the RX mbuf, meaning that the m->tso_segsz field is
 * valid and is set to the segment size of original packets.
 */
#define CNE_MBUF_F_RX_LRO (1ULL << 16)

/* There is no flag defined at offset 17. It is free for any future use. */

/**
 * Indicate that security offload processing was applied on the RX packet.
 */
#define CNE_MBUF_F_RX_SEC_OFFLOAD (1ULL << 18)

/**
 * Indicate that security offload processing failed on the RX packet.
 */
#define CNE_MBUF_F_RX_SEC_OFFLOAD_FAILED (1ULL << 19)

/**
 * The RX packet is a double VLAN, and the outer tci has been
 * saved in mbuf->vlan_tci_outer. If this flag is set, CNE_MBUF_F_RX_VLAN
 * must also be set and the inner tci is saved in mbuf->vlan_tci.
 * If the flag CNE_MBUF_F_RX_QINQ_STRIPPED is also present, both VLANs
 * headers have been stripped from mbuf data, else they are still
 * present.
 */
#define CNE_MBUF_F_RX_QINQ (1ULL << 20)

/**
 * Mask of bits used to determine the status of outer RX L4 checksum.
 * - CNE_MBUF_F_RX_OUTER_L4_CKSUM_UNKNOWN: no info about the outer RX L4
 *   checksum
 * - CNE_MBUF_F_RX_OUTER_L4_CKSUM_BAD: the outer L4 checksum in the packet
 *   is wrong
 * - CNE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD: the outer L4 checksum in the packet
 *   is valid
 * - CNE_MBUF_F_RX_OUTER_L4_CKSUM_INVALID: invalid outer L4 checksum state.
 *
 * The detection of CNE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD shall be based on the
 * given HW capability, At minimum, the PMD should support
 * CNE_MBUF_F_RX_OUTER_L4_CKSUM_UNKNOWN and CNE_MBUF_F_RX_OUTER_L4_CKSUM_BAD
 * states if the CNE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM offload is available.
 */
#define CNE_MBUF_F_RX_OUTER_L4_CKSUM_MASK ((1ULL << 21) | (1ULL << 22))

#define CNE_MBUF_F_RX_OUTER_L4_CKSUM_UNKNOWN 0
#define CNE_MBUF_F_RX_OUTER_L4_CKSUM_BAD     (1ULL << 21)
#define CNE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD    (1ULL << 22)
#define CNE_MBUF_F_RX_OUTER_L4_CKSUM_INVALID ((1ULL << 21) | (1ULL << 22))

/* add new RX flags here, don't forget to update CNE_MBUF_F_FIRST_FREE */

#define CNE_MBUF_F_FIRST_FREE (1ULL << 23)
#define CNE_MBUF_F_LAST_FREE  (1ULL << 40)

/* add new TX flags here, don't forget to update CNE_MBUF_F_LAST_FREE  */

/**
 * Outer UDP checksum offload flag. This flag is used for enabling
 * outer UDP checksum in PMD. To use outer UDP checksum, the user needs to
 * 1) Enable the following in mbuf,
 * a) Fill outer_l2_len and outer_l3_len in mbuf.
 * b) Set the CNE_MBUF_F_TX_OUTER_UDP_CKSUM flag.
 * c) Set the CNE_MBUF_F_TX_OUTER_IPV4 or CNE_MBUF_F_TX_OUTER_IPV6 flag.
 * 2) Configure CNE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM offload flag.
 */
#define CNE_MBUF_F_TX_OUTER_UDP_CKSUM (1ULL << 41)

/**
 * UDP Fragmentation Offload flag. This flag is used for enabling UDP
 * fragmentation in SW or in HW. When use UFO, mbuf->tso_segsz is used
 * to store the MSS of UDP fragments.
 */
#define CNE_MBUF_F_TX_UDP_SEG (1ULL << 42)

/**
 * Request security offload processing on the TX packet.
 * To use Tx security offload, the user needs to fill l2_len in mbuf
 * indicating L2 header size and where L3 header starts.
 */
#define CNE_MBUF_F_TX_SEC_OFFLOAD (1ULL << 43)

/**
 * Offload the MACsec. This flag must be set by the application to enable
 * this offload feature for a packet to be transmitted.
 */
#define CNE_MBUF_F_TX_MACSEC (1ULL << 44)

/**
 * Bits 45:48 used for the tunnel type.
 * The tunnel type must be specified for TSO or checksum on the inner part
 * of tunnel packets.
 * These flags can be used with CNE_MBUF_F_TX_TCP_SEG for TSO, or
 * CNE_MBUF_F_TX_xxx_CKSUM.
 * The mbuf fields for inner and outer header lengths are required:
 * outer_l2_len, outer_l3_len, l2_len, l3_len, l4_len and tso_segsz for TSO.
 */
#define CNE_MBUF_F_TX_TUNNEL_VXLAN  (0x1ULL << 45)
#define CNE_MBUF_F_TX_TUNNEL_GRE    (0x2ULL << 45)
#define CNE_MBUF_F_TX_TUNNEL_IPIP   (0x3ULL << 45)
#define CNE_MBUF_F_TX_TUNNEL_GENEVE (0x4ULL << 45)
/** TX packet with MPLS-in-UDP RFC 7510 header. */
#define CNE_MBUF_F_TX_TUNNEL_MPLSINUDP (0x5ULL << 45)
#define CNE_MBUF_F_TX_TUNNEL_VXLAN_GPE (0x6ULL << 45)
#define CNE_MBUF_F_TX_TUNNEL_GTP       (0x7ULL << 45)
#define CNE_MBUF_F_TX_TUNNEL_ESP       (0x8ULL << 45)
/**
 * Generic IP encapsulated tunnel type, used for TSO and checksum offload.
 * It can be used for tunnels which are not standards or listed above.
 * It is preferred to use specific tunnel flags like CNE_MBUF_F_TX_TUNNEL_GRE
 * or CNE_MBUF_F_TX_TUNNEL_IPIP if possible.
 * The device must be configured with CNE_ETH_TX_OFFLOAD_IP_TNL_TSO.
 * Outer and inner checksums are done according to the existing flags like
 * CNE_MBUF_F_TX_xxx_CKSUM.
 * Specific tunnel headers that contain payload length, sequence id
 * or checksum are not expected to be updated.
 */
#define CNE_MBUF_F_TX_TUNNEL_IP (0xDULL << 45)
/**
 * Generic UDP encapsulated tunnel type, used for TSO and checksum offload.
 * UDP tunnel type implies outer IP layer.
 * It can be used for tunnels which are not standards or listed above.
 * It is preferred to use specific tunnel flags like CNE_MBUF_F_TX_TUNNEL_VXLAN
 * if possible.
 * The device must be configured with CNE_ETH_TX_OFFLOAD_UDP_TNL_TSO.
 * Outer and inner checksums are done according to the existing flags like
 * CNE_MBUF_F_TX_xxx_CKSUM.
 * Specific tunnel headers that contain payload length, sequence id
 * or checksum are not expected to be updated.
 */
#define CNE_MBUF_F_TX_TUNNEL_UDP (0xEULL << 45)
/* add new TX TUNNEL type here */
#define CNE_MBUF_F_TX_TUNNEL_MASK (0xFULL << 45)

/**
 * Double VLAN insertion (QinQ) request to driver, driver may offload the
 * insertion based on device capability.
 * mbuf 'vlan_tci' & 'vlan_tci_outer' must be valid when this flag is set.
 */
#define CNE_MBUF_F_TX_QINQ (1ULL << 49)

/**
 * TCP segmentation offload. To enable this offload feature for a
 * packet to be transmitted on hardware supporting TSO:
 *  - set the CNE_MBUF_F_TX_TCP_SEG flag in mbuf->ol_flags (this flag implies
 *    CNE_MBUF_F_TX_TCP_CKSUM)
 *  - set the flag CNE_MBUF_F_TX_IPV4 or CNE_MBUF_F_TX_IPV6
 *  - if it's IPv4, set the CNE_MBUF_F_TX_IP_CKSUM flag
 *  - fill the mbuf offload information: l2_len, l3_len, l4_len, tso_segsz
 */
#define CNE_MBUF_F_TX_TCP_SEG (1ULL << 50)

/** TX IEEE1588 packet to timestamp. */
#define CNE_MBUF_F_TX_IEEE1588_TMST (1ULL << 51)

/*
 * Bits 52+53 used for L4 packet type with checksum enabled: 00: Reserved,
 * 01: TCP checksum, 10: SCTP checksum, 11: UDP checksum. To use hardware
 * L4 checksum offload, the user needs to:
 *  - fill l2_len and l3_len in mbuf
 *  - set the flags CNE_MBUF_F_TX_TCP_CKSUM, CNE_MBUF_F_TX_SCTP_CKSUM or
 *    CNE_MBUF_F_TX_UDP_CKSUM
 *  - set the flag CNE_MBUF_F_TX_IPV4 or CNE_MBUF_F_TX_IPV6
 */

/** Disable L4 cksum of TX pkt. */
#define CNE_MBUF_F_TX_L4_NO_CKSUM (0ULL << 52)

/** TCP cksum of TX pkt. computed by NIC. */
#define CNE_MBUF_F_TX_TCP_CKSUM (1ULL << 52)

/** SCTP cksum of TX pkt. computed by NIC. */
#define CNE_MBUF_F_TX_SCTP_CKSUM (2ULL << 52)

/** UDP cksum of TX pkt. computed by NIC. */
#define CNE_MBUF_F_TX_UDP_CKSUM (3ULL << 52)

/** Mask for L4 cksum offload request. */
#define CNE_MBUF_F_TX_L4_MASK (3ULL << 52)

/**
 * Offload the IP checksum in the hardware. The flag CNE_MBUF_F_TX_IPV4 should
 * also be set by the application, although a PMD will only check
 * CNE_MBUF_F_TX_IP_CKSUM.
 *  - fill the mbuf offload information: l2_len, l3_len
 */
#define CNE_MBUF_F_TX_IP_CKSUM (1ULL << 54)

/**
 * Packet is IPv4. This flag must be set when using any offload feature
 * (TSO, L3 or L4 checksum) to tell the NIC that the packet is an IPv4
 * packet. If the packet is a tunneled packet, this flag is related to
 * the inner headers.
 */
#define CNE_MBUF_F_TX_IPV4 (1ULL << 55)

/**
 * Packet is IPv6. This flag must be set when using an offload feature
 * (TSO or L4 checksum) to tell the NIC that the packet is an IPv6
 * packet. If the packet is a tunneled packet, this flag is related to
 * the inner headers.
 */
#define CNE_MBUF_F_TX_IPV6 (1ULL << 56)

/**
 * VLAN tag insertion request to driver, driver may offload the insertion
 * based on the device capability.
 * mbuf 'vlan_tci' field must be valid when this flag is set.
 */
#define CNE_MBUF_F_TX_VLAN (1ULL << 57)

/**
 * Offload the IP checksum of an external header in the hardware. The
 * flag CNE_MBUF_F_TX_OUTER_IPV4 should also be set by the application, although
 * a PMD will only check CNE_MBUF_F_TX_OUTER_IP_CKSUM.
 *  - fill the mbuf offload information: outer_l2_len, outer_l3_len
 */
#define CNE_MBUF_F_TX_OUTER_IP_CKSUM (1ULL << 58)

/**
 * Packet outer header is IPv4. This flag must be set when using any
 * outer offload feature (L3 or L4 checksum) to tell the NIC that the
 * outer header of the tunneled packet is an IPv4 packet.
 */
#define CNE_MBUF_F_TX_OUTER_IPV4 (1ULL << 59)

/**
 * Packet outer header is IPv6. This flag must be set when using any
 * outer offload feature (L4 checksum) to tell the NIC that the outer
 * header of the tunneled packet is an IPv6 packet.
 */
#define CNE_MBUF_F_TX_OUTER_IPV6 (1ULL << 60)

#define CNE_MBUF_TYPE_MCAST (1ULL << 61) /** Packet is a Multicast Packet. */
#define CNE_MBUF_TYPE_BCAST (1ULL << 62) /** Packet is a broadcast packet. */
#define CNE_MBUF_TYPE_IPv6  (1ULL << 63) /** Packet is a IPv6 packet. */
#define CNE_MBUF_TYPE_MASK                       \
    (CNE_MBUF_TYPE_MCAST | CNE_MBUF_TYPE_BCAST | \
     CNE_MBUF_TYPE_IPv6) /** Mask of bits for packet types. */
#define CNE_MBUF_IS_MCAST \
    (CNE_MBUF_TYPE_MCAST | CNE_MBUF_TYPE_BCAST) /** Packet mask to detect a multicast packet. */

/**
 * Bitmask of all supported packet Tx offload features flags,
 * which can be set for packet.
 */
#define CNE_MBUF_F_TX_OFFLOAD_MASK                                                           \
    (CNE_MBUF_F_TX_OUTER_IPV6 | CNE_MBUF_F_TX_OUTER_IPV4 | CNE_MBUF_F_TX_OUTER_IP_CKSUM |    \
     CNE_MBUF_F_TX_VLAN | CNE_MBUF_F_TX_IPV6 | CNE_MBUF_F_TX_IPV4 | CNE_MBUF_F_TX_IP_CKSUM | \
     CNE_MBUF_F_TX_L4_MASK | CNE_MBUF_F_TX_IEEE1588_TMST | CNE_MBUF_F_TX_TCP_SEG |           \
     CNE_MBUF_F_TX_QINQ | CNE_MBUF_F_TX_TUNNEL_MASK | CNE_MBUF_F_TX_MACSEC |                 \
     CNE_MBUF_F_TX_SEC_OFFLOAD | CNE_MBUF_F_TX_UDP_SEG | CNE_MBUF_F_TX_OUTER_UDP_CKSUM)

/**
 * Mbuf having an external buffer attached. shinfo in mbuf must be filled.
 */
#define CNE_MBUF_F_EXTERNAL (1ULL << 61)

#define CNE_MBUF_F_INDIRECT (1ULL << 62) /**< Indirect attached mbuf */

/**
 * enum for the tx_offload bit-fields lengths and offsets.
 * defines the layout of cne_mbuf tx_offload field.
 */
enum {
    CNE_MBUF_L2_LEN_BITS        = 7,
    CNE_MBUF_L3_LEN_BITS        = 9,
    CNE_MBUF_L4_LEN_BITS        = 8,
    CNE_MBUF_TSO_SEGSZ_BITS     = 16,
    CNE_MBUF_OUTL3_LEN_BITS     = 9,
    CNE_MBUF_OUTL2_LEN_BITS     = 7,
    CNE_MBUF_TXOFLD_UNUSED_BITS = sizeof(uint64_t) * CHAR_BIT - CNE_MBUF_L2_LEN_BITS -
                                  CNE_MBUF_L3_LEN_BITS - CNE_MBUF_L4_LEN_BITS -
                                  CNE_MBUF_TSO_SEGSZ_BITS - CNE_MBUF_OUTL3_LEN_BITS -
                                  CNE_MBUF_OUTL2_LEN_BITS,
    CNE_MBUF_L2_LEN_OFS        = 0,
    CNE_MBUF_L3_LEN_OFS        = CNE_MBUF_L2_LEN_OFS + CNE_MBUF_L2_LEN_BITS,
    CNE_MBUF_L4_LEN_OFS        = CNE_MBUF_L3_LEN_OFS + CNE_MBUF_L3_LEN_BITS,
    CNE_MBUF_TSO_SEGSZ_OFS     = CNE_MBUF_L4_LEN_OFS + CNE_MBUF_L4_LEN_BITS,
    CNE_MBUF_OUTL3_LEN_OFS     = CNE_MBUF_TSO_SEGSZ_OFS + CNE_MBUF_TSO_SEGSZ_BITS,
    CNE_MBUF_OUTL2_LEN_OFS     = CNE_MBUF_OUTL3_LEN_OFS + CNE_MBUF_OUTL3_LEN_BITS,
    CNE_MBUF_TXOFLD_UNUSED_OFS = CNE_MBUF_OUTL2_LEN_OFS + CNE_MBUF_OUTL2_LEN_BITS,
};

#ifdef __cplusplus
}
#endif

#endif /* _PKTMBUF_OFFLOAD_H_ */
