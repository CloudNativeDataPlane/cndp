/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CNE_ETHER_H_
#define _CNE_ETHER_H_

#include <errno.h>                 // for errno
#include <stdio.h>                 // for NULL, snprintf
#include <stdint.h>                // for uint8_t, uint16_t, UINT16_MAX, UINT8_MAX
#include <stdlib.h>                // for strtoul
#include <net/ethernet.h>          // for ether_addr, ETHER_MAX_LEN
#include <linux/if_ether.h>        // for ETH_ALEN
#include <stdbool.h>
#include <string.h>

#include <cne_common.h>

/**
 * @file
 *
 * Ethernet Helpers in CNE
 */

#ifdef __cplusplus
extern "C" {
#endif

#define CNE_ETHER_MAX_VLAN_FRAME_LEN (ETHER_MAX_LEN + 4)
/**< Maximum VLAN frame length, including CRC. */

#define CNE_ETHER_MAX_JUMBO_FRAME_LEN 0x3F00 /**< Maximum Jumbo frame length, including CRC. */

#define CNE_ETHER_MAX_VLAN_ID 4095 /**< Maximum VLAN ID. */

#define CNE_ETHER_MIN_MTU 68 /**< Minimum MTU for IPv4 packets, see RFC 791. */

#ifndef ETH_ALEN
#define ETH_ALEN 6

/**
 * Ethernet address:
 * A universally administered address is uniquely assigned to a device by its
 * manufacturer. The first three octets (in transmission order) contain the
 * Organizationally Unique Identifier (OUI). The following three (MAC-48 and
 * EUI-48) octets are assigned by that organization with the only constraint
 * of uniqueness.
 * A locally administered address is assigned to a device by a network
 * administrator and does not contain OUIs.
 * See http://standards.ieee.org/regauth/groupmac/tutorial.html
 */
struct ether_addr {
    uint8_t ether_addr_octet[ETH_ALEN]; /**< Addr bytes in tx order */
} __cne_packed;
#endif

#define ETHER_LOCAL_ADMIN_ADDR 0x02 /**< Locally assigned Eth. address. */
#define ETHER_GROUP_ADDR       0x01 /**< Multicast or broadcast Eth. address. */

/**
 * Ethernet header: Contains the destination address, source address
 * and frame type.
 */
struct cne_ether_hdr {
    struct ether_addr d_addr; /**< Destination address. */
    struct ether_addr s_addr; /**< Source address. */
    uint16_t ether_type;      /**< Frame type. */
} __cne_aligned(2);

/**
 * Ethernet VLAN Header.
 * Contains the 16-bit VLAN Tag Control Identifier and the Ethernet type
 * of the encapsulated frame.
 */
struct cne_vlan_hdr {
    uint16_t vlan_tci;  /**< Priority (3) + CFI (1) + Identifier Code (12) */
    uint16_t eth_proto; /**< Ethernet type of encapsulated frame. */
} __cne_packed;

/* Ethernet frame types */
#define CNE_ETHER_TYPE_IPV4            0x0800 /**< IPv4 Protocol. */
#define CNE_ETHER_TYPE_IPV6            0x86DD /**< IPv6 Protocol. */
#define CNE_ETHER_TYPE_ARP             0x0806 /**< Arp Protocol. */
#define CNE_ETHER_TYPE_RARP            0x8035 /**< Reverse Arp Protocol. */
#define CNE_ETHER_TYPE_VLAN            0x8100 /**< IEEE 802.1Q VLAN tagging. */
#define CNE_ETHER_TYPE_QINQ            0x88A8 /**< IEEE 802.1ad QinQ tagging. */
#define CNE_ETHER_TYPE_PPPOE_DISCOVERY 0x8863 /**< PPPoE Discovery Stage. */
#define CNE_ETHER_TYPE_PPPOE_SESSION   0x8864 /**< PPPoE Session Stage. */
#define CNE_ETHER_TYPE_ETAG            0x893F /**< IEEE 802.1BR E-Tag. */
#define CNE_ETHER_TYPE_1588            0x88F7
/**< IEEE 802.1AS 1588 Precise Time Protocol. */
#define CNE_ETHER_TYPE_SLOW  0x8809 /**< Slow protocols (LACP and Marker). */
#define CNE_ETHER_TYPE_TEB   0x6558 /**< Transparent Ethernet Bridging. */
#define CNE_ETHER_TYPE_LLDP  0x88CC /**< LLDP Protocol. */
#define CNE_ETHER_TYPE_MPLS  0x8847 /**< MPLS ethertype. */
#define CNE_ETHER_TYPE_MPLSM 0x8848 /**< MPLS multicast ethertype. */

/* Ethernet frame types */
#define __ETHER_TYPE_IPV4            0x0008 /**< IPv4 Protocol. */
#define __ETHER_TYPE_IPV6            0xDD86 /**< IPv6 Protocol. */
#define __ETHER_TYPE_ARP             0x0608 /**< Arp Protocol. */
#define __ETHER_TYPE_RARP            0x3580 /**< Reverse Arp Protocol. */
#define __ETHER_TYPE_VLAN            0x0081 /**< IEEE 802.1Q VLAN tagging. */
#define __ETHER_TYPE_QINQ            0xA888 /**< IEEE 802.1ad QinQ tagging. */
#define __ETHER_TYPE_PPPOE_DISCOVERY 0x6388 /**< PPPoE Discovery Stage. */
#define __ETHER_TYPE_PPPOE_SESSION   0x6488 /**< PPPoE Session Stage. */
#define __ETHER_TYPE_ETAG            0x3F89 /**< IEEE 802.1BR E-Tag. */
#define __ETHER_TYPE_1588            0xF788
/**< IEEE 802.1AS 1588 Precise Time Protocol. */
#define __ETHER_TYPE_SLOW  0x0988 /**< Slow protocols (LACP and Marker). */
#define __ETHER_TYPE_TEB   0x5865 /**< Transparent Ethernet Bridging. */
#define __ETHER_TYPE_LLDP  0xCC88 /**< LLDP Protocol. */
#define __ETHER_TYPE_MPLS  0x4788 /**< MPLS ethertype. */
#define __ETHER_TYPE_MPLSM 0x4888 /**< MPLS multicast ethertype. */

/**
 * Check if two Ethernet addresses are the same.
 *
 * @param ea1
 *  A pointer to the first ether_addr structure containing
 *  the ethernet address.
 * @param ea2
 *  A pointer to the second ether_addr structure containing
 *  the ethernet address.
 *
 * @return
 *  True  (1) if the given two ethernet address are the same;
 *  False (0) otherwise.
 */
static inline int
ether_addr_is_same(const struct ether_addr *ea1, const struct ether_addr *ea2)
{
    const uint16_t *w1 = (const uint16_t *)ea1;
    const uint16_t *w2 = (const uint16_t *)ea2;

    return ((w1[0] ^ w2[0]) | (w1[1] ^ w2[1]) | (w1[2] ^ w2[2])) == 0;
}

/**
 * Check if an Ethernet address is filled with zeros.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is filled with zeros;
 *   false (0) otherwise.
 */
static inline int
ether_addr_is_zero(const struct ether_addr *ea)
{
    const uint16_t *w = (const uint16_t *)ea;

    return (w[0] | w[1] | w[2]) == 0;
}

/**
 * Check if an Ethernet address is a unicast address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a unicast address;
 *   false (0) otherwise.
 */
static inline int
ether_addr_is_unicast(const struct ether_addr *ea)
{
    return (ea->ether_addr_octet[0] & ETHER_GROUP_ADDR) == 0;
}

/**
 * Check if an Ethernet address is a multicast address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a multicast address;
 *   false (0) otherwise.
 */
static inline int
ether_addr_is_multicast(const struct ether_addr *ea)
{
    return ea->ether_addr_octet[0] & ETHER_GROUP_ADDR;
}

/**
 * Check if an Ethernet address is a broadcast address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a broadcast address;
 *   false (0) otherwise.
 */
static inline int
ether_addr_is_broadcast(const struct ether_addr *ea)
{
    const uint16_t *ea_words = (const uint16_t *)ea;

    return (ea_words[0] == 0xFFFF && ea_words[1] == 0xFFFF && ea_words[2] == 0xFFFF);
}

/**
 * Check if an Ethernet address is a universally assigned address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a universally assigned address;
 *   false (0) otherwise.
 */
static inline int
ether_addr_is_universal(const struct ether_addr *ea)
{
    return (ea->ether_addr_octet[0] & ETHER_LOCAL_ADMIN_ADDR) == 0;
}

/**
 * Check if an Ethernet address is a locally assigned address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a locally assigned address;
 *   false (0) otherwise.
 */
static inline int
ether_addr_is_local_admin(const struct ether_addr *ea)
{
    return (ea->ether_addr_octet[0] & ETHER_LOCAL_ADMIN_ADDR) != 0;
}

/**
 * Check if an Ethernet address is a valid address. Checks that the address is a
 * unicast address and is not filled with zeros.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is valid;
 *   false (0) otherwise.
 */
static inline int
ether_addr_is_valid_assigned(const struct ether_addr *ea)
{
    return ether_addr_is_unicast(ea) && (!ether_addr_is_zero(ea));
}

/**
 * Generate a random Ethernet address that is locally administered
 * and not multicast.
 * @param addr
 *   A pointer to Ethernet address.
 */
static inline void
ether_random_addr(uint8_t *addr)
{
    uint64_t rnd = rand();
    uint8_t *p   = (uint8_t *)&rnd;

    memcpy(addr, p, ETH_ALEN);
    addr[0] &= (uint8_t)~ETHER_GROUP_ADDR; /* clear multicast bit */
    addr[0] |= ETHER_LOCAL_ADMIN_ADDR;     /* set local assignment bit */
}

/**
 * Fast copy an Ethernet address.
 *
 * @param ea_from
 *   A pointer to a ether_addr structure holding the Ethernet address to copy.
 * @param ea_to
 *   A pointer to a ether_addr structure where to copy the Ethernet address.
 */
static inline void
ether_addr_copy(const struct ether_addr *ea_from, struct ether_addr *ea_to)
{
#ifdef __INTEL_COMPILER
    uint16_t *from_words = (uint16_t *)(ea_from->ether_addr_octet);
    uint16_t *to_words   = (uint16_t *)(ea_to->ether_addr_octet);

    to_words[0] = from_words[0];
    to_words[1] = from_words[1];
    to_words[2] = from_words[2];
#else
    /*
     * Use the common way, because of a strange gcc warning.
     */
    *ea_to = *ea_from;
#endif
}

/* eth_swap(uint16_t * to, uint16_t * from) - Swap two 16 bit values */
static inline void
ether_swap(uint16_t *t, uint16_t *f)
{
    uint16_t v;

    v  = *t;
    *t = *f;
    *f = v;
}

/* eth_addr_swap( struct ether_addr * to, struct ether_addr * from ) - Swap two
   ethernet addresses */
static inline void
ether_addr_swap(struct ether_addr *t, struct ether_addr *f)
{
    uint16_t *d = (uint16_t *)t;
    uint16_t *s = (uint16_t *)f;

    ether_swap(d++, s++);
    ether_swap(d++, s++);
    ether_swap(d, s);
}

#define CNE_ETHER_ADDR_FMT_SIZE 18
/**
 * Format 48bits Ethernet address in pattern xx:xx:xx:xx:xx:xx.
 *
 * @param buf
 *   A pointer to buffer contains the formatted MAC address.
 * @param size
 *   The format buffer size.
 * @param eth_addr
 *   A pointer to a ether_addr structure.
 */
static inline void
ether_format_addr(char *buf, uint16_t size, const struct ether_addr *eth_addr)
{
    // clang-format off
    snprintf(buf, size, "%02X:%02X:%02X:%02X:%02X:%02X", eth_addr->ether_addr_octet[0],
             eth_addr->ether_addr_octet[1], eth_addr->ether_addr_octet[2],
             eth_addr->ether_addr_octet[3], eth_addr->ether_addr_octet[4],
             eth_addr->ether_addr_octet[5]);
    // clang-format on
}

static inline int8_t
__get_xdigit(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

/* Convert 00:11:22:33:44:55 to ethernet address */
static inline bool
__get_ether_addr6(const char *s0, struct ether_addr *ea)
{
    const char *s = s0;
    int i;

    for (i = 0; i < ETH_ALEN; i++) {
        int8_t x;

        x = __get_xdigit(*s++);
        if (x < 0)
            return false;

        ea->ether_addr_octet[i] = x << 4;
        x                       = __get_xdigit(*s++);
        if (x < 0)
            return false;
        ea->ether_addr_octet[i] |= x;

        if (i < ETH_ALEN - 1 && *s++ != ':')
            return false;
    }

    /* return true if at end of string */
    return *s == '\0';
}

/* Convert 0011:2233:4455 to ethernet address */
static inline bool
__get_ether_addr3(const char *s, struct ether_addr *ea)
{
    int i, j;

    for (i = 0; i < ETH_ALEN; i += 2) {
        uint16_t w = 0;

        for (j = 0; j < 4; j++) {
            int8_t x;

            x = __get_xdigit(*s++);
            if (x < 0)
                return false;
            w = (w << 4) | x;
        }
        ea->ether_addr_octet[i]     = w >> 8;
        ea->ether_addr_octet[i + 1] = w & 0xff;

        if (i < ETH_ALEN - 2 && *s++ != ':')
            return false;
    }

    return *s == '\0';
}

/**
 * Convert string with Ethernet address to an ether_addr.
 *
 * @param str
 *   A pointer to buffer contains the formatted MAC address.
 *   The supported formats are:
 *     XX:XX:XX:XX:XX:XX or XXXX:XXXX:XXXX
 *   where XX is a hex digit: 0-9, a-f, or A-F.
 * @param eth_addr
 *   A pointer to a ether_addr structure.
 * @return
 *   0 if successful
 *   -1 and sets errno if invalid string
 */
static inline int
ether_unformat_addr(const char *s, struct ether_addr *ea)
{
    if (__get_ether_addr6(s, ea))
        return 0;
    if (__get_ether_addr3(s, ea))
        return 0;

    errno = EINVAL;
    return -1;
}

/**
 * Convert a string Ethernet MAC address to the binary form
 *
 * @param a
 *   String containing the MAC address in two forms
 *      XX:XX:XX:XX:XX:XX or XXXX:XXXX:XXX
 * @param _e
 *   pointer to a struct ether_addr to place the return value. If the value
 *   is null then use a static location instead.
 * @return
 *   Pointer to the struct ether_addr structure;
 */
static inline struct ether_addr *
cne_ether_aton(const char *a, void *_e)
{
    int i;
    char *end;
    unsigned long o[ETH_ALEN];
    struct ether_addr *e = _e;
    static struct ether_addr ether_addr;

    if (!e)
        e = &ether_addr;

    i = 0;
    do {
        errno = 0;
        o[i]  = strtoul(a, &end, 16);
        if (errno != 0 || end == a || (end[0] != ':' && end[0] != 0))
            return NULL;
        a = end + 1;
    } while (++i != sizeof(o) / sizeof(o[0]) && end[0] != 0);

    /* Junk at the end of line */
    if (end[0] != 0)
        return NULL;

    /* Support the format XX:XX:XX:XX:XX:XX */
    if (i == ETH_ALEN) {
        while (i-- != 0) {
            if (o[i] > UINT8_MAX)
                return NULL;
            e->ether_addr_octet[i] = (uint8_t)o[i];
        }
        /* Support the format XXXX:XXXX:XXXX */
    } else if (i == ETH_ALEN / 2) {
        while (i-- != 0) {
            if (o[i] > UINT16_MAX)
                return NULL;
            e->ether_addr_octet[i * 2]     = (uint8_t)(o[i] >> 8);
            e->ether_addr_octet[i * 2 + 1] = (uint8_t)(o[i] & 0xff);
        }
        /* unknown format */
    } else
        return NULL;

    return e;
}

#ifndef _MTOA_
#define _MTOA_
/* char * inet_mtoa(char * buff, int len, struct ether_addr * eaddr) - Convert MAC address to
 * ascii */
static inline char *
inet_mtoa(char *buff, int len, struct ether_addr *eaddr)
{
    snprintf(buff, len, "%02x:%02x:%02x:%02x:%02x:%02x", eaddr->ether_addr_octet[0],
             eaddr->ether_addr_octet[1], eaddr->ether_addr_octet[2], eaddr->ether_addr_octet[3],
             eaddr->ether_addr_octet[4], eaddr->ether_addr_octet[5]);
    return buff;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* _CNE_ETHER_H_ */
