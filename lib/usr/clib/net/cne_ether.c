/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <stdbool.h>        // for false, bool
#include <stdint.h>         // for uint16_t, uint8_t, int8_t, uint64_t
#include <stdlib.h>         // for rand
#include <stdio.h>          // for snprintf
#include <string.h>         // for memcpy
#include <cne_ether.h>

void
ether_random_addr(uint8_t *addr)
{
    uint64_t rnd = rand();
    uint8_t *p   = (uint8_t *)&rnd;

    memcpy(addr, p, ETH_ALEN);
    addr[0] &= (uint8_t)~ETHER_GROUP_ADDR; /* clear multicast bit */
    addr[0] |= ETHER_LOCAL_ADMIN_ADDR;     /* set local assignment bit */
}

void
ether_format_addr(char *buf, uint16_t size, const struct ether_addr *eth_addr)
{
    // clang-format off
    snprintf(buf, size, "%02X:%02X:%02X:%02X:%02X:%02X", eth_addr->ether_addr_octet[0],
             eth_addr->ether_addr_octet[1], eth_addr->ether_addr_octet[2],
             eth_addr->ether_addr_octet[3], eth_addr->ether_addr_octet[4],
             eth_addr->ether_addr_octet[5]);
    // clang-format on
}

static int8_t
get_xdigit(char ch)
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
static bool
get_ether_addr6(const char *s0, struct ether_addr *ea)
{
    const char *s = s0;
    int i;

    for (i = 0; i < ETH_ALEN; i++) {
        int8_t x;

        x = get_xdigit(*s++);
        if (x < 0)
            return false;

        ea->ether_addr_octet[i] = x << 4;
        x                       = get_xdigit(*s++);
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
static bool
get_ether_addr3(const char *s, struct ether_addr *ea)
{
    int i, j;

    for (i = 0; i < ETH_ALEN; i += 2) {
        uint16_t w = 0;

        for (j = 0; j < 4; j++) {
            int8_t x;

            x = get_xdigit(*s++);
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

/*
 * Like ether_aton_r but can handle either
 * XX:XX:XX:XX:XX:XX or XXXX:XXXX:XXXX
 * and is more restrictive.
 */
int
ether_unformat_addr(const char *s, struct ether_addr *ea)
{
    if (get_ether_addr6(s, ea))
        return 0;
    if (get_ether_addr3(s, ea))
        return 0;

    errno = EINVAL;
    return -1;
}

int
ether_addr_is_same(const struct ether_addr *ea1, const struct ether_addr *ea2)
{
    const uint16_t *w1 = (const uint16_t *)ea1;
    const uint16_t *w2 = (const uint16_t *)ea2;

    return ((w1[0] ^ w2[0]) | (w1[1] ^ w2[1]) | (w1[2] ^ w2[2])) == 0;
}

int
ether_addr_is_zero(const struct ether_addr *ea)
{
    const uint16_t *w = (const uint16_t *)ea;

    return (w[0] | w[1] | w[2]) == 0;
}

int
ether_addr_is_unicast(const struct ether_addr *ea)
{
    return (ea->ether_addr_octet[0] & ETHER_GROUP_ADDR) == 0;
}

int
ether_addr_is_multicast(const struct ether_addr *ea)
{
    return ea->ether_addr_octet[0] & ETHER_GROUP_ADDR;
}

int
ether_addr_is_broadcast(const struct ether_addr *ea)
{
    const uint16_t *ea_words = (const uint16_t *)ea;

    return (ea_words[0] == 0xFFFF && ea_words[1] == 0xFFFF && ea_words[2] == 0xFFFF);
}

int
ether_addr_is_universal(const struct ether_addr *ea)
{
    return (ea->ether_addr_octet[0] & ETHER_LOCAL_ADMIN_ADDR) == 0;
}

int
ether_addr_is_local_admin(const struct ether_addr *ea)
{
    return (ea->ether_addr_octet[0] & ETHER_LOCAL_ADMIN_ADDR) != 0;
}

int
ether_addr_is_valid_assigned(const struct ether_addr *ea)
{
    return ether_addr_is_unicast(ea) && (!ether_addr_is_zero(ea));
}

void
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
