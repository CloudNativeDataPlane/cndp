/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2019 Vladimir Medvedkin <medvedkinv@gmail.com>
 */

#ifndef _CNE_THASH_H
#define _CNE_THASH_H

/**
 * @file
 *
 * toeplitz hash functions.
 */

/**
 * Software implementation of the Toeplitz hash function used by RSS.
 * Can be used either for packet distribution on single queue NIC
 * or for simulating of RSS computation on specific NIC (for example
 * after GRE header decapsulating)
 */

#include <stdint.h>
#include <cne_byteorder.h>
#include <cne_common.h>
#include <cne_vect.h>
#include <net/cne_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Byte swap mask used for converting IPv6 address
 * 4-byte chunks to CPU byte order
 */
static const __m128i cne_thash_ipv6_bswap_mask = {0x0405060700010203ULL, 0x0C0D0E0F08090A0BULL};

/**
 * length in dwords of input tuple to
 * calculate hash of ipv4 header only
 */
#define CNE_THASH_V4_L3_LEN \
    ((sizeof(struct cne_ipv4_tuple) - sizeof(((struct cne_ipv4_tuple *)0)->sctp_tag)) / 4)

/**
 * length in dwords of input tuple to
 * calculate hash of ipv4 header +
 * transport header
 */
#define CNE_THASH_V4_L4_LEN ((sizeof(struct cne_ipv4_tuple)) / 4)

/**
 * length in dwords of input tuple to
 * calculate hash of ipv6 header only
 */
#define CNE_THASH_V6_L3_LEN \
    ((sizeof(struct cne_ipv6_tuple) - sizeof(((struct cne_ipv6_tuple *)0)->sctp_tag)) / 4)

/**
 * length in dwords of input tuple to
 * calculate hash of ipv6 header +
 * transport header
 */
#define CNE_THASH_V6_L4_LEN ((sizeof(struct cne_ipv6_tuple)) / 4)

/**
 * IPv4 tuple
 * addresses and lports/sctp_tag have to be CPU byte order
 */
struct cne_ipv4_tuple {
    uint32_t src_addr;
    uint32_t dst_addr;
    CNE_STD_C11
    union {
        struct {
            uint16_t dport;
            uint16_t sport;
        };
        uint32_t sctp_tag;
    };
};

/**
 * IPv6 tuple
 * Addresses have to be filled by cne_thash_load_v6_addr()
 * lports/sctp_tag have to be CPU byte order
 */
struct cne_ipv6_tuple {
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
    CNE_STD_C11
    union {
        struct {
            uint16_t dport;
            uint16_t sport;
        };
        uint32_t sctp_tag;
    };
};

union cne_thash_tuple {
    struct cne_ipv4_tuple v4;
    struct cne_ipv6_tuple v6;
} __attribute__((aligned(XMM_SIZE)));

/**
 * Prepare special converted key to use with cne_softrss_be()
 * @param orig
 *   pointer to original RSS key
 * @param targ
 *   pointer to target RSS key
 * @param len
 *   RSS key length
 */
static inline void
cne_convert_rss_key(const uint32_t *orig, uint32_t *targ, int len)
{
    int i;

    for (i = 0; i < (len >> 2); i++)
        targ[i] = be32toh(orig[i]);
}

/**
 * Prepare and load IPv6 addresses (src and dst)
 * into target tuple
 * @param orig
 *   Pointer to ipv6 header of the original packet
 * @param targ
 *   Pointer to cne_ipv6_tuple structure
 */
static inline void
cne_thash_load_v6_addrs(const struct cne_ipv6_hdr *orig, union cne_thash_tuple *targ)
{
    __m128i ipv6                  = _mm_loadu_si128((const __m128i *)orig->src_addr);
    *(__m128i *)targ->v6.src_addr = _mm_shuffle_epi8(ipv6, cne_thash_ipv6_bswap_mask);
    ipv6                          = _mm_loadu_si128((const __m128i *)orig->dst_addr);
    *(__m128i *)targ->v6.dst_addr = _mm_shuffle_epi8(ipv6, cne_thash_ipv6_bswap_mask);
}

/**
 * Generic implementation. Can be used with original rss_key
 * @param input_tuple
 *   Pointer to input tuple
 * @param input_len
 *   Length of input_tuple in 4-bytes chunks
 * @param rss_key
 *   Pointer to RSS hash key.
 * @return
 *   Calculated hash value.
 */
static inline uint32_t
cne_softrss(uint32_t *input_tuple, uint32_t input_len, const uint8_t *rss_key)
{
    uint32_t i, j, map, ret = 0;

    for (j = 0; j < input_len; j++) {
        for (map = input_tuple[j]; map; map &= (map - 1)) {
            i = cne_bsf32(map);
            ret ^= htobe32(((const uint32_t *)rss_key)[j]) << (31 - i) |
                   (uint32_t)((uint64_t)(htobe32(((const uint32_t *)rss_key)[j + 1])) >> (i + 1));
        }
    }
    return ret;
}

/**
 * Optimized implementation.
 * If you want the calculated hash value matches NIC RSS value
 * you have to use special converted key with cne_convert_rss_key() fn.
 * @param input_tuple
 *   Pointer to input tuple
 * @param input_len
 *   Length of input_tuple in 4-bytes chunks
 * @param *rss_key
 *   Pointer to RSS hash key.
 * @return
 *   Calculated hash value.
 */
static inline uint32_t
cne_softrss_be(uint32_t *input_tuple, uint32_t input_len, const uint8_t *rss_key)
{
    uint32_t i, j, map, ret = 0;

    for (j = 0; j < input_len; j++) {
        for (map = input_tuple[j]; map; map &= (map - 1)) {
            i = cne_bsf32(map);
            ret ^= ((const uint32_t *)rss_key)[j] << (31 - i) |
                   (uint32_t)((uint64_t)(((const uint32_t *)rss_key)[j + 1]) >> (i + 1));
        }
    }
    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* _CNE_THASH_H */
