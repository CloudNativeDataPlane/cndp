/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <stdint.h>            // for uint32_t, uint8_t, uint16_t
#include <cne_common.h>        // for CNE_INIT, CNE_PRIORITY_LAST, __cne_alw...
#include <cne_net_crc.h>

#include "cne_build_config.h"        // for CNE_ARCH_X86_64, CNE_MACHINE_CPUFLAG_P...

#if defined(CNE_ARCH_X86_64) && defined(CNE_MACHINE_CPUFLAG_PCLMULQDQ)
#define X86_64_SSE42_PCLMULQDQ 1
#endif

#ifdef X86_64_SSE42_PCLMULQDQ
#include <net_crc_sse.h>        // for cne_crc16_ccitt_sse42_handler, cne_crc...
#endif

/** CRC polynomials */
#define CRC32_ETH_POLYNOMIAL   0x04c11db7UL
#define CRC16_CCITT_POLYNOMIAL 0x1021U

#define CRC_LUT_SIZE 256

/* crc tables */
static uint32_t crc32_eth_lut[CRC_LUT_SIZE];
static uint32_t crc16_ccitt_lut[CRC_LUT_SIZE];

static uint32_t cne_crc16_ccitt_handler(const uint8_t *data, uint32_t data_len);

static uint32_t cne_crc32_eth_handler(const uint8_t *data, uint32_t data_len);

typedef uint32_t (*cne_net_crc_handler)(const uint8_t *data, uint32_t data_len);

static cne_net_crc_handler *handlers;

static cne_net_crc_handler handlers_scalar[] = {
    [CNE_NET_CRC16_CCITT] = cne_crc16_ccitt_handler,
    [CNE_NET_CRC32_ETH]   = cne_crc32_eth_handler,
};

#ifdef X86_64_SSE42_PCLMULQDQ
static cne_net_crc_handler handlers_sse42[] = {
    [CNE_NET_CRC16_CCITT] = cne_crc16_ccitt_sse42_handler,
    [CNE_NET_CRC32_ETH]   = cne_crc32_eth_sse42_handler,
};
#endif

/**
 * Reflect the bits about the middle
 *
 * @param val
 *   value to be reflected
 *
 * @return
 *   reflected value
 */
static uint32_t
reflect_32bits(uint32_t val)
{
    uint32_t i, res = 0;

    for (i = 0; i < 32; i++)
        if ((val & (1U << i)) != 0)
            res |= (uint32_t)(1U << (31 - i));

    return res;
}

static void
crc32_eth_init_lut(uint32_t poly, uint32_t *lut)
{
    uint32_t i, j;

    for (i = 0; i < CRC_LUT_SIZE; i++) {
        uint32_t crc = reflect_32bits(i);

        for (j = 0; j < 8; j++) {
            if (crc & 0x80000000L)
                crc = (crc << 1) ^ poly;
            else
                crc <<= 1;
        }
        lut[i] = reflect_32bits(crc);
    }
}

static __cne_always_inline uint32_t
crc32_eth_calc_lut(const uint8_t *data, uint32_t data_len, uint32_t crc, const uint32_t *lut)
{
    while (data_len--)
        crc = lut[(crc ^ *data++) & 0xffL] ^ (crc >> 8);

    return crc;
}

static void
cne_net_crc_scalar_init(void)
{
    /* 32-bit crc init */
    crc32_eth_init_lut(CRC32_ETH_POLYNOMIAL, crc32_eth_lut);

    /* 16-bit CRC init */
    crc32_eth_init_lut(CRC16_CCITT_POLYNOMIAL << 16, crc16_ccitt_lut);
}

static inline uint32_t
cne_crc16_ccitt_handler(const uint8_t *data, uint32_t data_len)
{
    /* return 16-bit CRC value */
    return (uint16_t)~crc32_eth_calc_lut(data, data_len, 0xffff, crc16_ccitt_lut);
}

static inline uint32_t
cne_crc32_eth_handler(const uint8_t *data, uint32_t data_len)
{
    /* return 32-bit CRC value */
    return ~crc32_eth_calc_lut(data, data_len, 0xffffffffUL, crc32_eth_lut);
}

void
cne_net_crc_set_alg(enum cne_net_crc_alg alg)
{
    switch (alg) {
#ifdef X86_64_SSE42_PCLMULQDQ
    case CNE_NET_CRC_SSE42:
        handlers = handlers_sse42;
        break;
#endif
        /* fall-through */
    case CNE_NET_CRC_SCALAR:
        /* fall-through */
    default:
        handlers = handlers_scalar;
        break;
    }
}

uint32_t
cne_net_crc_calc(const void *data, uint32_t data_len, enum cne_net_crc_type type)
{
    uint32_t ret;
    cne_net_crc_handler f_handle;

    f_handle = handlers[type];
    ret      = f_handle(data, data_len);

    return ret;
}

/* Select highest available crc algorithm as default one */
CNE_INIT(cne_net_crc_init)
{
    enum cne_net_crc_alg alg = CNE_NET_CRC_SCALAR;

    cne_net_crc_scalar_init();

#ifdef X86_64_SSE42_PCLMULQDQ
    alg = CNE_NET_CRC_SSE42;
    cne_net_crc_sse42_init();
#endif

    cne_net_crc_set_alg(alg);
}
