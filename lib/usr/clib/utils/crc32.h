/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *  @(#)libkern.h   8.1 (Berkeley) 6/10/93
 * $FreeBSD$
 */

#ifndef _CRC32_H_
#define _CRC32_H_

#include <stdint.h>        // for uint32_t, uint8_t
#include <sys/cdefs.h>
#include <sys/types.h>
#include <stddef.h>        // for size_t

extern const uint32_t crc32_tab[];

#define rounddown(x, y)  (((x) / (y)) * (y))
#define rounddown2(x, y) ((x) & (~((y) - 1)))               /* if y is power of two */
#define roundup2(x, y)   (((x) + ((y) - 1)) & (~((y) - 1))) /* if y is power of two */

static __inline uint32_t
crc32_raw(const void *buf, size_t size, uint32_t crc)
{
    const uint8_t *p = (const uint8_t *)buf;

    while (size--)
        crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return (crc);
}

static __inline uint32_t
crc32(const void *buf, size_t size)
{
    uint32_t crc;

    crc = crc32_raw(buf, size, ~0U);
    return (crc ^ ~0U);
}

uint32_t calculate_crc32c(uint32_t crc32c, const unsigned char *buffer, unsigned int length);

uint32_t sse42_crc32c(uint32_t, const unsigned char *, unsigned);

#endif /* _CRC32_H_ */
