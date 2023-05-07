/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Intel Corporation
 */

#ifndef _DIR248_AVX512_H_
#define _DIR248_AVX512_H_

#include <stdint.h>        // for uint32_t, uint64_t

void cne_dir24_8_vec_lookup_bulk_1b(void *p, const uint32_t *ips, uint64_t *next_hops,
                                    const unsigned int n);

void cne_dir24_8_vec_lookup_bulk_2b(void *p, const uint32_t *ips, uint64_t *next_hops,
                                    const unsigned int n);

void cne_dir24_8_vec_lookup_bulk_4b(void *p, const uint32_t *ips, uint64_t *next_hops,
                                    const unsigned int n);

void cne_dir24_8_vec_lookup_bulk_8b(void *p, const uint32_t *ips, uint64_t *next_hops,
                                    const unsigned int n);

#endif /* _DIR248_AVX512_H_ */
