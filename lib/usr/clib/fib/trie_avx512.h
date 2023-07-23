/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Intel Corporation
 */

#ifndef _TRIE_AVX512_H_
#define _TRIE_AVX512_H_

#include <stdint.h>        // for uint64_t, uint8_t

#include "private_fib6.h"        // for IPV6_ADDR_LEN

void cne_trie_vec_lookup_bulk_2b(void *p, uint8_t ips[][IPV6_ADDR_LEN], uint64_t *next_hops,
                                 const unsigned int n);

void cne_trie_vec_lookup_bulk_4b(void *p, uint8_t ips[][IPV6_ADDR_LEN], uint64_t *next_hops,
                                 const unsigned int n);

void cne_trie_vec_lookup_bulk_8b(void *p, uint8_t ips[][IPV6_ADDR_LEN], uint64_t *next_hops,
                                 const unsigned int n);

#endif /* _TRIE_AVX512_H_ */
