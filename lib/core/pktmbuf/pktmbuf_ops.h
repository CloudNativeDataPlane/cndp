/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation.
 * Copyright (c) 2019-2020 6WIND S.A.
 */

#include <cne_common.h>        // for CNDP_API
#include <stdint.h>            // for uint16_t

#ifndef _PKTMBUF_OPS_H_
#define _PKTMBUF_OPS_H_

/**
 * @file
 *
 * Pktmbuf Operation data and APIs
 */

#ifdef __cplusplus
extern "C" {
#endif

struct pktmbuf_info_s;
struct pktmbuf_s;

/**
 * Initialization/Constructor function prototype
 *
 * @param pi
 *   The pktmbuf_info_t pointer, pktmbuf_pool_init() function
 * @return
 *   0 on success or -1 on error
 */
typedef int (*mbuf_ctor_t)(struct pktmbuf_info_s *pi);

/**
 * Destroy/Deconstructor function prototype
 *
 * @param pi
 *   The pktmbuf_info_t pointer, pktmbuf_pool_init() function
 */
typedef void (*mbuf_dtor_t)(struct pktmbuf_info_s *pi);

/**
 * Allocation function prototype, used to allocate pktmbuf_t pointers.
 *
 * @param pi
 *   The pktmbuf_info_t pointer, pktmbuf_pool_init() function
 * @param pkts
 *   The vector array of pktmbuf_t pointers
 * @param npkts
 *   The number of valid pktmbuy_t pointers in the *pkts* array
 * @return
 *   0 on success or -1 on error
 */
typedef int (*mbuf_alloc_t)(struct pktmbuf_info_s *pi, struct pktmbuf_s **pkts, uint16_t npkts);

/**
 * Free function prototype, used to free pktmbuf_t pointers.
 *
 * @param pi
 *   The pktmbuf_info_t pointer, pktmbuf_pool_init() function
 * @param pkts
 *   The vector array of pktmbuf_t pointers
 * @param npkts
 *   The number of valid pktmbuy_t pointers in the *pkts* array can be zero
 */
typedef void (*mbuf_free_t)(struct pktmbuf_info_s *pi, struct pktmbuf_s **pkts, uint16_t npkts);

/**
 * Function pointers to operate in pktmbuf setup/alloc/free.
 */
typedef struct mbuf_ops {
    mbuf_ctor_t mbuf_ctor;   /**< Initialize/Constructor function for pktmbuf setup */
    mbuf_dtor_t mbuf_dtor;   /**< Destroy/Deconstructor function for pktmbuf setup */
    mbuf_alloc_t mbuf_alloc; /**< Pointer to pktmbuf allocation routine */
    mbuf_free_t mbuf_free;   /**< pointer to pktmbuf free routine */
} mbuf_ops_t;

/**
 * Set the default operation function pointers in the structure pointed to by *ops*
 *
 * @param ops
 *   A pointer to the structure to place the default mbuf operation function pointers.
 */
CNDP_API void pktmbuf_set_default_ops(mbuf_ops_t *ops);

#ifdef __cplusplus
}
#endif

#endif /* _PKTMBUF_OPS_H_ */
