/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2023 Intel Corporation
 */

#ifndef _CNE_FIB_H_
#define _CNE_FIB_H_

/**
 * @file
 *
 * CNE FIB library.
 *
 * FIB (Forwarding information base) implementation
 * for IPv4 Longest Prefix Match
 */

#include <stdint.h>        // for uint32_t, uint64_t, uint8_t
#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cne_fib;
struct cne_rib;

/** Maximum depth value possible for IPv4 FIB. */
#define CNE_FIB_MAXDEPTH 32

/** Type of FIB struct */
enum cne_fib_type {
    CNE_FIB_DUMMY,  /**< RIB tree based FIB */
    CNE_FIB_DIR24_8 /**< DIR24_8 based FIB */
};

/** Modify FIB function */
typedef int (*cne_fib_modify_fn_t)(struct cne_fib *fib, uint32_t ip, uint8_t depth,
                                   uint64_t next_hop, int op);
/** FIB bulk lookup function */
typedef void (*cne_fib_lookup_fn_t)(void *fib, const uint32_t *ips, uint64_t *next_hops,
                                    const unsigned int n);

enum cne_fib_op {
    CNE_FIB_ADD,
    CNE_FIB_DEL,
};

/** Size of nexthop (1 << nh_sz) bits for DIR24_8 based FIB */
enum cne_fib_dir24_8_nh_sz {
    CNE_FIB_DIR24_8_1B,
    CNE_FIB_DIR24_8_2B,
    CNE_FIB_DIR24_8_4B,
    CNE_FIB_DIR24_8_8B
};

/** Type of lookup function implementation */
enum cne_fib_lookup_type {
    CNE_FIB_LOOKUP_DEFAULT,
    /**< Selects the best implementation based on the max simd bitwidth */
    CNE_FIB_LOOKUP_DIR24_8_SCALAR_MACRO,
    /**< Macro based lookup function */
    CNE_FIB_LOOKUP_DIR24_8_SCALAR_INLINE,
    /**<
     * Lookup implementation using inlined functions
     * for different next hop sizes
     */
    CNE_FIB_LOOKUP_DIR24_8_SCALAR_UNI,
    /**<
     * Unified lookup function for all next hop sizes
     */
    CNE_FIB_LOOKUP_DIR24_8_VECTOR_AVX512
    /**< Vector implementation using AVX512 */
};

/** FIB configuration structure */
struct cne_fib_conf {
    enum cne_fib_type type; /**< Type of FIB struct */
    /** Default value returned on lookup if there is no route */
    uint64_t default_nh;
    int max_routes;
    union {
        struct {
            enum cne_fib_dir24_8_nh_sz nh_sz;
            uint32_t num_tbl8;
        } dir24_8;
    };
};

/**
 * Create a FIB structure using the configuration specified.
 *
 * @param name
 *  FIB name
 * @param conf
 *  Structure containing the configuration
 * @return
 *  Pointer to the FIB object on success or NULL on error
 */
struct cne_fib *cne_fib_create(const char *name, struct cne_fib_conf *conf);

/**
 * Free an FIB object.
 *
 * @param fib
 *   FIB object handle
 * @return
 *   None
 */
void cne_fib_free(struct cne_fib *fib);

/**
 * Add a route to the FIB.
 *
 * @param fib
 *   FIB object handle
 * @param ip
 *   IPv4 prefix address to be added to the FIB
 * @param depth
 *   Prefix length
 * @param next_hop
 *   Next hop to be added to the FIB
 * @return
 *   0 on success, negative value otherwise
 */
int cne_fib_add(struct cne_fib *fib, uint32_t ip, uint8_t depth, uint64_t next_hop);

/**
 * Delete a rule from the FIB.
 *
 * @param fib
 *   FIB object handle
 * @param ip
 *   IPv4 prefix address to be deleted from the FIB
 * @param depth
 *   Prefix length
 * @return
 *   0 on success, negative value otherwise
 */
int cne_fib_delete(struct cne_fib *fib, uint32_t ip, uint8_t depth);

/**
 * Lookup multiple IP addresses in the FIB.
 *
 * @param fib
 *   FIB object handle
 * @param ips
 *   Array of IPs to be looked up in the FIB
 * @param next_hops
 *   Next hop of the most specific rule found for IP.
 *   This is an array of eight byte values.
 *   If the lookup for the given IP failed, then corresponding element would
 *   contain default nexthop value configured for a FIB.
 * @param n
 *   Number of elements in ips (and next_hops) array to lookup.
 *  @return
 *   -EINVAL for incorrect arguments, otherwise 0
 */
int cne_fib_lookup_bulk(struct cne_fib *fib, uint32_t *ips, uint64_t *next_hops, int n);

/**
 * Get pointer to the dataplane specific struct
 *
 * @param fib
 *   FIB object handle
 * @return
 *   Pointer to the dataplane structure on success
 *   NULL otherwise
 */
void *cne_fib_get_dp(struct cne_fib *fib);

/**
 * Get pointer to the RIB
 *
 * @param fib
 *   FIB object handle
 * @return
 *   Pointer to the RIB structure on success or NULL on error
 */
struct cne_rib *cne_fib_get_rib(struct cne_fib *fib);

/**
 * Set lookup function based on type
 *
 * @param fib
 *   FIB object handle
 * @param type
 *   type of lookup function
 *
 * @return
 *   0 on success
 *   -EINVAL on failure
 */
int cne_fib_select_lookup(struct cne_fib *fib, enum cne_fib_lookup_type type);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_FIB_H_ */
