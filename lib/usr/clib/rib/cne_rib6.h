/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CNE_RIB6_H_
#define _CNE_RIB6_H_

/**
 * @file
 *
 * CNE rib6 library.
 *
 * Level compressed tree implementation for IPv6 Longest Prefix Match
 */

#include <cne_common.h>        // for CNDP_API, CNE_MAX, CNE_MIN
#include <stdint.h>            // for uint8_t, int16_t, uint64_t, UINT8_MAX, uint16_t
#include <string.h>            // for NULL, memcpy, size_t

#ifdef __cplusplus
extern "C" {
#endif

#define CNE_RIB6_IPV6_ADDR_SIZE 16

/**
 * cne_rib6_get_nxt() flags
 */
enum {
    /** flag to get all subroutes in a RIB tree */
    CNE_RIB6_GET_NXT_ALL,
    /** flag to get first matched subroutes in a RIB tree */
    CNE_RIB6_GET_NXT_COVER
};

struct cne_rib6;
struct cne_rib6_node;

/** RIB configuration structure */
struct cne_rib6_conf {
    /**
     * Size of extension block inside cne_rib_node.
     * This space could be used to store additional user
     * defined data.
     */
    size_t ext_sz; /* size of cne_rib_node's pool */
    int max_nodes;
};

/**
 * Copy IPv6 address from one location to another
 *
 * @param dst
 *  pointer to the place to copy
 * @param src
 *  pointer from where to copy
 */
static inline void
cne_rib6_copy_addr(uint8_t *dst, const uint8_t *src)
{
    if ((dst == NULL) || (src == NULL))
        return;
    memcpy(dst, src, CNE_RIB6_IPV6_ADDR_SIZE);
}

/**
 * Compare two IPv6 addresses
 *
 * @param ip1
 *  pointer to the first ipv6 address
 * @param ip2
 *  pointer to the second ipv6 address
 *
 * @return
 *  1 if equal
 *  0 otherwise
 */
static inline int
cne_rib6_is_equal(const uint8_t *ip1, const uint8_t *ip2)
{
    int i;

    if ((ip1 == NULL) || (ip2 == NULL))
        return 0;
    for (i = 0; i < CNE_RIB6_IPV6_ADDR_SIZE; i++) {
        if (ip1[i] != ip2[i])
            return 0;
    }
    return 1;
}

/**
 * Get 8-bit part of 128-bit IPv6 mask
 *
 * @param depth
 *  ipv6 prefix length
 * @param byte
 *  position of a 8-bit chunk in the 128-bit mask
 *
 * @return
 *  8-bit chunk of the 128-bit IPv6 mask
 */
static inline uint8_t
get_msk_part(uint8_t depth, int byte)
{
    uint8_t part;

    byte &= 0xf;
    depth = CNE_MIN(depth, 128);
    part  = CNE_MAX((int16_t)depth - (byte * 8), 0);
    part  = (part > 8) ? 8 : part;
    return (uint16_t)(~UINT8_MAX) >> part;
}

/**
 * Lookup an IP into the RIB structure
 *
 * @param rib
 *  RIB object handle
 * @param ip
 *  IP to be looked up in the RIB
 * @return
 *  pointer to struct cne_rib6_node on success
 *  NULL otherwise
 */
CNDP_API struct cne_rib6_node *cne_rib6_lookup(struct cne_rib6 *rib,
                                               const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE]);

/**
 * Lookup less specific route into the RIB structure
 *
 * @param ent
 *  Pointer to struct cne_rib6_node that represents target route
 * @return
 *  pointer to struct cne_rib6_node that represents
 *   less specific route on success
 *  NULL otherwise
 */
CNDP_API struct cne_rib6_node *cne_rib6_lookup_parent(struct cne_rib6_node *ent);

/**
 * Provides exact mach lookup of the prefix into the RIB structure
 *
 * @param rib
 *  RIB object handle
 * @param ip
 *  net to be looked up in the RIB
 * @param depth
 *  prefix length
 * @return
 *  pointer to struct cne_rib6_node on success
 *  NULL otherwise
 */
CNDP_API struct cne_rib6_node *cne_rib6_lookup_exact(struct cne_rib6 *rib,
                                                     const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE],
                                                     uint8_t depth);

/**
 * Retrieve next more specific prefix from the RIB
 * that is covered by ip/depth supernet in an ascending order
 *
 * @param rib
 *  RIB object handle
 * @param ip
 *  net address of supernet prefix that covers returned more specific prefixes
 * @param depth
 *  supernet prefix length
 * @param last
 *   pointer to the last returned prefix to get next prefix
 *   or
 *   NULL to get first more specific prefix
 * @param flag
 *  -CNE_RIB6_GET_NXT_ALL
 *   get all prefixes from subtrie
 *  -CNE_RIB6_GET_NXT_COVER
 *   get only first more specific prefix even if it have more specifics
 * @return
 *  pointer to the next more specific prefix
 *  NULL if there is no prefixes left
 */
CNDP_API struct cne_rib6_node *cne_rib6_get_nxt(struct cne_rib6 *rib,
                                                const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE],
                                                uint8_t depth, struct cne_rib6_node *last,
                                                int flag);

/**
 * Remove prefix from the RIB
 *
 * @param rib
 *  RIB object handle
 * @param ip
 *  net to be removed from the RIB
 * @param depth
 *  prefix length
 */
CNDP_API void cne_rib6_remove(struct cne_rib6 *rib, const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE],
                              uint8_t depth);

/**
 * Insert prefix into the RIB
 *
 * @param rib
 *  RIB object handle
 * @param ip
 *  net to be inserted to the RIB
 * @param depth
 *  prefix length
 * @return
 *  pointer to new cne_rib6_node on success
 *  NULL otherwise
 */
CNDP_API struct cne_rib6_node *
cne_rib6_insert(struct cne_rib6 *rib, const uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE], uint8_t depth);

/**
 * Get an ip from cne_rib6_node
 *
 * @param node
 *  pointer to the rib6 node
 * @param ip
 *  pointer to the ipv6 to save
 * @return
 *  0 on success
 *  -1 on failure with cne_errno indicating reason for failure.
 */
CNDP_API int cne_rib6_get_ip(const struct cne_rib6_node *node, uint8_t ip[CNE_RIB6_IPV6_ADDR_SIZE]);

/**
 * Get a depth from cne_rib6_node
 *
 * @param node
 *  pointer to the rib6 node
 * @param depth
 *  pointer to the depth to save
 * @return
 *  0 on success
 *  -1 on failure with cne_errno indicating reason for failure.
 */
CNDP_API int cne_rib6_get_depth(const struct cne_rib6_node *node, uint8_t *depth);

/**
 * Get ext field from the cne_rib6_node
 * It is caller responsibility to make sure there are necessary space
 * for the ext field inside rib6 node.
 *
 * @param node
 *  pointer to the cne_rib6_node
 * @return
 *  pointer to the ext
 */
CNDP_API void *cne_rib6_get_ext(struct cne_rib6_node *node);

/**
 * Get nexthop from the cne_rib6_node
 *
 * @param node
 *  pointer to the rib6 node
 * @param nh
 *  pointer to the nexthop to save
 * @return
 *  0 on success
 *  -1 on failure, with cne_errno indicating reason for failure.
 */
CNDP_API int cne_rib6_get_nh(const struct cne_rib6_node *node, uint64_t *nh);

/**
 * Set nexthop into the cne_rib6_node
 *
 * @param node
 *  pointer to the rib6 node
 * @param nh
 *  nexthop value to set to the rib6 node
 * @return
 *  0 on success
 *  -1 on failure, with cne_errno indicating reason for failure.
 */
CNDP_API int cne_rib6_set_nh(struct cne_rib6_node *node, uint64_t nh);

/**
 * Create RIB
 *
 * @param name
 *  RIB name
 * @param conf
 *  Structure containing the configuration
 * @return
 *  Pointer to RIB object on success
 *  NULL otherwise with cne_errno indicating reason for failure.
 */
CNDP_API struct cne_rib6 *cne_rib6_create(const char *name, const struct cne_rib6_conf *conf);

/**
 * Free an RIB object.
 *
 * @param rib
 *   RIB object handle
 * @return
 *   None
 */
CNDP_API void cne_rib6_free(struct cne_rib6 *rib);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_RIB6_H_ */
