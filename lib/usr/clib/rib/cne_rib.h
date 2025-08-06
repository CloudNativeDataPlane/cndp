/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright (c) 2019-2025 Intel Corporation
 */

#ifndef _CNE_RIB_H_
#define _CNE_RIB_H_

/**
 * @file
 *
 * CNE RIB library.
 *
 * Level compressed tree implementation for IPv4 Longest Prefix Match
 */

#include <stdlib.h>
#include <stdint.h>

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * cne_rib_get_nxt() flags
 */
enum {
    /** flag to get all subroutes in a RIB tree */
    CNE_RIB_GET_NXT_ALL,
    /** flag to get first matched subroutes in a RIB tree */
    CNE_RIB_GET_NXT_COVER
};

struct cne_rib;
struct cne_rib_node;

/** RIB configuration structure */
struct cne_rib_conf {
    /**
     * Size of extension block inside cne_rib_node.
     * This space could be used to store additional user
     * defined data.
     */
    size_t ext_sz; /* size of cne_rib_node's pool */
    int max_nodes;
};

/**
 * Get an IPv4 mask from prefix length
 * It is caller responsibility to make sure depth is not bigger than 32
 *
 * @param depth
 *   prefix length
 * @return
 *  IPv4 mask
 */
static inline uint32_t
cne_rib_depth_to_mask(uint8_t depth)
{
    return (uint32_t)(UINT64_MAX << (32 - depth));
}

/**
 * Lookup an IP into the RIB structure
 *
 * @param rib
 *  RIB object handle
 * @param ip
 *  IP to be looked up in the RIB
 * @return
 *  pointer to struct cne_rib_node on success
 *  NULL otherwise
 */
CNDP_API struct cne_rib_node *cne_rib_lookup(struct cne_rib *rib, uint32_t ip);

/**
 * Lookup less specific route into the RIB structure
 *
 * @param ent
 *  Pointer to struct cne_rib_node that represents target route
 * @return
 *  pointer to struct cne_rib_node that represents
 *   less specific route on success
 *  NULL otherwise
 */
CNDP_API struct cne_rib_node *cne_rib_lookup_parent(struct cne_rib_node *ent);

/**
 * Lookup prefix into the RIB structure
 *
 * @param rib
 *  RIB object handle
 * @param ip
 *  net to be looked up in the RIB
 * @param depth
 *  prefix length
 * @return
 *  pointer to struct cne_rib_node on success
 *  NULL otherwise
 */
CNDP_API struct cne_rib_node *cne_rib_lookup_exact(struct cne_rib *rib, uint32_t ip, uint8_t depth);

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
 *  -CNE_RIB_GET_NXT_ALL
 *   get all prefixes from subtrie
 *  -CNE_RIB_GET_NXT_COVER
 *   get only first more specific prefix even if it have more specifics
 * @return
 *  pointer to the next more specific prefix
 *  NULL if there is no prefixes left
 */
CNDP_API struct cne_rib_node *cne_rib_get_nxt(struct cne_rib *rib, uint32_t ip, uint8_t depth,
                                              struct cne_rib_node *last, int flag);

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
CNDP_API void cne_rib_remove(struct cne_rib *rib, uint32_t ip, uint8_t depth);

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
 *  pointer to new cne_rib_node on success
 *  NULL otherwise
 */
CNDP_API struct cne_rib_node *cne_rib_insert(struct cne_rib *rib, uint32_t ip, uint8_t depth);

/**
 * Get an ip from cne_rib_node
 *
 * @param node
 *  pointer to the rib node
 * @param ip
 *  pointer to the ip to save
 * @return
 *  0 on success.
 *  -1 on failure with cne_errno indicating reason for failure.
 */
CNDP_API int cne_rib_get_ip(const struct cne_rib_node *node, uint32_t *ip);

/**
 * Get a depth from cne_rib_node
 *
 * @param node
 *  pointer to the rib node
 * @param depth
 *  pointer to the depth to save
 * @return
 *  0 on success.
 *  -1 on failure with cne_errno indicating reason for failure.
 */
CNDP_API int cne_rib_get_depth(const struct cne_rib_node *node, uint8_t *depth);

/**
 * Get ext field from the rib node
 * It is caller responsibility to make sure there are necessary space
 * for the ext field inside rib node.
 *
 * @param node
 *  pointer to the rib node
 * @return
 *  pointer to the ext
 */
CNDP_API void *cne_rib_get_ext(struct cne_rib_node *node);

/**
 * Get nexthop from the rib node
 *
 * @param node
 *  pointer to the rib node
 * @param nh
 *  pointer to the nexthop to save
 * @return
 *  0 on success.
 *  -1 on failure with cne_errno indicating reason for failure.
 */
CNDP_API int cne_rib_get_nh(const struct cne_rib_node *node, uint64_t *nh);

/**
 * Set nexthop into the rib node
 *
 * @param node
 *  pointer to the rib node
 * @param nh
 *  nexthop value to set to the rib node
 * @return
 *  0 on success.
 *  -1 on failure with cne_errno indicating reason for failure.
 */
CNDP_API int cne_rib_set_nh(struct cne_rib_node *node, uint64_t nh);

/**
 * Create RIB
 *
 * @param name
 *  RIB name
 * @param conf
 *  Structure containing the configuration
 * @return
 *  Handle to RIB object on success
 *  NULL otherwise with cne_errno indicating reason for failure.
 */
CNDP_API struct cne_rib *cne_rib_create(const char *name, const struct cne_rib_conf *conf);

/**
 * Free an RIB object.
 *
 * @param rib
 *   RIB object handle
 * @return
 *   None
 */
CNDP_API void cne_rib_free(struct cne_rib *rib);

#ifdef __cplusplus
}
#endif

#endif /* _CNE_RIB_H_ */
