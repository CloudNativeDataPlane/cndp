/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */

#ifndef __NODE_PRIVATE_H__
#define __NODE_PRIVATE_H__

#include <cne_common.h>
#include <cne_log.h>
#include <pktmbuf.h>

#define NODE_LOG(level, node_name, ...)                                       \
    cne_log(CNE_LOG_##level, __func__, __LINE__,                              \
            CNE_FMT("NODE: %s: " CNE_FMT_HEAD(__VA_ARGS__, ) "\n", node_name, \
                    CNE_FMT_TAIL(__VA_ARGS__, )))

#define node_err(node_name, ...)  NODE_LOG(ERR, node_name, __VA_ARGS__)
#define node_info(node_name, ...) NODE_LOG(INFO, node_name, __VA_ARGS__)
#define node_dbg(node_name, ...)  NODE_LOG(DEBUG, node_name, __VA_ARGS__)

/**
 * Node mbuf private data to store next hop, ttl and checksum.
 */
struct node_mbuf_priv1 {
    union {
        /* IP4 rewrite */
        struct {
            uint16_t nh;
            uint16_t ttl;
            uint32_t cksum;
        };

        uint64_t u;
    };
};

extern int node_mbuf_priv1_dynfield_offset;

/**
 * Node mbuf private area 2.
 */
struct node_mbuf_priv2 {
    uint64_t priv_data;
} __cne_cache_aligned;

#define NODE_MBUF_PRIV2_SIZE sizeof(struct node_mbuf_priv2)

#define OBJS_PER_CLINE (CNE_CACHE_LINE_SIZE / sizeof(void *))

/**
 * Get mbuf_priv1 pointer from pktmbuf.
 *
 * @param
 *   Pointer to the pktmbuf.
 *
 * @return
 *   Pointer to the mbuf_priv1.
 */
static __cne_always_inline struct node_mbuf_priv1 *
node_mbuf_priv1(pktmbuf_t *m, const int offset)
{
    return (struct node_mbuf_priv1 *)((char *)m + offset);
}

/**
 * Get mbuf_priv2 pointer from pktmbuf.
 *
 * @param
 *   Pointer to the pktmbuf.
 *
 * @return
 *   Pointer to the mbuf_priv2.
 */
static __cne_always_inline struct node_mbuf_priv2 *
node_mbuf_priv2(pktmbuf_t *m)
{
    return (struct node_mbuf_priv2 *)((char *)pktmbuf_udata64(m) + sizeof(uint64_t));
}

#endif /* __NODE_PRIVATE_H__ */
