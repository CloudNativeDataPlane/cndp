/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_PCB_H
#define __CNET_PCB_H

/**
 * @file
 * CNET PCB routines.
 */

#include <cne_inet.h>        // for in_caddr
#include <stdint.h>          // for uint16_t, uint8_t, int32_t
#include <string.h>          // for NULL, memset

#include "cne_common.h"        // for __cne_aligned, __cne_cache_aligned
#include "cne_log.h"           // for CNE_LOG, CNE_LOG_DEBUG
#include "cne_vec.h"           // for cne_vec (ptr only), vec_add_ptr, vec_alloc_ptr, vec...
#include "cnet_const.h"        // for BEST_MATCH
#include "cnet_stk.h"          // for per_thread_stk, stk_entry, this_stk
#include "mempool.h"           // for mempool_put, mempool_get

#ifdef __cplusplus
extern "C" {
#endif

struct pcb_key {
    struct in_caddr faddr; /**< foreign IP address */
    struct in_caddr laddr; /**< local IP address */
} __cne_aligned(sizeof(void *));

struct netif;
struct chnl;
struct tcb_entry;

struct pcb_entry {
    TAILQ_ENTRY(pcb_entry) next; /**< Pointer to the next pcb_entry in a list */
    struct pcb_key key;          /**< Key values for PCB entry */
    struct netif *netif;         /**< Netif pointer */
    struct chnl *ch;             /**< Channel pointer */
    struct tcb_entry *tcb;       /**< TCB pointer */
    uint16_t opt_flag;           /**< Option flags */
    uint8_t ttl;                 /**< Time to live */
    uint8_t tos;                 /**< TOS value */
    uint8_t closed;              /**< Closed flag */
    uint8_t ip_proto;            /**< IP protocol number */
} __cne_cache_aligned;

struct pcb_hd {
    struct pcb_entry **vec; /**< PCB entries */
    uint16_t local_port;    /**< Local port number i.e. IP local port ID */
};

static inline void
cnet_pcb_free(struct pcb_entry *pcb)
{
    if (pcb) {
        memset(pcb, 0, sizeof(struct pcb_entry));
        pcb->closed   = 1;
        pcb->ip_proto = -1;
        mempool_put(this_stk->pcb_objs, (void *)pcb);
    }
}

static inline struct pcb_entry *
cnet_pcb_alloc(struct pcb_hd *hd, uint16_t proto)
{
    struct pcb_entry *pcb;

    if (mempool_get(this_stk->pcb_objs, (void *)&pcb) < 0)
        return NULL;

    pcb->closed   = 0;
    pcb->ip_proto = proto;

    vec_add(hd->vec, pcb);

    return pcb;
}

static inline void
cnet_pcb_delete(struct pcb_hd *hd, struct pcb_entry *pcb)
{
    struct pcb_entry *p;

    vec_foreach_ptr (p, hd->vec) {
        if (p == pcb) {
            cnet_pcb_free(pcb);
            break;
        }
    }
}

/**
 * Lookup a PCB in the given list to locate the matching PCB or near matching
 * PCB. The flag value denotes is the match is EXACT or a best match. With the
 * local (laddr) and foreign address (faddr) locate the matching or best
 * matching PCB data.
 *
 * Find a matching local, foreign and port address in the PCB list given. A
 * local copy of the local and foreign address is created for the compare when
 * not doing a exact match, but looking for the best match.
 *
 * Parameters:
 * @param hd
 *   A pointer to the PCB list head.
 * @param key
 *   Pointer to key information to PCB list.
 * @param flags
 *   Flags for the compare EXACT or BEST match
 *
 *   PCB laddr |   laddr   |  Type
 *  -----------+-----------+--------
 *    non-Zero |  non-Zero |  Exact
 *    non-Zero |     Zero  |  Best
 *        Zero | non-Zero  |  Best
 *        Zero |     Zero  |  Invalid
 *
 *   PCB faddr |   faddr   |  Type
 *  -----------+-----------+--------
 *    non-Zero |  non-Zero |  Exact
 *    non-Zero |     Zero  |  Best
 *        Zero | non-Zero  |  Best
 *        Zero |     Zero  |  Invalid
 *
 * @return
 *   NULL or the matching PCB pointer.
 */
CNDP_API struct pcb_entry *cnet_pcb_lookup(struct pcb_hd *hd, struct pcb_key *key, int32_t flags);

/**
 * @brief Dump out the PCB information.
 *
 * @param stk
 *   The stack instance pointer to use for dumping the data.
 * @return
 *   N/A
 */
CNDP_API void cnet_pcb_dump(stk_t *stk);

/**
 * Print out the given PCB entry.
 *
 * @param pcb
 *   The PCB entry to dump out
 */
CNDP_API void cnet_pcb_show(struct pcb_entry *pcb);

/**
 * @brief Return the PCB entry matching the given information.
 *
 * @param hd
 *   A pointer to the PCB list head.
 * @param faddr
 *   The foreign address entry to look for in the list.
 * @param laddr
 *   The local address entyr to look for in the list.
 * @return
 *   NULL on error or pointer to a pcb_entry.
 */
static inline struct pcb_entry *
cnet_pcb_locate(struct pcb_hd *hd, struct in_caddr *faddr, struct in_caddr *laddr)
{
    struct pcb_key key;

    *(struct in_caddr *)&key.faddr = *faddr;
    *(struct in_caddr *)&key.laddr = *laddr;

    return cnet_pcb_lookup(hd, &key, BEST_MATCH);
}

#ifdef __cplusplus
}
#endif

#endif /* __CNET_PCB_H */
