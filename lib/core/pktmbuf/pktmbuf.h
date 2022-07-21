/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 * Copyright (c) 2019-2020 6WIND S.A.
 */

#ifndef _PKTMBUF_H_
#define _PKTMBUF_H_

/**
 * @file
 * Pktmbuf
 *
 * The mbuf library provides the ability to create and destroy buffers
 * that may be used by the CNE application to store message
 * buffers. The message buffers are stored in a mempool, using the
 * CNE mempool library.
 *
 * The preferred way to create a mbuf pool is to use
 * pktmbuf_pool_create(). However, in some situations, an
 * application may want to have more control (ex: populate the pool with
 * specific memory), in this case it is possible to use functions from
 * mempool. See how pktmbuf_pool_create() is implemented for
 * details.
 *
 * This library provides an API to allocate/free packet mbufs, which are
 * used to carry network packets.
 *
 * To understand the concepts of packet buffers or mbufs, you
 * should read "TCP/IP Illustrated, Volume 2: The Implementation,
 * Addison-Wesley, 1995, ISBN 0-201-63354-X from Richard Stevens"
 * http://www.kohala.com/start/tcpipiv2.html
 */

#include <errno.h>                        // for EINVAL
#include <stdint.h>                       // for uint16_t, uint32_t, uint8_t, UINT...
#include <stdio.h>                        // for NULL, FILE
#include <bsd/string.h>                   // for strlcpy
#include <cne_atomic.h>                   // for atomic_uint_least16_t
#include <cne_common.h>                   // for CNDP_API, CNE_STD_C11, __cne_alwa...
#include <cne_branch_prediction.h>        // for likely, unlikely
#include <cne_log.h>                      // for CNE_ASSERT
#include <cne_mmap.h>                     // for mmap_type_t
#include <cne_prefetch.h>                 // for cne_prefetch0
#include <mempool.h>                      // for mempool_t, mempool_get, mempool_g...

#include "pktmbuf_ops.h"        // for mbuf_ops_t
#include "pktmbuf_offload.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    DEFAULT_BURST_SIZE   = 64,          /**< Default burst size */
    DEFAULT_MBUF_COUNT   = (16 * 1024), /**< Default mbuf count */
    DEFAULT_MBUF_SIZE    = 2048,        /**< Default mbuf size data + sizeof(pktmbuf_t) + extra */
    PKTMBUF_PENDING_SZ   = 128,         /**< Size of the pending free mbuf pointers */
    PKTMBUF_INFO_NAME_SZ = 24,          /**< Size of the the info name */
};

struct pktmbuf_info_s;
struct pktmbuf_s;

typedef struct pktmbuf_pool_cfg {
    char *addr;              /**< Pointer to the address of the pktmbuf buffers */
    uint32_t bufcnt;         /**< Number of buffers in the pool */
    uint32_t bufsz;          /**< Size of each buffer in the pool */
    uint32_t cache_sz;       /**< Size of the cache for each thread */
    uint32_t metadata_bufsz; /**< The size of each metadata buffer */
    char *metadata;          /**< Pointer to the metadata buffers */
    mbuf_ops_t *ops;         /**< pktmbuf operation functions */
} pktmbuf_pool_cfg_t;

/**
 * Information structure for pktmbuf buffer and related information.
 */
typedef struct pktmbuf_info_s {
    TAILQ_ENTRY(pktmbuf_info_s) next; /**< Next pktmbuf_info structure entry */
    char name[PKTMBUF_INFO_NAME_SZ];  /**< pktmbuf_info name string can be empty */
    void *addr;                       /**< Address of pktmbuf array */
    void *pd;                         /**< Pool data pointer i.e. mempool pointer like value */
    mbuf_ops_t ops;                   /**< pktmbuf functions pointers */
    uint32_t bufcnt;                  /**< Number of buffers created */
    uint32_t bufsz;                   /**< Size of each buffer */
    uint32_t cache_sz;                /**< Cache size if needed for allocation cache */
    uint32_t metadata_bufsz;          /**< Size of of metadata buffers */
    char *metadata;                   /**< Pointer to metadata buffers */
} pktmbuf_info_t;

/**
 * Some NICs need at least 2KB buffer to RX standard Ethernet frame without
 * splitting it into multiple segments.
 * So, for mbufs that planned to be involved in RX/TX, the recommended
 * minimal buffer length is 2KB.
 */
#define CNE_MBUF_DEFAULT_DATAROOM (2 * 1024)
#define CNE_MBUF_DEFAULT_BUF_SIZE CNE_MBUF_DEFAULT_DATAROOM

/**
 * The generic pktmbuf_s, containing a packet mbuf.
 */
struct pktmbuf_s {
    void *pooldata;      /**< pktmbuf information pool data pointer */
    void *buf_addr;      /**< Virtual address of segment buffer */
    uint32_t hash;       /**< Hash value */
    uint32_t meta_index; /**< Index into the metadata array if present */
    uint16_t data_off;   /**< Data offset */
    uint16_t lport;      /**< RX lport number */
    uint16_t buf_len;    /**< Length of segment buffer - sizeof(pktmbuf_t) */
    uint16_t data_len;   /**< Amount of data in segment buffer */

    /*
     * The packet type, which is the combination of outer/inner L2, L3, L4
     * and tunnel types. The packet_type is about data really present in the
     * pktmbuf. Example: if vlan stripping is enabled, a received vlan packet
     * would have CNE_PTYPE_L2_ETHER and not CNE_PTYPE_L2_VLAN because the
     * vlan is stripped from the data.
     */
    CNE_STD_C11
    union {
        uint32_t packet_type; /**< L2/L3/L4 and tunnel information. */
        CNE_STD_C11
        struct {
            uint8_t l2_type : 4;  /**< (Outer) L2 type. */
            uint8_t l3_type : 4;  /**< (Outer) L3 type. */
            uint8_t l4_type : 4;  /**< (Outer) L4 type. */
            uint8_t tun_type : 4; /**< Tunnel type. */
            CNE_STD_C11
            union {
                uint8_t inner_esp_next_proto;
                /**< ESP next protocol type, valid if
                 * CNE_PTYPE_TUNNEL_ESP tunnel type is set
                 * on both Tx and Rx.
                 */
                CNE_STD_C11
                struct {
                    uint8_t inner_l2_type : 4; /**< Inner L2 type. */
                    uint8_t inner_l3_type : 4; /**< Inner L3 type. */
                };
            };
            uint8_t inner_l4_type : 4; /**< Inner L4 type. */
        };
    };

    /**
     * Reference counter. Its size should at least equal to the size
     * of lport field (16 bits), to support zero-copy broadcast.
     * It should only be accessed using the following functions:
     * pktmbuf_refcnt_update(), pktmbuf_refcnt_read(), and
     * pktmbuf_refcnt_set(). The functionality of these functions (atomic,
     * or non-atomic) is controlled by the CONFIG_CNE_MBUF_REFCNT_ATOMIC
     * config option.
     */
    CNE_STD_C11
    union {
        CNE_ATOMIC(uint_least16_t) refcnt_atomic; /**< Atomically accessed refcnt */
        uint16_t refcnt;                          /**< Non-atomically accessed refcnt */
    };

    uint16_t rsvd16;

    /* fields to support TX offloads */
    CNE_STD_C11
    union {
        uint64_t tx_offload; /**< combined for easy fetch */
        CNE_STD_C11
        struct {
            uint64_t l2_len : CNE_MBUF_L2_LEN_BITS;
            /**< L2 (MAC) Header Length for non-tunneling pkt.
             * Outer_L4_len + ... + Inner_L2_len for tunneling pkt.
             */
            uint64_t l3_len : CNE_MBUF_L3_LEN_BITS;       /**< L3 (IP) Header Length. */
            uint64_t l4_len : CNE_MBUF_L4_LEN_BITS;       /**< L4 (TCP/UDP) Header Length. */
            uint64_t tso_segsz : CNE_MBUF_TSO_SEGSZ_BITS; /**< TCP TSO segment size */

            /*
             * Fields for Tx offloading of tunnels.
             * These are undefined for packets which don't request
             * any tunnel offloads (outer IP or UDP checksum,
             * tunnel TSO).
             *
             * PMDs should not use these fields unconditionally
             * when calculating offsets.
             *
             * Applications are expected to set appropriate tunnel
             * offload flags when they fill in these fields.
             */
            uint64_t outer_l3_len : CNE_MBUF_OUTL3_LEN_BITS; /**< Outer L3 (IP) Hdr Length. */
            uint64_t outer_l2_len : CNE_MBUF_OUTL2_LEN_BITS; /**< Outer L2 (MAC) Hdr Length. */

            /* uint64_t unused:CNE_MBUF_TXOFLD_UNUSED_BITS; */
        };
    };

    uint64_t ol_flags; /**< Offload flags */

    CNE_STD_C11
    union {               /**< Extra user supplied data or pointer to data */
        void *userptr;    /**< 64bit user supplied pointer (optional) */
        uint64_t udata64; /**< 64bit data value (optional) */
    };
} __cne_cache_aligned;

typedef struct pktmbuf_s pktmbuf_t;

/**
 * Structure to help with bulk free of mbufs.
 *
 * As the pktmbuf_free_bulk is called this structure holds all of the mbufs
 * allocated from the same pool. When a different pool is found in the array of
 * mbufs pointers they are freed and the set of mbufs to a given pool is created.
 */
typedef struct pktmbuf_pending {
    uint16_t nb_pending; /**< The number of current pending mbufs in thr pending array */
    uint16_t pending_sz; /**< Max number of mbufs that can be held in the pending array */
    void *pooldata;      /**< The current pool pointer for the mbufs in the pending array */
    pktmbuf_t *pending[PKTMBUF_PENDING_SZ]; /**< array of mbufs to be freed */
} pktmbuf_pending_t;

/**
 * Destroy the pktmbuf_info_t structure
 *
 * @param pi
 *   Free the data and pktmbuf_info_t structure data.
 */
CNDP_API void pktmbuf_destroy(pktmbuf_info_t *pi);

/**
 * Create the pktmbuf_info_t structure with no external metadata information.
 *
 * @param addr
 *   The starting address of the buffer space
 * @param bufcnt
 *   Number of buffers to create or allocate
 * @param bufsz
 *   The size of each buffer to be allocated
 * @param cache_sz
 *   Cache size for mempool or other user needs, can be zero for no cache.
 * @param ops
 *   Pointer to mbuf_ops_t structure for mbuf operator function pointers. This
 *   structure is copied into the pktmbuf_info_t.ops structure and can be NULL.
 * @return
 *   NULL on error or a valid pktmbuf_info_t pointer.
 */
CNDP_API pktmbuf_info_t *pktmbuf_pool_create(char *addr, uint32_t bufcnt, uint32_t bufsz,
                                             uint32_t cache_sz, mbuf_ops_t *ops);

/**
 * Create the pktmbuf_info_t structure and setup some of the fields
 *
 * @param cfg
 *   Pointer to a configuration structure.
 *     addr - The starting address of the buffer space
 *     bufcnt - Number of buffers to create or allocate, using the *mtype* for mmap_alloc()
 *     bufsz - The size of each buffer to be allocated
 *     cache_sz - Cache size for mempool or other user needs
 *     ops - Pointer to mbuf_ops_t structure for mbuf operator function pointers. This
 *           structure is copied into the pktmbuf_info_t.ops structure and can be NULL.
 *     metadata_bufsz - is the size of the external metadata buffers.
 *     metadata - is a pointer to the start of the metadata, can be NULL for no external metadata.
 * @return
 *   NULL on error or a valid pktmbuf_info_t pointer.
 */
CNDP_API pktmbuf_info_t *pktmbuf_pool_cfg_create(const pktmbuf_pool_cfg_t *cfg);

/**
 * Object or pktmbuf callback routine to initialize the allocated pktmbuf_t structure.
 *
 * @param pi
 *   The pktmbuf_info_t pointer
 * @param buf
 *   The buffer pointer to pktmbuf_t structure to initialize
 * @param sz
 *   The size of the buffer to use in initialing the buffer, if needed.
 * @param idx
 *   The index of the pktmbuf structure
 * @param ud
 *   User data pointer supplied by the caller
 * @return
 *   0 on successfully initialized buffer or -1 on error
 */
typedef int (*pktmbuf_cb_t)(pktmbuf_info_t *pi, pktmbuf_t *buf, uint32_t sz, uint32_t idx,
                            void *ud);

/**
 * Iterate over the set of buffers while calling the supplied callback function.
 *
 * @param pi
 *   Pointer to pktmbuf_info_t structure, returned from pktmbuf_pool_init().
 * @param cb
 *   The callback routine to call to initialize the buffer. The callback uses
 *   the *pktmbuf_cb_t* prototype.
 * @param ud
 *   The user data pointer for the callback function
 * @return
 *   0 on successfully initializing the buffer or -1 on error
 */
CNDP_API int pktmbuf_iterate(pktmbuf_info_t *pi, pktmbuf_cb_t cb, void *ud);

/**
 * A macro to access the hash value in the mbuf
 *
 * @param m
 *   The mbuf pointer.
 */
#define pktmbuf_hash(m) ((m)->hash)

/**
 * A macro that returns the pool pointer.
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_pooldata(m) ((m)->pooldata)

/**
 * A macro that returns the buffer address
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_buf_addr(m) ((m)->buf_addr)

/**
 * A macro that returns the lport number
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_port(m) ((m)->lport)

/**
 * A macro that returns the total buffer length
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_buf_len(m) ((m)->buf_len)

/**
 * A macro that returns the TX offload value
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_tx_offload(m) ((m)->tx_offload)

/**
 * A macro that returns the user pointer value, which is a union with udata64.
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_userptr(m) ((m)->userptr)

/**
 * A macro that returns the udata64 value, which is a union with userptr.
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_udata64(m) ((m)->udata64)

/**
 * A macro that returns the length of the segment.
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_data_len(m) ((m)->data_len)

/**
 * A macro that returns the data offset of the packet.
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_data_off(m) ((m)->data_off)

/**
 * A macro that returns the refcnt non-atomic
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_refcnt(m) ((m)->refcnt)

/**
 * A macro that points to an offset into the data in the mbuf.
 *
 * The returned pointer is cast to type t. Before using this
 * function, the user must ensure that the first segment is large
 * enough to accommodate its data.
 *
 * @param m
 *   The packet mbuf.
 * @param o
 *   The offset into the mbuf data.
 * @param t
 *   The type to cast the result into.
 */
#define pktmbuf_mtod_offset(m, t, o) ((t)((char *)pktmbuf_buf_addr(m) + pktmbuf_data_off(m) + (o)))

/**
 * A macro that points to the start of the data in the mbuf.
 *
 * The returned pointer is cast to type t. Before using this
 * function, the user must ensure that the segment is large
 * enough to accommodate its data.
 *
 * @param m
 *   The packet mbuf.
 * @param t
 *   The type to cast the result into.
 */
#define pktmbuf_mtod(m, t) pktmbuf_mtod_offset(m, t, 0)

/**
 * Return the metadata index value from the pktmbuf header.
 *
 * @param m
 *   The pktmbuf_t pointer.
 */
#define pktmbuf_meta_index(m) ((m)->meta_index)

/**
 * Prefetch the first part of the mbuf
 *
 * The first 64 bytes of the mbuf corresponds to fields that are used early
 * in the receive path. If the cache line of the architecture is higher than
 * 64B, the second part will also be prefetched.
 *
 * @param m
 *   The pointer to the mbuf.
 */
static inline void
pktmbuf_prefetch(pktmbuf_t *m)
{
    cne_prefetch0(m);
}

/**
 * Return the default address of the beginning of the mbuf data.
 *
 * @param mb
 *   The pointer to the mbuf.
 * @return
 *   The pointer of the beginning of the mbuf data.
 */
static inline char *
pktmbuf_data_addr_default(pktmbuf_t *mb)
{
    /* gcc complains about calling this function even
     * when not using it.
     */
    return (char *)pktmbuf_buf_addr(mb) + CNE_PKTMBUF_HEADROOM;
}

#ifdef CNE_LIBCNE_MBUF_DEBUG

/**  check mbuf type in debug mode */
#define __pktmbuf_sanity_check(m, is_h) pktmbuf_sanity_check(m, is_h)

#else /*  CNE_LIBCNE_MBUF_DEBUG */

// clang-format off
/**  check mbuf type in debug mode */
#define __pktmbuf_sanity_check(m, is_h) do { } while (0)
// clang-format on

#endif /*  CNE_LIBCNE_MBUF_DEBUG */

/**
 * Reads the value of an mbuf's refcnt.
 * @param m
 *   Mbuf to read
 * @return
 *   Reference count number.
 */
static inline uint16_t
pktmbuf_refcnt_read(const pktmbuf_t *m)
{
    return atomic_load_explicit(&m->refcnt_atomic, CNE_MEMORY_ORDER(relaxed));
}

/**
 * Sets an mbuf's refcnt to a defined value.
 * @param m
 *   Mbuf to update
 * @param new_value
 *   Value set
 */
static inline void
pktmbuf_refcnt_set(pktmbuf_t *m, uint16_t new_value)
{
    atomic_store_explicit(&m->refcnt_atomic, new_value, CNE_MEMORY_ORDER(relaxed));
}

/* internal */
static inline uint16_t
__pktmbuf_refcnt_update(pktmbuf_t *m, int16_t value)
{
    return atomic_fetch_add_explicit(&m->refcnt_atomic, (uint16_t)value, CNE_MEMORY_ORDER(relaxed));
}

/**
 * Adds given value to an mbuf's refcnt and returns its new value.
 * @param m
 *   Mbuf to update
 * @param value
 *   Value to add/subtract
 * @return
 *   Updated value
 */
static inline uint16_t
pktmbuf_refcnt_update(pktmbuf_t *m, int16_t value)
{
    uint16_t refcnt;

    /*
     * The atomic_add is an expensive operation, so we don't want to
     * call it in the case where we know we are the unique holder of
     * this mbuf (i.e. ref_cnt == 1). Otherwise, an atomic
     * operation has to be used because concurrent accesses on the
     * reference counter can occur.
     */
    refcnt = pktmbuf_refcnt_read(m);
    if (likely(refcnt == 1)) {
        refcnt = refcnt + value;
        pktmbuf_refcnt_set(m, refcnt);
        return (uint16_t)refcnt;
    }

    __pktmbuf_refcnt_update(m, value);

    return pktmbuf_refcnt_read(m);
}

// clang-format off
/** Mbuf prefetch */
#define CNE_MBUF_PREFETCH_TO_FREE(m) do {       \
        if ((m) != NULL)                        \
            cne_prefetch0(m);                   \
    } while (0)
// clang-format on

/**
 * Sanity checks on an mbuf.
 *
 * Check the consistency of the given mbuf. The function will cause a
 * panic if corruption is detected.
 *
 * @param m
 *   The mbuf to be checked.
 * @param is_header
 *   True if the mbuf is a packet header, false if it is a sub-segment
 *   of a packet (in this case, some fields like nb_segs are not checked)
 */
CNDP_API void pktmbuf_sanity_check(const pktmbuf_t *m, int is_header);

/**
 * Sanity checks on a mbuf.
 *
 * Almost like pktmbuf_sanity_check(), but this function gives the reason
 * if corruption is detected rather than panic.
 *
 * @param m
 *   The mbuf to be checked.
 * @param is_header
 *   True if the mbuf is a packet header, false if it is a sub-segment
 *   of a packet (in this case, some fields like nb_segs are not checked)
 * @param reason
 *   A reference to a string pointer where to store the reason why a mbuf is
 *   considered invalid.
 * @return
 *   - 0 if no issue has been found, reason is left untouched.
 *   - -1 if a problem is detected, reason then points to a string describing
 *     the reason why the mbuf is deemed invalid.
 */
CNDP_API int pktmbuf_check(const pktmbuf_t *m, int is_header, const char **reason);

/**
 * Set the pktmbuf_info_t.name field with given string, does not need to be unique.
 *
 * The string passed will be copied into the field. If \p pi is NULL return without setting the name
 * field.
 *
 * @param pi
 *   The pktmbuf_info_t pointer to set the name field.
 * @param str
 *   The string to copy into the name field, can be NULL and the string will cleared.
 * @return
 *   N/A
 */
static inline void
pktmbuf_info_name_set(pktmbuf_info_t *pi, const char *str)
{
    if (pi) {
        if (!str)
            memset(pi->name, 0, sizeof(pi->name));
        else
            strlcpy(pi->name, str, sizeof(pi->name));
    }
}

/**
 * Get the pktmbuf_info_t.name field.
 *
 * @param pi
 *   The pktmbuf_info_t pointer to set the name field.
 * @return
 *   NULL if \p pi is NULL or pointer to pktmbuf_info_t.name field which could be empty.
 */
static inline const char *
pktmbuf_info_name_get(pktmbuf_info_t *pi)
{
    return (!pi) ? NULL : pi->name;
}

/**
 * Reset the data_off field of a packet mbuf to its default value.
 *
 * @param m
 *   The packet mbuf's data_off field has to be reset.
 */
static inline void
pktmbuf_reset_headroom(pktmbuf_t *m)
{
    m->data_off = (uint16_t)CNE_MIN((uint16_t)CNE_PKTMBUF_HEADROOM, (uint16_t)pktmbuf_buf_len(m));
}

/**
 * Reset the fields of a packet mbuf to their default values.
 *
 * @param m
 *   The packet mbuf to be reset.
 */
#define CNE_MBUF_INVALID_PORT UINT16_MAX

/**
 * Reset a mbuf internal fields to valid known states.
 */
static inline void
pktmbuf_reset(pktmbuf_t *m)
{
    pktmbuf_reset_headroom(m);

    pktmbuf_data_len(m) = 0;
    pktmbuf_port(m)     = CNE_MBUF_INVALID_PORT;
    m->packet_type      = 0;
    m->tx_offload       = 0;
    m->ol_flags         = 0;
    m->hash             = 0;
}

/**
 * Allocate a bulk of mbufs, initialize refcnt and reset the fields to default
 * values.
 *
 * @param pi
 *    The mempool from which mbufs are allocated.
 * @param mbufs
 *    Array of pointers to mbufs
 * @param count
 *    Array size
 * @return
 *   number of mbufs allocated or 0 if not able to allocate request number of mbufs
 */
static inline int
pktmbuf_alloc_bulk(pktmbuf_info_t *pi, pktmbuf_t **mbufs, unsigned count)
{
    return (!pi) ? -EINVAL : pi->ops.mbuf_alloc(pi, mbufs, count);
}

/**
 * Allocate a new mbuf from a mempool.
 *
 * This new mbuf, which has a length of 0. The pointer
 * to data is initialized to have some bytes of headroom in the buffer
 * (if buffer size allows).
 *
 * @param pi
 *   The mempool from which the mbuf is allocated.
 * @return
 *   - The pointer to the new mbuf on success.
 *   - NULL if allocation failed.
 */
static inline pktmbuf_t *
pktmbuf_alloc(pktmbuf_info_t *pi)
{
    pktmbuf_t *m = NULL;

    if (pktmbuf_alloc_bulk(pi, &m, 1) <= 0)
        return NULL;

    pktmbuf_reset(m);

    return m;
}

/* internal */
static inline void
__pktmbuf_copy_hdr(pktmbuf_t *mdst, const pktmbuf_t *msrc)
{
    pktmbuf_port(mdst) = pktmbuf_port(msrc);
}

/**
 * Decrease reference counter of an mbuf
 *
 * This function does the same thing as a free.
 * It decreases the reference counter, and if it reaches 0 it is freed.
 *
 * @param m
 *   The mbuf to be unlinked
 * @return
 *   - (m) if it is the last reference. It can be recycled or freed.
 *   - (NULL) if the mbuf still has remaining references on it.
 */
static __cne_always_inline pktmbuf_t *
pktmbuf_refcnt_free(pktmbuf_t *m)
{
    if (m) {
        if (likely(pktmbuf_refcnt_read(m) == 1))
            return m;
        else if (__pktmbuf_refcnt_update(m, -1) == 0) {
            pktmbuf_refcnt_set(m, 1);
            return m;
        }
    }
    return NULL;
}

/**
 * Free a packet mbuf back into its original pool.
 *
 * @param m
 *   The packet mbuf to be freed. If NULL, the function does nothing.
 */
static __cne_always_inline void
pktmbuf_free(pktmbuf_t *m)
{
    m = pktmbuf_refcnt_free(m);
    if (likely(m != NULL)) {
        pktmbuf_info_t *pi = (pktmbuf_info_t *)m->pooldata;

        (void)pi->ops.mbuf_free(pi, &m, 1);
    }
}

static __cne_always_inline void
__pktmbuf_flush_pending(pktmbuf_pending_t *p)
{
    pktmbuf_info_t *pi = (pktmbuf_info_t *)p->pooldata;

    (void)pi->ops.mbuf_free(pi, p->pending, p->nb_pending);
    p->nb_pending = 0;
}

/**
 * @internal helper function for freeing a bulk of packet mbufs
 * via an array holding the packet mbuf from the same mempool
 * pending to be freed.
 *
 * @param m
 *  The packet mbuf to be freed.
 * @param pending
 *  Pointer to the array of packet mbuf pending to be freed.
 * @param nb_pending
 *  Pointer to the number of elements held in the array.
 * @param pending_sz
 *  Number of elements the array can hold.
 *  Note: The compiler should optimize this parameter away when using a
 *  constant value, such as PKTMBUF_PENDING_SZ.
 */
static __cne_always_inline void
__pktmbuf_free_bulk(pktmbuf_pending_t *p, pktmbuf_t *m)
{
    m = pktmbuf_refcnt_free(m);

    if (likely(m != NULL)) {
        if (p->nb_pending == p->pending_sz || (p->nb_pending > 0 && m->pooldata != p->pooldata)) {
            __pktmbuf_flush_pending(p);
            p->pooldata = m->pooldata;
        }

        p->pending[p->nb_pending++] = m;
    }
}

/**
 * Free a bulk of packet mbufs back into their original pools.
 *
 *  @param mbufs
 *    Array of pointers to packet mbufs.
 *    The array may contain NULL pointers.
 *  @param count
 *    Array size.
 */
static inline void
pktmbuf_free_bulk(pktmbuf_t **mbufs, unsigned int count)
{
    pktmbuf_pending_t pend;

    memset(&pend, 0, sizeof(pend));
    pend.pending_sz = PKTMBUF_PENDING_SZ;

    if (count == 0)
        return;

    pend.pooldata = mbufs[0]->pooldata;

    for (unsigned int idx = 0; idx < count; idx++)
        __pktmbuf_free_bulk(&pend, mbufs[idx]);

    if (pend.nb_pending)
        __pktmbuf_flush_pending(&pend);
}

/**
 * Create a full copy of a given packet mbuf.
 *
 * Copies all the data from a given packet mbuf to a newly allocated
 * set of mbufs. The private data are is not copied.
 *
 * @param m
 *   The packet mbuf to be copiedd.
 * @param pi
 *   The pktmbuf_info_t from which the "clone" mbufs are allocated.
 * @param offset
 *   The number of bytes to skip before copying.
 *   If the mbuf does not have that many bytes, it is an error
 *   and NULL is returned.
 * @param length
 *   The upper limit on bytes to copy.  Passing UINT32_MAX
 *   means all data (after offset).
 * @return
 *   - The pointer to the new "clone" mbuf on success.
 *   - NULL if allocation fails.
 */
CNDP_API pktmbuf_t *pktmbuf_copy(const pktmbuf_t *m, pktmbuf_info_t *pi, uint32_t offset,
                                 uint32_t length);

/**
 * Get the headroom in a packet mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @return
 *   The length of the headroom.
 */
static inline uint16_t
pktmbuf_headroom(const pktmbuf_t *m)
{
    __pktmbuf_sanity_check(m, 0);
    return pktmbuf_data_off(m);
}

/**
 * Get the tailroom of a packet mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @return
 *   The length of the tailroom.
 */
static inline uint16_t
pktmbuf_tailroom(const pktmbuf_t *m)
{
    __pktmbuf_sanity_check(m, 0);
    return (uint16_t)(pktmbuf_buf_len(m) - pktmbuf_data_off(m) - pktmbuf_data_len(m));
}

/**
 * Return pointer to the end or last of the packet data in the mbuf.
 *
 * Note: The pointer returned is just past the last byte of the data.
 *
 * @param m
 *   Pointer to mbuf to get the end of the packet
 * @return
 *   Pointer to the end of the packet data.
 */
static inline char *
pktmbuf_mtod_last(const pktmbuf_t *m)
{
    __pktmbuf_sanity_check(m, 0);
    return pktmbuf_mtod_offset(m, char *, pktmbuf_data_len(m));
}

/**
 * Return pointer to the end of the mbuf buffer
 *
 * Note: The pointer returned is just past the last byte of the buffer.
 *
 * @param m
 *   Pointer to mbuf to use in finding the end of the buffer
 * @return
 *   Pointer to the end of the mbuf buffer.
 */
static inline char *
pktmbuf_mtod_end(const pktmbuf_t *m)
{
    __pktmbuf_sanity_check(m, 0);
    return (char *)CNE_PTR_ADD((char *)(uintptr_t)m, pktmbuf_buf_len(m) + sizeof(pktmbuf_t));
}

/**
 * Prepend len bytes to an mbuf data area.
 *
 * Returns a pointer to the new data start address. If there is not
 * enough headroom in the mbuf, the function will return NULL,
 * without modifying the mbuf.
 *
 * @param m
 *   The pkt mbuf.
 * @param len
 *   The amount of data to prepend (in bytes).
 * @return
 *   A pointer to the start of the newly prepended data, or
 *   NULL if there is not enough headroom space in the first segment
 */
static inline char *
pktmbuf_prepend(pktmbuf_t *m, uint16_t len)
{
    __pktmbuf_sanity_check(m, 1);

    if (unlikely(len > pktmbuf_headroom(m)))
        return NULL;

    /* NB: elaborating the subtraction like this instead of using
     *     -= allows us to ensure the result type is uint16_t
     *     avoiding compiler warnings on gcc 8.1 at least */
    pktmbuf_data_off(m) = (uint16_t)(pktmbuf_data_off(m) - len);
    pktmbuf_data_len(m) = (uint16_t)(pktmbuf_data_len(m) + len);

    return pktmbuf_mtod(m, char *);
}

/**
 * Remove len bytes of an mbuf, by increasing mbuf.data_off value
 *
 * Returns a pointer to the new data start address. If the request length
 * to move the data_off exceeds the mbuf len then return NULL or return
 * the new start address.
 *
 * @param m
 *   The pkt mbuf.
 * @param len
 *   The amount of data to remove/added in bytes from the start of the mbuf.
 * @return
 *   A pointer to the new offset into the mbuf where the data begins.
 */
static inline char *
pktmbuf_adj_offset(pktmbuf_t *m, int16_t len)
{
    uint16_t alen = abs(len);

    __pktmbuf_sanity_check(m, 1);

    if (likely(len >= 0)) {
        if (unlikely(alen > pktmbuf_data_len(m)))
            return NULL;
        if (unlikely((alen + pktmbuf_data_off(m)) > pktmbuf_buf_len(m)))
            return NULL;

        /* NB: elaborating the subtraction like this instead of using
         *     -= allows us to ensure the result type is uint16_t
         *     avoiding compiler warnings on gcc 8.1 at least */
        pktmbuf_data_off(m) = (uint16_t)(pktmbuf_data_off(m) + alen);
        pktmbuf_data_len(m) = (uint16_t)(pktmbuf_data_len(m) - alen);
    } else {
        if (unlikely(alen > pktmbuf_data_off(m)))
            return NULL;

        /* NB: elaborating the subtraction like this instead of using
         *     -= allows us to ensure the result type is uint16_t
         *     avoiding compiler warnings on gcc 8.1 at least */
        pktmbuf_data_off(m) = (uint16_t)(pktmbuf_data_off(m) - alen);
        pktmbuf_data_len(m) = (uint16_t)(pktmbuf_data_len(m) + alen);
    }
    return pktmbuf_mtod(m, char *);
}

#define pktmbuf_adjust(m, t, len) (t) pktmbuf_adj_offset(m, len)

/**
 * Append len bytes to an mbuf.
 *
 * Append len bytes to an mbuf and return a pointer to the start address
 * of the added data.
 *
 * @param m
 *   The packet mbuf.
 * @param len
 *   The amount of data to append (in bytes).
 * @return
 *   A pointer to the start of the newly appended data, or
 *   NULL if there is not enough tailroom space in the last segment
 */
static inline char *
pktmbuf_append(pktmbuf_t *m, uint16_t len)
{
    void *tail;

    __pktmbuf_sanity_check(m, 1);

    if (unlikely(len > pktmbuf_tailroom(m)))
        return NULL;

    tail                = (char *)pktmbuf_buf_addr(m) + pktmbuf_data_off(m) + pktmbuf_data_len(m);
    pktmbuf_data_len(m) = (uint16_t)(pktmbuf_data_len(m) + len);
    return (char *)tail;
}

/**
 * Remove len bytes of data at the end of the mbuf.
 *
 * If the length is greater than the length of the segment, the
 * function will fail and return -1 without modifying the mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @param len
 *   The amount of data to remove (in bytes).
 * @return
 *   - 0: On success.
 *   - -1: On error.
 */
static inline int
pktmbuf_trim(pktmbuf_t *m, uint16_t len)
{
    __pktmbuf_sanity_check(m, 1);

    if (unlikely(len > pktmbuf_data_len(m)))
        return -1;

    pktmbuf_data_len(m) = (uint16_t)(pktmbuf_data_len(m) - len);

    return 0;
}

/**
 * @internal used by pktmbuf_read().
 */
const void *__pktmbuf_read(const pktmbuf_t *m, uint32_t off, uint32_t len, void *buf);

/**
 * Read len data bytes in a mbuf at specified offset.
 *
 * Copy the data in the buffer provided by the user and return its pointer.
 *
 * @param m
 *   The pointer to the mbuf.
 * @param off
 *   The offset of the data in the mbuf.
 * @param len
 *   The amount of bytes to read.
 * @param buf
 *   The buffer where data is copied in mbuf data. Its length should be at least
 *   equal to the len parameter.
 * @return
 *   The pointer to the data or in the user buffer. If mbuf is too small, NULL is returned.
 */
static inline const void *
pktmbuf_read(const pktmbuf_t *m, uint32_t off, uint32_t len, void *buf)
{
    if (likely(off + len <= pktmbuf_data_len(m)))
        return pktmbuf_mtod_offset(m, char *, off);
    else
        return __pktmbuf_read(m, off, len, buf);
}

/**
 * @internal used by pktmbuf_write() to copy data into an mbuf.
 */
const void *__pktmbuf_write(const void *buf, uint32_t len, pktmbuf_t *m, uint32_t off);

/**
 * Write len data bytes into the mbuf at specified offset.
 *
 * Copy the data in the buffer provided by the user into the mbuf.
 *
 * @param buf
 *   The buffer where data is copied to in mbuf buffer. Its length should be at least
 *   equal to the len parameter.
 * @param len
 *   The amount of bytes to write from buffer to mbuf.
 * @param m
 *   The pointer to the mbuf.
 * @param off
 *   The offset of the data in the mbuf.
 * @return
 *   The pointer to the data or in the user buffer. If mbuf is too small, NULL is returned.
 */
static inline const void *
pktmbuf_write(const void *buf, uint32_t len, pktmbuf_t *m, uint32_t off)
{
    if (likely((len + off) > pktmbuf_tailroom(m)))
        return NULL;
    else
        return __pktmbuf_write(buf, len, m, off);
}

/**
 * Amount of total data space available for packet data.
 *
 * This value is the max space available for packet data in a pktmbuf_t, which means
 * the value for a 2K buffer would be (2K - sizeof(pktmbuf_t)).
 *
 * @param mp
 *   The mempool pointer to get the element size.
 * @return
 *   The total amount of space available for packet data in a pktmbuf_t.
 */
static inline uint16_t
pktmbuf_data_room_size(mempool_t *mp)
{
    return mempool_objsz(mp) - sizeof(pktmbuf_t);
}

/**
 * Clone a pktmbuf from a given pool.
 *
 * @param md
 *   The mbuf to clone
 * @param pi
 *   The pktmbuf_info pointer to allocate the new mbuf from.
 * @return
 *   NULL on error or the new cloned mbuf pointer.
 */
CNDP_API pktmbuf_t *pktmbuf_clone(pktmbuf_t *md, pktmbuf_info_t *pi);

/**
 * Dump an mbuf structure to a file.
 *
 * Dump all fields for the given packet mbuf and all its associated
 * segments (in the case of a chained buffer).
 *
 * @param msg
 *   Title message, can be NULL
 * @param m
 *   The packet mbuf.
 * @param dump_len
 *   If dump_len != 0, also dump the "dump_len" first data bytes of
 *   the packet.
 */
CNDP_API void pktmbuf_dump(const char *msg, const pktmbuf_t *m, unsigned dump_len);

/**
 * Get the name of a RX offload flag
 *
 * @param mask
 *   The mask describing the flag.
 * @return
 *   The name of this flag, or NULL if it's not a valid RX flag.
 */
const char *cne_get_rx_ol_flag_name(uint64_t mask);

/**
 * Dump the list of RX offload flags in a buffer
 *
 * @param mask
 *   The mask describing the RX flags.
 * @param buf
 *   The output buffer.
 * @param buflen
 *   The length of the buffer.
 * @return
 *   0 on success, (-1) on error.
 */
int cne_get_rx_ol_flag_list(uint64_t mask, char *buf, size_t buflen);

/**
 * Get the name of a TX offload flag
 *
 * @param mask
 *   The mask describing the flag. Usually only one bit must be set.
 *   Several bits can be given if they belong to the same mask.
 *   Ex: PKT_TX_L4_MASK.
 * @return
 *   The name of this flag, or NULL if it's not a valid TX flag.
 */
const char *cne_get_tx_ol_flag_name(uint64_t mask);

/**
 * Dump the list of TX offload flags in a buffer
 *
 * @param mask
 *   The mask describing the TX flags.
 * @param buf
 *   The output buffer.
 * @param buflen
 *   The length of the buffer.
 * @return
 *   0 on success, (-1) on error.
 */
int cne_get_tx_ol_flag_list(uint64_t mask, char *buf, size_t buflen);

/**
 * Return the metadata buffer address
 *
 * @param m
 *   The pktmbuf_t structure pointer
 * @return
 *   NULL on error or pointer to metadata buffer
 */
static inline void *
pktmbuf_metadata(const pktmbuf_t *m)
{
    pktmbuf_info_t *p;

    if (!m)
        return NULL;

    if (((p = (pktmbuf_info_t *)m->pooldata) != NULL) && p->metadata)
        return CNE_PTR_ADD(p->metadata, (m->meta_index * p->metadata_bufsz));
    else
        return CNE_PTR_ADD(m, sizeof(pktmbuf_t)); /* default to metadata in pktmbuf headroom */
}

/**
 * Return the size of the metadata buffer if external or headroom size if internal buffer.
 *
 * @param m
 *   The pktmbuf_t structure pointer
 * @return
 *   -1 if pktmbuf pointer is NULL or size of metadata buffer or headroom size if internal.
 */
static inline int32_t
pktmbuf_metadata_bufsz(const pktmbuf_t *m)
{
    pktmbuf_info_t *p;

    if (!m)
        return -1;

    if (((p = (pktmbuf_info_t *)m->pooldata) != NULL) && p->metadata)
        return (int32_t)p->metadata_bufsz;
    else
        return (int32_t)pktmbuf_headroom(m);
}

/**
 * Construct a pktmbuf_pool_cfg_t structure with the given parameters.
 *
 * @param c
 *   Pointer to the pktmbuf_pool_cfg_t structure
 * @param addr
 *   Address of the pktmbuf buffers, must not be NULL
 * @param bufcnt
 *   Number of buffers in the pktmbuf pool, can be zero to use default
 * @param bufsz
 *   Size of each buffer in the pktmbuf pool, can be zero to use default
 * @param cache_sz
 *   Cache size of the mempool to use in allocate/free buffers, can be zero
 * @param metadata
 *   The pointer of the metadata buffer pool, can be NULL.
 * @param metadata_bufsz
 *   The size of each metadata buffer in the pool, if metadata is valid can not be zero
 *   and needs to be a multiple of a cacheline.
 * @param ops
 *   The pktmbuf ops structure pointer, can be NULL.
 * @return
 *   0 on success or -1 on error.
 */
CNDP_API int pktmbuf_pool_cfg(pktmbuf_pool_cfg_t *c, void *addr, uint32_t bufcnt, uint32_t bufsz,
                              uint32_t cache_sz, void *metadata, uint32_t metadata_bufsz,
                              mbuf_ops_t *ops);

/**
 * Dump out the list of pktmbuf_info_t structures
 *
 * @return
 *   N/A
 */
CNDP_API void pktmbuf_info_dump(void);

#ifdef __cplusplus
}
#endif

#endif /* _PKTMBUF_H_ */
