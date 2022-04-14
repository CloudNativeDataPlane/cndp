/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 * Copyright (c) 2018 Arm Limited
 */

#include <string.h>                       // for NULL, memset, memcpy
#include <stdint.h>                       // for uint32_t, int32_t, uint16_t, uint...
#include <errno.h>                        // for ENOENT, ENOSPC, EINVAL
#include <stdio.h>                        // for snprintf
#include <cne_common.h>                   // for cne_align32pow2, CNE_NAME_LEN
#include <cne_log.h>                      // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_NU...
#include <cne_prefetch.h>                 // for cne_prefetch0
#include <cne_branch_prediction.h>        // for likely, unlikely
#include <cne_ring.h>                     // for cne_ring_t
#include <cne_rwlock.h>                   // for cne_rwlock_write_unlock, cne_rwlo...
#include <bsd/string.h>                   // for strlcpy
#include <emmintrin.h>                    // for _mm_cmpeq_epi16, _mm_load_si128
#include <stdlib.h>                       // for free, calloc

#include "cne_hash.h"        // for cne_hash_parameters, CNE_HASH_LOO...
#include "cne_cuckoo_hash.h"
#include "cne_hash_crc.h"        // for cne_hash_crc
#include "cne_jhash.h"           // for cne_jhash
#include "cne_ring_api.h"        // for cne_ring_enqueue_elem, cne_ring_free

/* Mask of all flags supported by this version */
#define CNE_HASH_EXTRA_FLAGS_MASK                                                     \
    (CNE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | CNE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD | \
     CNE_HASH_EXTRA_FLAGS_RW_CONCURRENCY | CNE_HASH_EXTRA_FLAGS_EXT_TABLE |           \
     CNE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL | CNE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF)

#define FOR_EACH_BUCKET(CURRENT_BKT, START_BUCKET) \
    for (CURRENT_BKT = START_BUCKET; CURRENT_BKT != NULL; CURRENT_BKT = CURRENT_BKT->next)

static cne_rwlock_t __hash_lock;

static inline struct cne_hash_bucket *
cne_hash_get_last_bkt(struct cne_hash_bucket *lst_bkt)
{
    while (lst_bkt->next != NULL)
        lst_bkt = lst_bkt->next;
    return lst_bkt;
}

void
cne_hash_set_cmp_func(struct cne_hash *h, cne_hash_cmp_eq_t func)
{
    h->cmp_jump_table_idx     = KEY_CUSTOM;
    h->cne_hash_custom_cmp_eq = func;
}

static inline int
cne_hash_cmp_eq(const void *key1, const void *key2, const struct cne_hash *h)
{
    if (h->cmp_jump_table_idx == KEY_CUSTOM)
        return h->cne_hash_custom_cmp_eq(key1, key2, h->key_len);
    else
        return cmp_jump_table[h->cmp_jump_table_idx](key1, key2, h->key_len);
}

/*
 * We use higher 16 bits of hash as the signature value stored in table.
 * We use the lower bits for the primary bucket
 * location. Then we XOR primary bucket location and the signature
 * to get the secondary bucket location. This is same as
 * proposed in Bin Fan, et al's paper
 * "MemC3: Compact and Concurrent MemCache with Dumber Caching and
 * Smarter Hashing". The benefit to use
 * XOR is that one could derive the alternative bucket location
 * by only using the current bucket location and the signature.
 */
static inline uint16_t
get_short_sig(const hash_sig_t hash)
{
    return hash >> 16;
}

static inline uint32_t
get_prim_bucket_index(const struct cne_hash *h, const hash_sig_t hash)
{
    return hash & h->bucket_bitmask;
}

static inline uint32_t
get_alt_bucket_index(const struct cne_hash *h, uint32_t cur_bkt_idx, uint16_t sig)
{
    return (cur_bkt_idx ^ sig) & h->bucket_bitmask;
}

struct cne_hash *
cne_hash_create(const struct cne_hash_parameters *params)
{
    struct cne_hash *h = NULL;
    cne_ring_t *r      = NULL;
    cne_ring_t *r_ext  = NULL;
    char hash_name[CNE_HASH_NAMESIZE];
    void *k           = NULL;
    void *buckets     = NULL;
    void *buckets_ext = NULL;
    char ring_name[CNE_NAME_LEN];
    char ext_ring_name[CNE_NAME_LEN];
    unsigned num_key_slots;
    unsigned int hw_trans_mem_support        = 0;
    unsigned int ext_table_support           = 0;
    unsigned int readwrite_concur_support    = 0;
    unsigned int writer_takes_lock           = 0;
    unsigned int no_free_on_del              = 0;
    uint32_t *ext_bkt_to_free                = NULL;
    uint32_t *tbl_chng_cnt                   = NULL;
    unsigned int readwrite_concur_lf_support = 0;
    unsigned int ring_create_flags           = 0;
    uint32_t i;

    cne_hash_function default_hash_func = (cne_hash_function)cne_jhash;

    if (params == NULL)
        CNE_NULL_RET("cne_hash_create has no parameters\n");

    /* Check for valid parameters */
    if ((params->entries > CNE_HASH_ENTRIES_MAX) || (params->entries < CNE_HASH_BUCKET_ENTRIES) ||
        (params->key_len == 0))
        CNE_NULL_RET("cne_hash_create has invalid parameters\n");

    /* Validate correct usage of extra options */
    if ((params->extra_flag & CNE_HASH_EXTRA_FLAGS_RW_CONCURRENCY) &&
        (params->extra_flag & CNE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF))
        CNE_NULL_RET("cne_hash_create: choose rw concurrency or "
                     "rw concurrency lock free\n");

    /* Check extra flags field to check extra options. */
    if (params->extra_flag & CNE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT)
        hw_trans_mem_support = 1;

    if (params->extra_flag & CNE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD)
        writer_takes_lock = 1;

    if (params->extra_flag & CNE_HASH_EXTRA_FLAGS_RW_CONCURRENCY) {
        readwrite_concur_support = 1;
        writer_takes_lock        = 1;
    }

    if (params->extra_flag & CNE_HASH_EXTRA_FLAGS_EXT_TABLE)
        ext_table_support = 1;

    if (params->extra_flag & CNE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL)
        no_free_on_del = 1;

    if (params->extra_flag & CNE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF) {
        readwrite_concur_lf_support = 1;
        /* Enable not freeing internal memory/index on delete.
         * If internal RCU is enabled, freeing of internal memory/index
         * is done on delete
         */
        no_free_on_del = 1;
    }

    /* Store all keys and leave the first entry as a dummy entry for lookup_bulk */
    num_key_slots     = params->entries + 1;
    ring_create_flags = RING_F_SP_ENQ | RING_F_SC_DEQ;

    snprintf(ring_name, sizeof(ring_name), "HT_%s", params->name);
    /* Create ring (Dummy slot index is not enqueued) */
    r = cne_ring_create(ring_name, sizeof(uint32_t), cne_align32pow2(num_key_slots),
                        ring_create_flags);
    if (r == NULL)
        CNE_ERR_GOTO(err, "memory allocation failed\n");

    const uint32_t num_buckets = cne_align32pow2(params->entries) / CNE_HASH_BUCKET_ENTRIES;

    /* Create ring for extendable buckets. */
    if (ext_table_support) {
        snprintf(ext_ring_name, sizeof(ext_ring_name), "HT_EXT_%s", params->name);
        r_ext = cne_ring_create(ext_ring_name, sizeof(uint32_t), cne_align32pow2(num_buckets + 1),
                                RING_F_SP_ENQ | RING_F_SC_DEQ);

        if (r_ext == NULL)
            CNE_ERR_GOTO(err, "ext buckets memory allocation failed\n");
    }

    snprintf(hash_name, sizeof(hash_name), "HT_%s", params->name);

    cne_rwlock_write_lock(&__hash_lock);

    h = (struct cne_hash *)calloc(1, sizeof(struct cne_hash));

    if (h == NULL)
        CNE_ERR_GOTO(err_unlock, "memory allocation failed\n");

    buckets = calloc(num_buckets, sizeof(struct cne_hash_bucket));

    if (buckets == NULL)
        CNE_ERR_GOTO(err_unlock, "buckets memory allocation failed\n");

    /* Allocate same number of extendable buckets */
    if (ext_table_support) {
        buckets_ext = calloc(num_buckets, sizeof(struct cne_hash_bucket));
        if (buckets_ext == NULL)
            CNE_ERR_GOTO(err_unlock, "ext buckets memory allocation failed\n");
        /* Populate ext bkt ring. We reserve 0 similar to the
         * key-data slot, just in case in future we want to
         * use bucket index for the linked list and 0 means NULL
         * for next bucket
         */
        for (i = 1; i <= num_buckets; i++)
            cne_ring_enqueue_elem(r_ext, &i, sizeof(uint32_t));

        if (readwrite_concur_lf_support) {
            ext_bkt_to_free = calloc(num_key_slots, sizeof(uint32_t));
            if (ext_bkt_to_free == NULL)
                CNE_ERR_GOTO(err_unlock, "ext bkt to free memory allocation failed\n");
        }
    }

    const uint32_t key_entry_size =
        CNE_ALIGN(sizeof(struct cne_hash_key) + params->key_len, KEY_ALIGNMENT);
    const uint64_t key_tbl_size = (uint64_t)key_entry_size * num_key_slots;

    k = calloc(1, key_tbl_size);

    if (k == NULL)
        CNE_ERR_GOTO(err_unlock, "memory allocation failed\n");

    tbl_chng_cnt = calloc(1, sizeof(uint32_t));

    if (tbl_chng_cnt == NULL)
        CNE_ERR_GOTO(err_unlock, "memory allocation failed\n");

    /*
     * Select appropriate compare function,
     * which may use x86 intrinsics, otherwise use memcmp
     */
    /* Select function to compare keys */
    switch (params->key_len) {
    case 16:
        h->cmp_jump_table_idx = KEY_16_BYTES;
        break;
    case 32:
        h->cmp_jump_table_idx = KEY_32_BYTES;
        break;
    case 48:
        h->cmp_jump_table_idx = KEY_48_BYTES;
        break;
    case 64:
        h->cmp_jump_table_idx = KEY_64_BYTES;
        break;
    case 80:
        h->cmp_jump_table_idx = KEY_80_BYTES;
        break;
    case 96:
        h->cmp_jump_table_idx = KEY_96_BYTES;
        break;
    case 112:
        h->cmp_jump_table_idx = KEY_112_BYTES;
        break;
    case 128:
        h->cmp_jump_table_idx = KEY_128_BYTES;
        break;
    default:
        /* If key is not multiple of 16, use generic memcmp */
        h->cmp_jump_table_idx = KEY_OTHER_BYTES;
    }

    /* Default hash function */
    default_hash_func = (cne_hash_function)cne_hash_crc;

    /* Setup hash context */
    strlcpy(h->name, (params->name) ? params->name : "", sizeof(h->name));
    h->entries            = params->entries;
    h->key_len            = params->key_len;
    h->key_entry_size     = key_entry_size;
    h->hash_func_init_val = params->hash_func_init_val;

    h->num_buckets          = num_buckets;
    h->bucket_bitmask       = h->num_buckets - 1;
    h->buckets              = buckets;
    h->buckets_ext          = buckets_ext;
    h->free_ext_bkts        = r_ext;
    h->hash_func            = (params->hash_func == NULL) ? default_hash_func : params->hash_func;
    h->key_store            = k;
    h->free_slots           = r;
    h->ext_bkt_to_free      = ext_bkt_to_free;
    h->tbl_chng_cnt         = tbl_chng_cnt;
    *h->tbl_chng_cnt        = 0;
    h->hw_trans_mem_support = hw_trans_mem_support;
    h->readwrite_concur_support    = readwrite_concur_support;
    h->ext_table_support           = ext_table_support;
    h->writer_takes_lock           = writer_takes_lock;
    h->no_free_on_del              = no_free_on_del;
    h->readwrite_concur_lf_support = readwrite_concur_lf_support;

    if (__builtin_cpu_supports("sse2"))
        h->sig_cmp_fn = CNE_HASH_COMPARE_SSE;
    else
        h->sig_cmp_fn = CNE_HASH_COMPARE_SCALAR;

    /* Writer threads need to take the lock when:
     * 1) CNE_HASH_EXTRA_FLAGS_RW_CONCURRENCY is enabled OR
     * 2) CNE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD is enabled
     */
    if (h->writer_takes_lock) {
        h->readwrite_lock = calloc(1, sizeof(cne_rwlock_t));
        if (h->readwrite_lock == NULL)
            goto err_unlock;

        cne_rwlock_init(h->readwrite_lock);
    }

    /* Populate free slots ring. Entry zero is reserved for key misses. */
    for (i = 1; i < num_key_slots; i++)
        cne_ring_enqueue_elem(r, &i, sizeof(uint32_t));

    cne_rwlock_write_unlock(&__hash_lock);

    return h;
err_unlock:
    cne_rwlock_write_unlock(&__hash_lock);
err:
    cne_ring_free(r);
    cne_ring_free(r_ext);
    free(h);
    free(buckets);
    free(buckets_ext);
    free(k);
    free(tbl_chng_cnt);
    free(ext_bkt_to_free);
    return NULL;
}

void
cne_hash_free(struct cne_hash *h)
{

    if (h == NULL)
        return;

    if (h->writer_takes_lock)
        free(h->readwrite_lock);
    cne_ring_free(h->free_slots);
    cne_ring_free(h->free_ext_bkts);
    free(h->key_store);
    free(h->buckets);
    free(h->buckets_ext);
    free(h->tbl_chng_cnt);
    free(h->ext_bkt_to_free);
    free(h);
}

hash_sig_t
cne_hash_hash(const struct cne_hash *h, const void *key)
{
    /* calc hash result by key */
    return h->hash_func(key, h->key_len, h->hash_func_init_val);
}

int32_t
cne_hash_max_key_id(const struct cne_hash *h)
{
    RETURN_IF_TRUE((h == NULL), -EINVAL);
    return h->entries;
}

int32_t
cne_hash_count(const struct cne_hash *h)
{
    uint32_t tot_ring_cnt;
    uint32_t ret;

    if (h == NULL)
        return -EINVAL;

    tot_ring_cnt = h->entries;
    ret          = tot_ring_cnt - cne_ring_count(h->free_slots);
    return ret;
}

/* Read write locks implemented using cne_rwlock */
static inline void
__hash_rw_writer_lock(const struct cne_hash *h)
{
    if (h->writer_takes_lock && h->hw_trans_mem_support)
        cne_rwlock_write_lock_tm(h->readwrite_lock);
    else if (h->writer_takes_lock)
        cne_rwlock_write_lock(h->readwrite_lock);
}

static inline void
__hash_rw_reader_lock(const struct cne_hash *h)
{
    if (h->readwrite_concur_support && h->hw_trans_mem_support)
        cne_rwlock_read_lock_tm(h->readwrite_lock);
    else if (h->readwrite_concur_support)
        cne_rwlock_read_lock(h->readwrite_lock);
}

static inline void
__hash_rw_writer_unlock(const struct cne_hash *h)
{
    if (h->writer_takes_lock && h->hw_trans_mem_support)
        cne_rwlock_write_unlock_tm(h->readwrite_lock);
    else if (h->writer_takes_lock)
        cne_rwlock_write_unlock(h->readwrite_lock);
}

static inline void
__hash_rw_reader_unlock(const struct cne_hash *h)
{
    if (h->readwrite_concur_support && h->hw_trans_mem_support)
        cne_rwlock_read_unlock_tm(h->readwrite_lock);
    else if (h->readwrite_concur_support)
        cne_rwlock_read_unlock(h->readwrite_lock);
}

void
cne_hash_reset(struct cne_hash *h)
{
    uint32_t tot_ring_cnt, i;

    if (h == NULL)
        return;

    __hash_rw_writer_lock(h);

    memset(h->buckets, 0, h->num_buckets * sizeof(struct cne_hash_bucket));
    memset(h->key_store, 0, h->key_entry_size * (h->entries + 1));
    *h->tbl_chng_cnt = 0;

    /* reset the free ring */
    cne_ring_reset(h->free_slots);

    /* flush free extendable bucket ring and memory */
    if (h->ext_table_support) {
        memset(h->buckets_ext, 0, h->num_buckets * sizeof(struct cne_hash_bucket));
        cne_ring_reset(h->free_ext_bkts);
    }

    /* Repopulate the free slots ring. Entry zero is reserved for key misses */
    tot_ring_cnt = h->entries;

    for (i = 1; i < tot_ring_cnt + 1; i++)
        cne_ring_enqueue_elem(h->free_slots, &i, sizeof(uint32_t));

    /* Repopulate the free ext bkt ring. */
    if (h->ext_table_support) {
        for (i = 1; i <= h->num_buckets; i++)
            cne_ring_enqueue_elem(h->free_ext_bkts, &i, sizeof(uint32_t));
    }

    __hash_rw_writer_unlock(h);
}

/*
 * Function called to enqueue back an index in the cache/ring,
 * as slot has not being used and it can be used in the
 * next addition attempt.
 */
static inline void
enqueue_slot_back(const struct cne_hash *h, uint32_t slot_id)
{
    cne_ring_enqueue_elem(h->free_slots, &slot_id, sizeof(uint32_t));
}

/* Search a key from bucket and update its data.
 * Writer holds the lock before calling this.
 */
static inline int32_t
search_and_update(const struct cne_hash *h, void *data, const void *key,
                  struct cne_hash_bucket *bkt, uint16_t sig)
{
    int i;
    struct cne_hash_key *k, *keys = h->key_store;

    for (i = 0; i < CNE_HASH_BUCKET_ENTRIES; i++) {
        if (bkt->sig_current[i] == sig) {
            k = (struct cne_hash_key *)((char *)keys + bkt->key_idx[i] * h->key_entry_size);
            if (cne_hash_cmp_eq(key, k->key, h) == 0) {
                /* The store to application data at *data
                 * should not leak after the store to pdata
                 * in the key store. i.e. pdata is the guard
                 * variable. Release the application data
                 * to the readers.
                 */
                __atomic_store_n(&k->pdata, data, __ATOMIC_RELEASE);
                /*
                 * Return index where key is stored,
                 * subtracting the first dummy index
                 */
                return bkt->key_idx[i] - 1;
            }
        }
    }
    return -1;
}

/* Only tries to insert at one bucket (@prim_bkt) without trying to push
 * buckets around.
 * return 1 if matching existing key, return 0 if succeeds, return -1 for no
 * empty entry.
 */
static inline int32_t
cne_hash_cuckoo_insert_mw(const struct cne_hash *h, struct cne_hash_bucket *prim_bkt,
                          struct cne_hash_bucket *sec_bkt, const struct cne_hash_key *key,
                          void *data, uint16_t sig, uint32_t new_idx, int32_t *ret_val)
{
    unsigned int i;
    struct cne_hash_bucket *cur_bkt;
    int32_t ret;

    __hash_rw_writer_lock(h);
    /* Check if key was inserted after last check but before this
     * protected region in case of inserting duplicated keys.
     */
    ret = search_and_update(h, data, key, prim_bkt, sig);
    if (ret != -1) {
        __hash_rw_writer_unlock(h);
        *ret_val = ret;
        return 1;
    }

    FOR_EACH_BUCKET (cur_bkt, sec_bkt) {
        ret = search_and_update(h, data, key, cur_bkt, sig);
        if (ret != -1) {
            __hash_rw_writer_unlock(h);
            *ret_val = ret;
            return 1;
        }
    }

    /* Insert new entry if there is room in the primary
     * bucket.
     */
    for (i = 0; i < CNE_HASH_BUCKET_ENTRIES; i++) {
        /* Check if slot is available */
        if (likely(prim_bkt->key_idx[i] == EMPTY_SLOT)) {
            prim_bkt->sig_current[i] = sig;
            /* Store to signature and key should not
             * leak after the store to key_idx. i.e.
             * key_idx is the guard variable for signature
             * and key.
             */
            __atomic_store_n(&prim_bkt->key_idx[i], new_idx, __ATOMIC_RELEASE);
            break;
        }
    }
    __hash_rw_writer_unlock(h);

    if (i != CNE_HASH_BUCKET_ENTRIES)
        return 0;

    /* no empty entry */
    return -1;
}

/* Shift buckets along provided cuckoo_path (@leaf and @leaf_slot) and fill
 * the path head with new entry (sig, alt_hash, new_idx)
 * return 1 if matched key found, return -1 if cuckoo path invalided and fail,
 * return 0 if succeeds.
 */
static inline int
cne_hash_cuckoo_move_insert_mw(const struct cne_hash *h, struct cne_hash_bucket *bkt,
                               struct cne_hash_bucket *alt_bkt, const struct cne_hash_key *key,
                               void *data, struct queue_node *leaf, uint32_t leaf_slot,
                               uint16_t sig, uint32_t new_idx, int32_t *ret_val)
{
    uint32_t prev_alt_bkt_idx;
    struct cne_hash_bucket *cur_bkt;
    struct queue_node *prev_node, *curr_node    = leaf;
    struct cne_hash_bucket *prev_bkt, *curr_bkt = leaf->bkt;
    uint32_t prev_slot, curr_slot               = leaf_slot;
    int32_t ret;

    __hash_rw_writer_lock(h);

    /* In case empty slot was gone before entering protected region */
    if (curr_bkt->key_idx[curr_slot] != EMPTY_SLOT) {
        __hash_rw_writer_unlock(h);
        return -1;
    }

    /* Check if key was inserted after last check but before this
     * protected region.
     */
    ret = search_and_update(h, data, key, bkt, sig);
    if (ret != -1) {
        __hash_rw_writer_unlock(h);
        *ret_val = ret;
        return 1;
    }

    FOR_EACH_BUCKET (cur_bkt, alt_bkt) {
        ret = search_and_update(h, data, key, cur_bkt, sig);
        if (ret != -1) {
            __hash_rw_writer_unlock(h);
            *ret_val = ret;
            return 1;
        }
    }

    while (likely(curr_node->prev != NULL)) {
        prev_node = curr_node->prev;
        prev_bkt  = prev_node->bkt;
        prev_slot = curr_node->prev_slot;

        prev_alt_bkt_idx =
            get_alt_bucket_index(h, prev_node->cur_bkt_idx, prev_bkt->sig_current[prev_slot]);

        if (unlikely(&h->buckets[prev_alt_bkt_idx] != curr_bkt)) {
            /* revert it to empty, otherwise duplicated keys */
            __atomic_store_n(&curr_bkt->key_idx[curr_slot], EMPTY_SLOT, __ATOMIC_RELEASE);
            return -1;
        }

        if (h->readwrite_concur_lf_support) {
            /* Inform the previous move. The current move need
             * not be informed now as the current bucket entry
             * is present in both primary and secondary.
             * Since there is one writer, load acquires on
             * tbl_chng_cnt are not required.
             */
            __atomic_store_n(h->tbl_chng_cnt, *h->tbl_chng_cnt + 1, __ATOMIC_RELEASE);
            /* The store to sig_current should not
             * move above the store to tbl_chng_cnt.
             */
            __atomic_thread_fence(__ATOMIC_RELEASE);
        }

        /* Need to swap current/alt sig to allow later
         * Cuckoo insert to move elements back to its
         * primary bucket if available
         */
        curr_bkt->sig_current[curr_slot] = prev_bkt->sig_current[prev_slot];
        /* Release the updated bucket entry */
        __atomic_store_n(&curr_bkt->key_idx[curr_slot], prev_bkt->key_idx[prev_slot],
                         __ATOMIC_RELEASE);

        curr_slot = prev_slot;
        curr_node = prev_node;
        curr_bkt  = curr_node->bkt;
    }

    if (h->readwrite_concur_lf_support) {
        /* Inform the previous move. The current move need
         * not be informed now as the current bucket entry
         * is present in both primary and secondary.
         * Since there is one writer, load acquires on
         * tbl_chng_cnt are not required.
         */
        __atomic_store_n(h->tbl_chng_cnt, *h->tbl_chng_cnt + 1, __ATOMIC_RELEASE);
        /* The store to sig_current should not
         * move above the store to tbl_chng_cnt.
         */
        __atomic_thread_fence(__ATOMIC_RELEASE);
    }

    curr_bkt->sig_current[curr_slot] = sig;
    /* Release the new bucket entry */
    __atomic_store_n(&curr_bkt->key_idx[curr_slot], new_idx, __ATOMIC_RELEASE);

    return 0;
}

/*
 * Make space for new key, using bfs Cuckoo Search and Multi-Writer safe
 * Cuckoo
 */
static inline int
cne_hash_cuckoo_make_space_mw(const struct cne_hash *h, struct cne_hash_bucket *bkt,
                              struct cne_hash_bucket *sec_bkt, const struct cne_hash_key *key,
                              void *data, uint16_t sig, uint32_t bucket_idx, uint32_t new_idx,
                              int32_t *ret_val)
{
    unsigned int i;
    struct queue_node queue[CNE_HASH_BFS_QUEUE_MAX_LEN];
    struct queue_node *tail, *head;
    struct cne_hash_bucket *curr_bkt, *alt_bkt;
    uint32_t cur_idx, alt_idx;

    tail              = queue;
    head              = queue + 1;
    tail->bkt         = bkt;
    tail->prev        = NULL;
    tail->prev_slot   = -1;
    tail->cur_bkt_idx = bucket_idx;

    /* Cuckoo bfs Search */
    while (likely(tail != head &&
                  head < queue + CNE_HASH_BFS_QUEUE_MAX_LEN - CNE_HASH_BUCKET_ENTRIES)) {
        curr_bkt = tail->bkt;
        cur_idx  = tail->cur_bkt_idx;
        for (i = 0; i < CNE_HASH_BUCKET_ENTRIES; i++) {
            if (curr_bkt->key_idx[i] == EMPTY_SLOT) {
                int32_t ret = cne_hash_cuckoo_move_insert_mw(h, bkt, sec_bkt, key, data, tail, i,
                                                             sig, new_idx, ret_val);
                if (likely(ret != -1))
                    return ret;
            }

            /* Enqueue new node and keep prev node info */
            alt_idx           = get_alt_bucket_index(h, cur_idx, curr_bkt->sig_current[i]);
            alt_bkt           = &(h->buckets[alt_idx]);
            head->bkt         = alt_bkt;
            head->cur_bkt_idx = alt_idx;
            head->prev        = tail;
            head->prev_slot   = i;
            head++;
        }
        tail++;
    }

    return -ENOSPC;
}

static inline uint32_t
alloc_slot(const struct cne_hash *h)
{
    uint32_t slot_id;

    if (cne_ring_dequeue_elem(h->free_slots, &slot_id, sizeof(uint32_t)) != 0)
        return EMPTY_SLOT;

    return slot_id;
}

static inline int32_t
__cne_hash_add_key_with_hash(const struct cne_hash *h, const void *key, hash_sig_t sig, void *data)
{
    uint16_t short_sig;
    uint32_t prim_bucket_idx, sec_bucket_idx;
    struct cne_hash_bucket *prim_bkt, *sec_bkt, *cur_bkt;
    struct cne_hash_key *new_k, *keys = h->key_store;
    uint32_t ext_bkt_id = 0;
    uint32_t slot_id;
    int ret;
    unsigned int i;
    int32_t ret_val = 0;
    struct cne_hash_bucket *last;

    short_sig       = get_short_sig(sig);
    prim_bucket_idx = get_prim_bucket_index(h, sig);
    sec_bucket_idx  = get_alt_bucket_index(h, prim_bucket_idx, short_sig);
    prim_bkt        = &h->buckets[prim_bucket_idx];
    sec_bkt         = &h->buckets[sec_bucket_idx];
    cne_prefetch0(prim_bkt);
    cne_prefetch0(sec_bkt);

    /* Check if key is already inserted in primary location */
    __hash_rw_writer_lock(h);
    ret = search_and_update(h, data, key, prim_bkt, short_sig);
    if (ret != -1) {
        __hash_rw_writer_unlock(h);
        return ret;
    }

    /* Check if key is already inserted in secondary location */
    FOR_EACH_BUCKET (cur_bkt, sec_bkt) {
        ret = search_and_update(h, data, key, cur_bkt, short_sig);
        if (ret != -1) {
            __hash_rw_writer_unlock(h);
            return ret;
        }
    }

    __hash_rw_writer_unlock(h);

    /* Did not find a match, so get a new slot for storing the new key */
    slot_id = alloc_slot(h);
    if (slot_id == EMPTY_SLOT)
        return -ENOSPC;

    new_k = CNE_PTR_ADD(keys, slot_id * h->key_entry_size);
    /* The store to application data (by the application) at *data should
     * not leak after the store of pdata in the key store. i.e. pdata is
     * the guard variable. Release the application data to the readers.
     */
    __atomic_store_n(&new_k->pdata, data, __ATOMIC_RELEASE);
    /* Copy key */
    memcpy(new_k->key, key, h->key_len);

    /* Find an empty slot and insert */
    ret = cne_hash_cuckoo_insert_mw(h, prim_bkt, sec_bkt, key, data, short_sig, slot_id, &ret_val);
    if (ret == 0)
        return slot_id - 1;
    else if (ret == 1) {
        enqueue_slot_back(h, slot_id);
        return ret_val;
    }

    /* Primary bucket full, need to make space for new entry */
    ret = cne_hash_cuckoo_make_space_mw(h, prim_bkt, sec_bkt, key, data, short_sig, prim_bucket_idx,
                                        slot_id, &ret_val);
    if (ret == 0)
        return slot_id - 1;
    else if (ret == 1) {
        enqueue_slot_back(h, slot_id);
        return ret_val;
    }

    /* Also search secondary bucket to get better occupancy */
    ret = cne_hash_cuckoo_make_space_mw(h, sec_bkt, prim_bkt, key, data, short_sig, sec_bucket_idx,
                                        slot_id, &ret_val);

    if (ret == 0)
        return slot_id - 1;
    else if (ret == 1) {
        enqueue_slot_back(h, slot_id);
        return ret_val;
    }

    /* if ext table not enabled, we failed the insertion */
    if (!h->ext_table_support) {
        enqueue_slot_back(h, slot_id);
        return ret;
    }

    /* Now we need to go through the extendable bucket. Protection is needed
     * to protect all extendable bucket processes.
     */
    __hash_rw_writer_lock(h);
    /* We check for duplicates again since could be inserted before the lock */
    ret = search_and_update(h, data, key, prim_bkt, short_sig);
    if (ret != -1) {
        enqueue_slot_back(h, slot_id);
        goto failure;
    }

    FOR_EACH_BUCKET (cur_bkt, sec_bkt) {
        ret = search_and_update(h, data, key, cur_bkt, short_sig);
        if (ret != -1) {
            enqueue_slot_back(h, slot_id);
            goto failure;
        }
    }

    /* Search sec and ext buckets to find an empty entry to insert. */
    FOR_EACH_BUCKET (cur_bkt, sec_bkt) {
        for (i = 0; i < CNE_HASH_BUCKET_ENTRIES; i++) {
            /* Check if slot is available */
            if (likely(cur_bkt->key_idx[i] == EMPTY_SLOT)) {
                cur_bkt->sig_current[i] = short_sig;
                /* Store to signature and key should not
                 * leak after the store to key_idx. i.e.
                 * key_idx is the guard variable for signature
                 * and key.
                 */
                __atomic_store_n(&cur_bkt->key_idx[i], slot_id, __ATOMIC_RELEASE);
                __hash_rw_writer_unlock(h);
                return slot_id - 1;
            }
        }
    }

    /* Failed to get an empty entry from extendable buckets. Link a new
     * extendable bucket. We first get a free bucket from ring.
     */
    if (cne_ring_dequeue_elem(h->free_ext_bkts, &ext_bkt_id, sizeof(uint32_t)) != 0 ||
        ext_bkt_id == 0) {
        cne_ring_dequeue_elem(h->free_ext_bkts, &ext_bkt_id, sizeof(uint32_t));
        if (ext_bkt_id == 0) {
            ret = -ENOSPC;
            goto failure;
        }
    }

    /* Use the first location of the new bucket */
    (h->buckets_ext[ext_bkt_id - 1]).sig_current[0] = short_sig;
    /* Store to signature and key should not leak after
     * the store to key_idx. i.e. key_idx is the guard variable
     * for signature and key.
     */
    __atomic_store_n(&(h->buckets_ext[ext_bkt_id - 1]).key_idx[0], slot_id, __ATOMIC_RELEASE);
    /* Link the new bucket to sec bucket linked list */
    last       = cne_hash_get_last_bkt(sec_bkt);
    last->next = &h->buckets_ext[ext_bkt_id - 1];
    __hash_rw_writer_unlock(h);
    return slot_id - 1;

failure:
    __hash_rw_writer_unlock(h);
    return ret;
}

int32_t
cne_hash_add_key_with_hash(const struct cne_hash *h, const void *key, hash_sig_t sig)
{
    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
    return __cne_hash_add_key_with_hash(h, key, sig, 0);
}

int32_t
cne_hash_add_key(const struct cne_hash *h, const void *key)
{
    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
    return __cne_hash_add_key_with_hash(h, key, cne_hash_hash(h, key), 0);
}

int
cne_hash_add_key_with_hash_data(const struct cne_hash *h, const void *key, hash_sig_t sig,
                                void *data)
{
    int ret;

    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
    ret = __cne_hash_add_key_with_hash(h, key, sig, data);
    if (ret >= 0)
        return 0;
    else
        return ret;
}

int
cne_hash_add_key_data(const struct cne_hash *h, const void *key, void *data)
{
    int ret;

    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

    ret = __cne_hash_add_key_with_hash(h, key, cne_hash_hash(h, key), data);
    if (ret >= 0)
        return 0;
    else
        return ret;
}

/* Search one bucket to find the match key - uses rw lock */
static inline int32_t
search_one_bucket_l(const struct cne_hash *h, const void *key, uint16_t sig, void **data,
                    const struct cne_hash_bucket *bkt)
{
    int i;
    struct cne_hash_key *k, *keys = h->key_store;

    for (i = 0; i < CNE_HASH_BUCKET_ENTRIES; i++) {
        if (bkt->sig_current[i] == sig && bkt->key_idx[i] != EMPTY_SLOT) {
            k = (struct cne_hash_key *)((char *)keys + bkt->key_idx[i] * h->key_entry_size);

            if (cne_hash_cmp_eq(key, k->key, h) == 0) {
                if (data != NULL)
                    *data = k->pdata;
                /*
                 * Return index where key is stored,
                 * subtracting the first dummy index
                 */
                return bkt->key_idx[i] - 1;
            }
        }
    }
    return -1;
}

/* Search one bucket to find the match key */
static inline int32_t
search_one_bucket_lf(const struct cne_hash *h, const void *key, uint16_t sig, void **data,
                     const struct cne_hash_bucket *bkt)
{
    int i;
    uint32_t key_idx;
    struct cne_hash_key *k, *keys = h->key_store;

    for (i = 0; i < CNE_HASH_BUCKET_ENTRIES; i++) {
        /* Signature comparison is done before the acquire-load
         * of the key index to achieve better performance.
         * This can result in the reader loading old signature
         * (which matches), while the key_idx is updated to a
         * value that belongs to a new key. However, the full
         * key comparison will ensure that the lookup fails.
         */
        if (bkt->sig_current[i] == sig) {
            key_idx = __atomic_load_n(&bkt->key_idx[i], __ATOMIC_ACQUIRE);
            if (key_idx != EMPTY_SLOT) {
                k = (struct cne_hash_key *)((char *)keys + key_idx * h->key_entry_size);

                if (cne_hash_cmp_eq(key, k->key, h) == 0) {
                    if (data != NULL) {
                        *data = __atomic_load_n(&k->pdata, __ATOMIC_ACQUIRE);
                    }
                    /*
                     * Return index where key is stored,
                     * subtracting the first dummy index
                     */
                    return key_idx - 1;
                }
            }
        }
    }
    return -1;
}

static inline int32_t
__cne_hash_lookup_with_hash_l(const struct cne_hash *h, const void *key, hash_sig_t sig,
                              void **data)
{
    uint32_t prim_bucket_idx, sec_bucket_idx;
    struct cne_hash_bucket *bkt, *cur_bkt;
    int ret;
    uint16_t short_sig;

    short_sig       = get_short_sig(sig);
    prim_bucket_idx = get_prim_bucket_index(h, sig);
    sec_bucket_idx  = get_alt_bucket_index(h, prim_bucket_idx, short_sig);

    bkt = &h->buckets[prim_bucket_idx];

    __hash_rw_reader_lock(h);

    /* Check if key is in primary location */
    ret = search_one_bucket_l(h, key, short_sig, data, bkt);
    if (ret != -1) {
        __hash_rw_reader_unlock(h);
        return ret;
    }
    /* Calculate secondary hash */
    bkt = &h->buckets[sec_bucket_idx];

    /* Check if key is in secondary location */
    FOR_EACH_BUCKET (cur_bkt, bkt) {
        ret = search_one_bucket_l(h, key, short_sig, data, cur_bkt);
        if (ret != -1) {
            __hash_rw_reader_unlock(h);
            return ret;
        }
    }

    __hash_rw_reader_unlock(h);

    return -ENOENT;
}

static inline int32_t
__cne_hash_lookup_with_hash_lf(const struct cne_hash *h, const void *key, hash_sig_t sig,
                               void **data)
{
    uint32_t prim_bucket_idx, sec_bucket_idx;
    struct cne_hash_bucket *bkt, *cur_bkt;
    uint32_t cnt_b, cnt_a;
    int ret;
    uint16_t short_sig;

    short_sig       = get_short_sig(sig);
    prim_bucket_idx = get_prim_bucket_index(h, sig);
    sec_bucket_idx  = get_alt_bucket_index(h, prim_bucket_idx, short_sig);

    do {
        /* Load the table change counter before the lookup
         * starts. Acquire semantics will make sure that
         * loads in search_one_bucket are not hoisted.
         */
        cnt_b = __atomic_load_n(h->tbl_chng_cnt, __ATOMIC_ACQUIRE);

        /* Check if key is in primary location */
        bkt = &h->buckets[prim_bucket_idx];
        ret = search_one_bucket_lf(h, key, short_sig, data, bkt);
        if (ret != -1)
            return ret;
        /* Calculate secondary hash */
        bkt = &h->buckets[sec_bucket_idx];

        /* Check if key is in secondary location */
        FOR_EACH_BUCKET (cur_bkt, bkt) {
            ret = search_one_bucket_lf(h, key, short_sig, data, cur_bkt);
            if (ret != -1)
                return ret;
        }

        /* The loads of sig_current in search_one_bucket
         * should not move below the load from tbl_chng_cnt.
         */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        /* Re-read the table change counter to check if the
         * table has changed during search. If yes, re-do
         * the search.
         * This load should not get hoisted. The load
         * acquires on cnt_b, key index in primary bucket
         * and key index in secondary bucket will make sure
         * that it does not get hoisted.
         */
        cnt_a = __atomic_load_n(h->tbl_chng_cnt, __ATOMIC_ACQUIRE);
    } while (cnt_b != cnt_a);

    return -ENOENT;
}

static inline int32_t
__cne_hash_lookup_with_hash(const struct cne_hash *h, const void *key, hash_sig_t sig, void **data)
{
    if (h->readwrite_concur_lf_support)
        return __cne_hash_lookup_with_hash_lf(h, key, sig, data);
    else
        return __cne_hash_lookup_with_hash_l(h, key, sig, data);
}

int32_t
cne_hash_lookup_with_hash(const struct cne_hash *h, const void *key, hash_sig_t sig)
{
    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
    return __cne_hash_lookup_with_hash(h, key, sig, NULL);
}

int32_t
cne_hash_lookup(const struct cne_hash *h, const void *key)
{
    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
    return __cne_hash_lookup_with_hash(h, key, cne_hash_hash(h, key), NULL);
}

int
cne_hash_lookup_with_hash_data(const struct cne_hash *h, const void *key, hash_sig_t sig,
                               void **data)
{
    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
    return __cne_hash_lookup_with_hash(h, key, sig, data);
}

int
cne_hash_lookup_data(const struct cne_hash *h, const void *key, void **data)
{
    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
    return __cne_hash_lookup_with_hash(h, key, cne_hash_hash(h, key), data);
}

static int
free_slot(const struct cne_hash *h, uint32_t slot_id)
{
    /* Return key indexes to free slot ring */
    enqueue_slot_back(h, slot_id);
    return 0;
}

static inline void
remove_entry(const struct cne_hash *h, struct cne_hash_bucket *bkt, unsigned int i)
{
    int ret = free_slot(h, bkt->key_idx[i]);

    if (ret < 0)
        CNE_ERR("%s: could not enqueue free slots in global ring\n", __func__);
}

/* Compact the linked list by moving key from last entry in linked list to the
 * empty slot.
 */
static inline void
__cne_hash_compact_ll(const struct cne_hash *h, struct cne_hash_bucket *cur_bkt, int pos)
{
    int i;
    struct cne_hash_bucket *last_bkt;

    if (!cur_bkt->next)
        return;

    last_bkt = cne_hash_get_last_bkt(cur_bkt);

    for (i = CNE_HASH_BUCKET_ENTRIES - 1; i >= 0; i--) {
        if (last_bkt->key_idx[i] != EMPTY_SLOT) {
            cur_bkt->sig_current[pos] = last_bkt->sig_current[i];
            __atomic_store_n(&cur_bkt->key_idx[pos], last_bkt->key_idx[i], __ATOMIC_RELEASE);
            if (h->readwrite_concur_lf_support) {
                /* Inform the readers that the table has changed
                 * Since there is one writer, load acquire on
                 * tbl_chng_cnt is not required.
                 */
                __atomic_store_n(h->tbl_chng_cnt, *h->tbl_chng_cnt + 1, __ATOMIC_RELEASE);
                /* The store to sig_current should
                 * not move above the store to tbl_chng_cnt.
                 */
                __atomic_thread_fence(__ATOMIC_RELEASE);
            }
            last_bkt->sig_current[i] = NULL_SIGNATURE;
            __atomic_store_n(&last_bkt->key_idx[i], EMPTY_SLOT, __ATOMIC_RELEASE);
            return;
        }
    }
}

/* Search one bucket and remove the matched key.
 * Writer is expected to hold the lock while calling this
 * function.
 */
static inline int32_t
search_and_remove(const struct cne_hash *h, const void *key, struct cne_hash_bucket *bkt,
                  uint16_t sig, int *pos)
{
    struct cne_hash_key *k, *keys = h->key_store;
    unsigned int i;
    uint32_t key_idx;

    /* Check if key is in bucket */
    for (i = 0; i < CNE_HASH_BUCKET_ENTRIES; i++) {
        key_idx = __atomic_load_n(&bkt->key_idx[i], __ATOMIC_ACQUIRE);
        if (bkt->sig_current[i] == sig && key_idx != EMPTY_SLOT) {
            k = (struct cne_hash_key *)((char *)keys + key_idx * h->key_entry_size);
            if (cne_hash_cmp_eq(key, k->key, h) == 0) {
                bkt->sig_current[i] = NULL_SIGNATURE;
                /* Free the key store index if
                 * no_free_on_del is disabled.
                 */
                if (!h->no_free_on_del)
                    remove_entry(h, bkt, i);

                __atomic_store_n(&bkt->key_idx[i], EMPTY_SLOT, __ATOMIC_RELEASE);

                *pos = i;
                /*
                 * Return index where key is stored,
                 * subtracting the first dummy index
                 */
                return key_idx - 1;
            }
        }
    }
    return -1;
}

static inline int32_t
__cne_hash_del_key_with_hash(const struct cne_hash *h, const void *key, hash_sig_t sig)
{
    uint32_t prim_bucket_idx, sec_bucket_idx;
    struct cne_hash_bucket *prim_bkt, *sec_bkt, *prev_bkt, *last_bkt;
    struct cne_hash_bucket *cur_bkt;
    int pos;
    int32_t ret, i;
    uint16_t short_sig;
    uint32_t index = EMPTY_SLOT;

    short_sig       = get_short_sig(sig);
    prim_bucket_idx = get_prim_bucket_index(h, sig);
    sec_bucket_idx  = get_alt_bucket_index(h, prim_bucket_idx, short_sig);
    prim_bkt        = &h->buckets[prim_bucket_idx];

    __hash_rw_writer_lock(h);
    /* look for key in primary bucket */
    ret = search_and_remove(h, key, prim_bkt, short_sig, &pos);
    if (ret != -1) {
        __cne_hash_compact_ll(h, prim_bkt, pos);
        last_bkt = prim_bkt->next;
        prev_bkt = prim_bkt;
        goto return_bkt;
    }

    /* Calculate secondary hash */
    sec_bkt = &h->buckets[sec_bucket_idx];

    FOR_EACH_BUCKET (cur_bkt, sec_bkt) {
        ret = search_and_remove(h, key, cur_bkt, short_sig, &pos);
        if (ret != -1) {
            __cne_hash_compact_ll(h, cur_bkt, pos);
            last_bkt = sec_bkt->next;
            prev_bkt = sec_bkt;
            goto return_bkt;
        }
    }

    __hash_rw_writer_unlock(h);
    return -ENOENT;

/* Search last bucket to see if empty to be recycled */
return_bkt:
    if (!last_bkt)
        goto return_key;

    while (last_bkt->next) {
        prev_bkt = last_bkt;
        last_bkt = last_bkt->next;
    }

    for (i = 0; i < CNE_HASH_BUCKET_ENTRIES; i++) {
        if (last_bkt->key_idx[i] != EMPTY_SLOT)
            break;
    }
    /* found empty bucket and recycle */
    if (i == CNE_HASH_BUCKET_ENTRIES) {
        prev_bkt->next = NULL;
        index          = last_bkt - h->buckets_ext + 1;
        /* Recycle the empty bkt if
         * no_free_on_del is disabled.
         */
        if (h->no_free_on_del) {
            /* Store index of an empty ext bkt to be recycled
             * on calling cne_hash_del_xxx APIs.
             * When lock free read-write concurrency is enabled,
             * an empty ext bkt cannot be put into free list
             * immediately (as readers might be using it still).
             * Hence freeing of the ext bkt is piggy-backed to
             * freeing of the key index.
             */
        } else
            cne_ring_enqueue_elem(h->free_ext_bkts, &index, sizeof(uint32_t));
    }

return_key:
    __hash_rw_writer_unlock(h);
    return ret;
}

int32_t
cne_hash_del_key_with_hash(const struct cne_hash *h, const void *key, hash_sig_t sig)
{
    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
    return __cne_hash_del_key_with_hash(h, key, sig);
}

int32_t
cne_hash_del_key(const struct cne_hash *h, const void *key)
{
    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
    return __cne_hash_del_key_with_hash(h, key, cne_hash_hash(h, key));
}

int
cne_hash_get_key_with_position(const struct cne_hash *h, const int32_t position, void **key)
{
    RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

    struct cne_hash_key *k, *keys = h->key_store;
    k    = (struct cne_hash_key *)((char *)keys + (position + 1) * h->key_entry_size);
    *key = k->key;

    if (position != __cne_hash_lookup_with_hash(h, *key, cne_hash_hash(h, *key), NULL))
        return -ENOENT;

    return 0;
}

int
cne_hash_free_key_with_position(const struct cne_hash *h, const int32_t position)
{
    /* Key index where key is stored, adding the first dummy index */
    uint32_t key_idx = position + 1;

    RETURN_IF_TRUE(((h == NULL) || (key_idx == EMPTY_SLOT)), -EINVAL);

    const uint32_t total_entries = h->entries + 1;

    /* Out of bounds */
    if (key_idx >= total_entries)
        return -EINVAL;
    if (h->ext_table_support && h->readwrite_concur_lf_support) {
        uint32_t index = h->ext_bkt_to_free[position];
        if (index) {
            /* Recycle empty ext bkt to free list. */
            cne_ring_enqueue_elem(h->free_ext_bkts, &index, sizeof(uint32_t));
            h->ext_bkt_to_free[position] = 0;
        }
    }

    /* Enqueue slot to cache/ring of free slots. */
    return free_slot(h, key_idx);
}

static inline void
compare_signatures(uint32_t *prim_hash_matches, uint32_t *sec_hash_matches,
                   const struct cne_hash_bucket *prim_bkt, const struct cne_hash_bucket *sec_bkt,
                   uint16_t sig, enum cne_hash_sig_compare_function sig_cmp_fn)
{
    unsigned int i;

    /* For match mask the first bit of every two bits indicates the match */
    switch (sig_cmp_fn) {
    case CNE_HASH_COMPARE_SSE:
        if (__builtin_cpu_supports("sse2")) {
            /* Compare all signatures in the bucket */
            *prim_hash_matches = _mm_movemask_epi8(_mm_cmpeq_epi16(
                _mm_load_si128((__m128i const *)prim_bkt->sig_current), _mm_set1_epi16(sig)));
            /* Compare all signatures in the bucket */
            *sec_hash_matches = _mm_movemask_epi8(_mm_cmpeq_epi16(
                _mm_load_si128((__m128i const *)sec_bkt->sig_current), _mm_set1_epi16(sig)));
            break;
        }
        /* FALL-THRU */
    default:
        for (i = 0; i < CNE_HASH_BUCKET_ENTRIES; i++) {
            *prim_hash_matches |= ((sig == prim_bkt->sig_current[i]) << (i << 1));
            *sec_hash_matches |= ((sig == sec_bkt->sig_current[i]) << (i << 1));
        }
    }
}

static inline void
__bulk_lookup_l(const struct cne_hash *h, const void **keys,
                const struct cne_hash_bucket **primary_bkt,
                const struct cne_hash_bucket **secondary_bkt, uint16_t *sig, int32_t num_keys,
                int32_t *positions, uint64_t *hit_mask, void *data[])
{
    uint64_t hits = 0;
    int32_t i;
    int32_t ret;
    uint32_t prim_hitmask[CNE_HASH_LOOKUP_BULK_MAX] = {0};
    uint32_t sec_hitmask[CNE_HASH_LOOKUP_BULK_MAX]  = {0};
    struct cne_hash_bucket *cur_bkt, *next_bkt;

    /* Compare signatures and prefetch key slot of first hit */
    for (i = 0; i < num_keys; i++) {
        compare_signatures(&prim_hitmask[i], &sec_hitmask[i], primary_bkt[i], secondary_bkt[i],
                           sig[i], h->sig_cmp_fn);

        if (prim_hitmask[i]) {
            uint32_t first_hit = __builtin_ctzl(prim_hitmask[i]) >> 1;
            uint32_t key_idx   = primary_bkt[i]->key_idx[first_hit];
            const struct cne_hash_key *key_slot =
                (const struct cne_hash_key *)((const char *)h->key_store +
                                              key_idx * h->key_entry_size);
            cne_prefetch0(key_slot);
            continue;
        }

        if (sec_hitmask[i]) {
            uint32_t first_hit = __builtin_ctzl(sec_hitmask[i]) >> 1;
            uint32_t key_idx   = secondary_bkt[i]->key_idx[first_hit];
            const struct cne_hash_key *key_slot =
                (const struct cne_hash_key *)((const char *)h->key_store +
                                              key_idx * h->key_entry_size);
            cne_prefetch0(key_slot);
        }
    }

    /* Compare keys, first hits in primary first */
    for (i = 0; i < num_keys; i++) {
        positions[i] = -ENOENT;
        while (prim_hitmask[i]) {
            uint32_t hit_index = __builtin_ctzl(prim_hitmask[i]) >> 1;
            uint32_t key_idx   = primary_bkt[i]->key_idx[hit_index];
            const struct cne_hash_key *key_slot =
                (const struct cne_hash_key *)((const char *)h->key_store +
                                              key_idx * h->key_entry_size);

            /*
             * If key index is 0, do not compare key,
             * as it is checking the dummy slot
             */
            if (!!key_idx & !cne_hash_cmp_eq(key_slot->key, keys[i], h)) {
                if (data != NULL)
                    data[i] = key_slot->pdata;

                hits |= 1ULL << i;
                positions[i] = key_idx - 1;
                goto next_key;
            }
            prim_hitmask[i] &= ~(3ULL << (hit_index << 1));
        }

        while (sec_hitmask[i]) {
            uint32_t hit_index = __builtin_ctzl(sec_hitmask[i]) >> 1;
            uint32_t key_idx   = secondary_bkt[i]->key_idx[hit_index];
            const struct cne_hash_key *key_slot =
                (const struct cne_hash_key *)((const char *)h->key_store +
                                              key_idx * h->key_entry_size);

            /*
             * If key index is 0, do not compare key,
             * as it is checking the dummy slot
             */

            if (!!key_idx & !cne_hash_cmp_eq(key_slot->key, keys[i], h)) {
                if (data != NULL)
                    data[i] = key_slot->pdata;

                hits |= 1ULL << i;
                positions[i] = key_idx - 1;
                goto next_key;
            }
            sec_hitmask[i] &= ~(3ULL << (hit_index << 1));
        }
    next_key:
        continue;
    }

    /* all found, do not need to go through ext bkt */
    if ((hits == ((1ULL << num_keys) - 1)) || !h->ext_table_support) {
        if (hit_mask != NULL)
            *hit_mask = hits;
        __hash_rw_reader_unlock(h);
        return;
    }

    /* need to check ext buckets for match */
    for (i = 0; i < num_keys; i++) {
        if ((hits & (1ULL << i)) != 0)
            continue;
        next_bkt = secondary_bkt[i]->next;
        FOR_EACH_BUCKET (cur_bkt, next_bkt) {
            if (data != NULL)
                ret = search_one_bucket_l(h, keys[i], sig[i], &data[i], cur_bkt);
            else
                ret = search_one_bucket_l(h, keys[i], sig[i], NULL, cur_bkt);
            if (ret != -1) {
                positions[i] = ret;
                hits |= 1ULL << i;
                break;
            }
        }
    }

    __hash_rw_reader_unlock(h);

    if (hit_mask != NULL)
        *hit_mask = hits;
}

static inline void
__bulk_lookup_lf(const struct cne_hash *h, const void **keys,
                 const struct cne_hash_bucket **primary_bkt,
                 const struct cne_hash_bucket **secondary_bkt, uint16_t *sig, int32_t num_keys,
                 int32_t *positions, uint64_t *hit_mask, void *data[])
{
    uint64_t hits = 0;
    int32_t i;
    int32_t ret;
    uint32_t prim_hitmask[CNE_HASH_LOOKUP_BULK_MAX] = {0};
    uint32_t sec_hitmask[CNE_HASH_LOOKUP_BULK_MAX]  = {0};
    struct cne_hash_bucket *cur_bkt, *next_bkt;
    uint32_t cnt_b, cnt_a;

    for (i = 0; i < num_keys; i++)
        positions[i] = -ENOENT;

    do {
        /* Load the table change counter before the lookup
         * starts. Acquire semantics will make sure that
         * loads in compare_signatures are not hoisted.
         */
        cnt_b = __atomic_load_n(h->tbl_chng_cnt, __ATOMIC_ACQUIRE);

        /* Compare signatures and prefetch key slot of first hit */
        for (i = 0; i < num_keys; i++) {
            compare_signatures(&prim_hitmask[i], &sec_hitmask[i], primary_bkt[i], secondary_bkt[i],
                               sig[i], h->sig_cmp_fn);

            if (prim_hitmask[i]) {
                uint32_t first_hit = __builtin_ctzl(prim_hitmask[i]) >> 1;
                uint32_t key_idx   = primary_bkt[i]->key_idx[first_hit];
                const struct cne_hash_key *key_slot =
                    (const struct cne_hash_key *)((const char *)h->key_store +
                                                  key_idx * h->key_entry_size);
                cne_prefetch0(key_slot);
                continue;
            }

            if (sec_hitmask[i]) {
                uint32_t first_hit = __builtin_ctzl(sec_hitmask[i]) >> 1;
                uint32_t key_idx   = secondary_bkt[i]->key_idx[first_hit];
                const struct cne_hash_key *key_slot =
                    (const struct cne_hash_key *)((const char *)h->key_store +
                                                  key_idx * h->key_entry_size);
                cne_prefetch0(key_slot);
            }
        }

        /* Compare keys, first hits in primary first */
        for (i = 0; i < num_keys; i++) {
            while (prim_hitmask[i]) {
                uint32_t hit_index = __builtin_ctzl(prim_hitmask[i]) >> 1;
                uint32_t key_idx =
                    __atomic_load_n(&primary_bkt[i]->key_idx[hit_index], __ATOMIC_ACQUIRE);
                const struct cne_hash_key *key_slot =
                    (const struct cne_hash_key *)((const char *)h->key_store +
                                                  key_idx * h->key_entry_size);

                /*
                 * If key index is 0, do not compare key,
                 * as it is checking the dummy slot
                 */
                if (!!key_idx & !cne_hash_cmp_eq(key_slot->key, keys[i], h)) {
                    if (data != NULL)
                        data[i] = __atomic_load_n(&key_slot->pdata, __ATOMIC_ACQUIRE);

                    hits |= 1ULL << i;
                    positions[i] = key_idx - 1;
                    goto next_key;
                }
                prim_hitmask[i] &= ~(3ULL << (hit_index << 1));
            }

            while (sec_hitmask[i]) {
                uint32_t hit_index = __builtin_ctzl(sec_hitmask[i]) >> 1;
                uint32_t key_idx =
                    __atomic_load_n(&secondary_bkt[i]->key_idx[hit_index], __ATOMIC_ACQUIRE);
                const struct cne_hash_key *key_slot =
                    (const struct cne_hash_key *)((const char *)h->key_store +
                                                  key_idx * h->key_entry_size);

                /*
                 * If key index is 0, do not compare key,
                 * as it is checking the dummy slot
                 */

                if (!!key_idx & !cne_hash_cmp_eq(key_slot->key, keys[i], h)) {
                    if (data != NULL)
                        data[i] = __atomic_load_n(&key_slot->pdata, __ATOMIC_ACQUIRE);

                    hits |= 1ULL << i;
                    positions[i] = key_idx - 1;
                    goto next_key;
                }
                sec_hitmask[i] &= ~(3ULL << (hit_index << 1));
            }
        next_key:
            continue;
        }

        /* all found, do not need to go through ext bkt */
        if (hits == ((1ULL << num_keys) - 1)) {
            if (hit_mask != NULL)
                *hit_mask = hits;
            return;
        }
        /* need to check ext buckets for match */
        if (h->ext_table_support) {
            for (i = 0; i < num_keys; i++) {
                if ((hits & (1ULL << i)) != 0)
                    continue;
                next_bkt = secondary_bkt[i]->next;
                FOR_EACH_BUCKET (cur_bkt, next_bkt) {
                    if (data != NULL)
                        ret = search_one_bucket_lf(h, keys[i], sig[i], &data[i], cur_bkt);
                    else
                        ret = search_one_bucket_lf(h, keys[i], sig[i], NULL, cur_bkt);
                    if (ret != -1) {
                        positions[i] = ret;
                        hits |= 1ULL << i;
                        break;
                    }
                }
            }
        }
        /* The loads of sig_current in compare_signatures
         * should not move below the load from tbl_chng_cnt.
         */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        /* Re-read the table change counter to check if the
         * table has changed during search. If yes, re-do
         * the search.
         * This load should not get hoisted. The load
         * acquires on cnt_b, primary key index and secondary
         * key index will make sure that it does not get
         * hoisted.
         */
        cnt_a = __atomic_load_n(h->tbl_chng_cnt, __ATOMIC_ACQUIRE);
    } while (cnt_b != cnt_a);

    if (hit_mask != NULL)
        *hit_mask = hits;
}

#define PREFETCH_OFFSET 4
static inline void
__bulk_lookup_prefetching_loop(const struct cne_hash *h, const void **keys, int32_t num_keys,
                               uint16_t *sig, const struct cne_hash_bucket **primary_bkt,
                               const struct cne_hash_bucket **secondary_bkt)
{
    int32_t i;
    uint32_t prim_hash[CNE_HASH_LOOKUP_BULK_MAX];
    uint32_t prim_index[CNE_HASH_LOOKUP_BULK_MAX];
    uint32_t sec_index[CNE_HASH_LOOKUP_BULK_MAX];

    /* Prefetch first keys */
    for (i = 0; i < PREFETCH_OFFSET && i < num_keys; i++)
        cne_prefetch0(keys[i]);

    /*
     * Prefetch rest of the keys, calculate primary and
     * secondary bucket and prefetch them
     */
    for (i = 0; i < (num_keys - PREFETCH_OFFSET); i++) {
        cne_prefetch0(keys[i + PREFETCH_OFFSET]);

        prim_hash[i] = cne_hash_hash(h, keys[i]);

        sig[i]        = get_short_sig(prim_hash[i]);
        prim_index[i] = get_prim_bucket_index(h, prim_hash[i]);
        sec_index[i]  = get_alt_bucket_index(h, prim_index[i], sig[i]);

        primary_bkt[i]   = &h->buckets[prim_index[i]];
        secondary_bkt[i] = &h->buckets[sec_index[i]];

        cne_prefetch0(primary_bkt[i]);
        cne_prefetch0(secondary_bkt[i]);
    }

    /* Calculate and prefetch rest of the buckets */
    for (; i < num_keys; i++) {
        prim_hash[i] = cne_hash_hash(h, keys[i]);

        sig[i]        = get_short_sig(prim_hash[i]);
        prim_index[i] = get_prim_bucket_index(h, prim_hash[i]);
        sec_index[i]  = get_alt_bucket_index(h, prim_index[i], sig[i]);

        primary_bkt[i]   = &h->buckets[prim_index[i]];
        secondary_bkt[i] = &h->buckets[sec_index[i]];

        cne_prefetch0(primary_bkt[i]);
        cne_prefetch0(secondary_bkt[i]);
    }
}

static inline void
__cne_hash_lookup_bulk_l(const struct cne_hash *h, const void **keys, int32_t num_keys,
                         int32_t *positions, uint64_t *hit_mask, void *data[])
{
    uint16_t sig[CNE_HASH_LOOKUP_BULK_MAX];
    const struct cne_hash_bucket *primary_bkt[CNE_HASH_LOOKUP_BULK_MAX];
    const struct cne_hash_bucket *secondary_bkt[CNE_HASH_LOOKUP_BULK_MAX];

    __bulk_lookup_prefetching_loop(h, keys, num_keys, sig, primary_bkt, secondary_bkt);

    __bulk_lookup_l(h, keys, primary_bkt, secondary_bkt, sig, num_keys, positions, hit_mask, data);
}

static inline void
__cne_hash_lookup_bulk_lf(const struct cne_hash *h, const void **keys, int32_t num_keys,
                          int32_t *positions, uint64_t *hit_mask, void *data[])
{
    uint16_t sig[CNE_HASH_LOOKUP_BULK_MAX];
    const struct cne_hash_bucket *primary_bkt[CNE_HASH_LOOKUP_BULK_MAX];
    const struct cne_hash_bucket *secondary_bkt[CNE_HASH_LOOKUP_BULK_MAX];

    __bulk_lookup_prefetching_loop(h, keys, num_keys, sig, primary_bkt, secondary_bkt);

    __bulk_lookup_lf(h, keys, primary_bkt, secondary_bkt, sig, num_keys, positions, hit_mask, data);
}

static inline void
__cne_hash_lookup_bulk(const struct cne_hash *h, const void **keys, int32_t num_keys,
                       int32_t *positions, uint64_t *hit_mask, void *data[])
{
    if (h->readwrite_concur_lf_support)
        __cne_hash_lookup_bulk_lf(h, keys, num_keys, positions, hit_mask, data);
    else
        __cne_hash_lookup_bulk_l(h, keys, num_keys, positions, hit_mask, data);
}

int
cne_hash_lookup_bulk(const struct cne_hash *h, const void **keys, uint32_t num_keys,
                     int32_t *positions)
{
    RETURN_IF_TRUE(((h == NULL) || (keys == NULL) || (num_keys == 0) ||
                    (num_keys > CNE_HASH_LOOKUP_BULK_MAX) || (positions == NULL)),
                   -EINVAL);

    __cne_hash_lookup_bulk(h, keys, num_keys, positions, NULL, NULL);
    return 0;
}

int
cne_hash_lookup_bulk_data(const struct cne_hash *h, const void **keys, uint32_t num_keys,
                          uint64_t *hit_mask, void *data[])
{
    RETURN_IF_TRUE(((h == NULL) || (keys == NULL) || (num_keys == 0) ||
                    (num_keys > CNE_HASH_LOOKUP_BULK_MAX) || (hit_mask == NULL)),
                   -EINVAL);

    int32_t positions[num_keys];

    __cne_hash_lookup_bulk(h, keys, num_keys, positions, hit_mask, data);

    /* Return number of hits */
    return __builtin_popcountl(*hit_mask);
}

static inline void
__cne_hash_lookup_with_hash_bulk_l(const struct cne_hash *h, const void **keys,
                                   hash_sig_t *prim_hash, int32_t num_keys, int32_t *positions,
                                   uint64_t *hit_mask, void *data[])
{
    int32_t i;
    uint32_t prim_index[CNE_HASH_LOOKUP_BULK_MAX];
    uint32_t sec_index[CNE_HASH_LOOKUP_BULK_MAX];
    uint16_t sig[CNE_HASH_LOOKUP_BULK_MAX];
    const struct cne_hash_bucket *primary_bkt[CNE_HASH_LOOKUP_BULK_MAX];
    const struct cne_hash_bucket *secondary_bkt[CNE_HASH_LOOKUP_BULK_MAX];

    /*
     * Prefetch keys, calculate primary and
     * secondary bucket and prefetch them
     */
    for (i = 0; i < num_keys; i++) {
        cne_prefetch0(keys[i]);

        sig[i]        = get_short_sig(prim_hash[i]);
        prim_index[i] = get_prim_bucket_index(h, prim_hash[i]);
        sec_index[i]  = get_alt_bucket_index(h, prim_index[i], sig[i]);

        primary_bkt[i]   = &h->buckets[prim_index[i]];
        secondary_bkt[i] = &h->buckets[sec_index[i]];

        cne_prefetch0(primary_bkt[i]);
        cne_prefetch0(secondary_bkt[i]);
    }

    __bulk_lookup_l(h, keys, primary_bkt, secondary_bkt, sig, num_keys, positions, hit_mask, data);
}

static inline void
__cne_hash_lookup_with_hash_bulk_lf(const struct cne_hash *h, const void **keys,
                                    hash_sig_t *prim_hash, int32_t num_keys, int32_t *positions,
                                    uint64_t *hit_mask, void *data[])
{
    int32_t i;
    uint32_t prim_index[CNE_HASH_LOOKUP_BULK_MAX];
    uint32_t sec_index[CNE_HASH_LOOKUP_BULK_MAX];
    uint16_t sig[CNE_HASH_LOOKUP_BULK_MAX];
    const struct cne_hash_bucket *primary_bkt[CNE_HASH_LOOKUP_BULK_MAX];
    const struct cne_hash_bucket *secondary_bkt[CNE_HASH_LOOKUP_BULK_MAX];

    /*
     * Prefetch keys, calculate primary and
     * secondary bucket and prefetch them
     */
    for (i = 0; i < num_keys; i++) {
        cne_prefetch0(keys[i]);

        sig[i]        = get_short_sig(prim_hash[i]);
        prim_index[i] = get_prim_bucket_index(h, prim_hash[i]);
        sec_index[i]  = get_alt_bucket_index(h, prim_index[i], sig[i]);

        primary_bkt[i]   = &h->buckets[prim_index[i]];
        secondary_bkt[i] = &h->buckets[sec_index[i]];

        cne_prefetch0(primary_bkt[i]);
        cne_prefetch0(secondary_bkt[i]);
    }

    __bulk_lookup_lf(h, keys, primary_bkt, secondary_bkt, sig, num_keys, positions, hit_mask, data);
}

static inline void
__cne_hash_lookup_with_hash_bulk(const struct cne_hash *h, const void **keys, hash_sig_t *prim_hash,
                                 int32_t num_keys, int32_t *positions, uint64_t *hit_mask,
                                 void *data[])
{
    if (h->readwrite_concur_lf_support)
        __cne_hash_lookup_with_hash_bulk_lf(h, keys, prim_hash, num_keys, positions, hit_mask,
                                            data);
    else
        __cne_hash_lookup_with_hash_bulk_l(h, keys, prim_hash, num_keys, positions, hit_mask, data);
}

int
cne_hash_lookup_with_hash_bulk(const struct cne_hash *h, const void **keys, hash_sig_t *sig,
                               uint32_t num_keys, int32_t *positions)
{
    RETURN_IF_TRUE(((h == NULL) || (keys == NULL) || (sig == NULL) || (num_keys == 0) ||
                    (num_keys > CNE_HASH_LOOKUP_BULK_MAX) || (positions == NULL)),
                   -EINVAL);

    __cne_hash_lookup_with_hash_bulk(h, keys, sig, num_keys, positions, NULL, NULL);
    return 0;
}

int
cne_hash_lookup_with_hash_bulk_data(const struct cne_hash *h, const void **keys, hash_sig_t *sig,
                                    uint32_t num_keys, uint64_t *hit_mask, void *data[])
{
    RETURN_IF_TRUE(((h == NULL) || (keys == NULL) || (sig == NULL) || (num_keys == 0) ||
                    (num_keys > CNE_HASH_LOOKUP_BULK_MAX) || (hit_mask == NULL)),
                   -EINVAL);

    int32_t positions[num_keys];

    __cne_hash_lookup_with_hash_bulk(h, keys, sig, num_keys, positions, hit_mask, data);

    /* Return number of hits */
    return __builtin_popcountl(*hit_mask);
}

int32_t
cne_hash_iterate(const struct cne_hash *h, const void **key, void **data, uint32_t *next)
{
    uint32_t bucket_idx, idx, position;
    struct cne_hash_key *next_key;

    RETURN_IF_TRUE(((h == NULL) || (next == NULL)), -EINVAL);

    const uint32_t total_entries_main = h->num_buckets * CNE_HASH_BUCKET_ENTRIES;
    const uint32_t total_entries      = total_entries_main << 1;

    /* Out of bounds of all buckets (both main table and ext table) */
    if (*next >= total_entries_main)
        goto extend_table;

    /* Calculate bucket and index of current iterator */
    bucket_idx = *next / CNE_HASH_BUCKET_ENTRIES;
    idx        = *next % CNE_HASH_BUCKET_ENTRIES;

    /* If current position is empty, go to the next one */
    while ((position = __atomic_load_n(&h->buckets[bucket_idx].key_idx[idx], __ATOMIC_ACQUIRE)) ==
           EMPTY_SLOT) {
        (*next)++;
        /* End of table */
        if (*next == total_entries_main)
            goto extend_table;
        bucket_idx = *next / CNE_HASH_BUCKET_ENTRIES;
        idx        = *next % CNE_HASH_BUCKET_ENTRIES;
    }

    __hash_rw_reader_lock(h);
    next_key = (struct cne_hash_key *)((char *)h->key_store + position * h->key_entry_size);
    /* Return key and data */
    *key  = next_key->key;
    *data = next_key->pdata;

    __hash_rw_reader_unlock(h);

    /* Increment iterator */
    (*next)++;

    return position - 1;

/* Begin to iterate extendable buckets */
extend_table:
    /* Out of total bound or if ext bucket feature is not enabled */
    if (*next >= total_entries || !h->ext_table_support)
        return -ENOENT;

    bucket_idx = (*next - total_entries_main) / CNE_HASH_BUCKET_ENTRIES;
    idx        = (*next - total_entries_main) % CNE_HASH_BUCKET_ENTRIES;

    while ((position = h->buckets_ext[bucket_idx].key_idx[idx]) == EMPTY_SLOT) {
        (*next)++;
        if (*next == total_entries)
            return -ENOENT;
        bucket_idx = (*next - total_entries_main) / CNE_HASH_BUCKET_ENTRIES;
        idx        = (*next - total_entries_main) % CNE_HASH_BUCKET_ENTRIES;
    }
    __hash_rw_reader_lock(h);
    next_key = (struct cne_hash_key *)((char *)h->key_store + position * h->key_entry_size);
    /* Return key and data */
    *key  = next_key->key;
    *data = next_key->pdata;

    __hash_rw_reader_unlock(h);

    /* Increment iterator */
    (*next)++;
    return position - 1;
}
