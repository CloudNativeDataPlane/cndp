/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2023 Intel Corporation
 */

#include <stdint.h>            // for uint32_t
#include <stdio.h>             // for snprintf
#include <string.h>            // for NULL
#include <cne_common.h>        // for cne_is_power_of_2
#include <cne_log.h>           // for CNE_LOG_ERR, CNE_NULL_RET
#include <bsd/string.h>        // for strlcpy
#include <stdlib.h>            // for calloc, free

#include "cne_fbk_hash.h"
#include "cne_hash_crc.h"        // for cne_hash_crc_4byte
#include "cne_jhash.h"           // for cne_jhash_1word

/**
 * Create a new hash table for use with four byte keys.
 *
 * @param params
 *   Parameters used in creation of hash table.
 *
 * @return
 *   Pointer to hash table structure that is used in future hash table
 *   operations, or NULL on error.
 */
struct cne_fbk_hash_table *
cne_fbk_hash_create(const struct cne_fbk_hash_params *params)
{
    struct cne_fbk_hash_table *ht = NULL;
    char hash_name[CNE_FBK_HASH_NAMESIZE];
    const uint32_t mem_size = sizeof(*ht) + (sizeof(ht->t[0]) * params->entries);
    uint32_t i;

    cne_fbk_hash_fn default_hash_func = (cne_fbk_hash_fn)cne_jhash_1word;

    /* Error checking of parameters. */
    if ((!cne_is_power_of_2(params->entries)) || (!cne_is_power_of_2(params->entries_per_bucket)) ||
        (params->entries == 0) || (params->entries_per_bucket == 0) ||
        (params->entries_per_bucket > params->entries) ||
        (params->entries > CNE_FBK_HASH_ENTRIES_MAX) ||
        (params->entries_per_bucket > CNE_FBK_HASH_ENTRIES_PER_BUCKET_MAX)) {
        return NULL;
    }

    snprintf(hash_name, sizeof(hash_name), "FBK_%s", params->name);

    /* Allocate memory for table. */
    ht = calloc(1, mem_size);
    if (ht == NULL)
        CNE_NULL_RET("Failed to allocate fbk hash table\n");

    /* Default hash function */
    default_hash_func = (cne_fbk_hash_fn)cne_hash_crc_4byte;

    /* Set up hash table context. */
    strlcpy(ht->name, params->name, sizeof(ht->name));
    ht->entries            = params->entries;
    ht->entries_per_bucket = params->entries_per_bucket;
    ht->used_entries       = 0;
    ht->bucket_mask        = (params->entries / params->entries_per_bucket) - 1;
    for (ht->bucket_shift = 0, i = 1; (params->entries_per_bucket & i) == 0;
         ht->bucket_shift++, i <<= 1)
        ; /* empty loop body */

    if (params->hash_func != NULL) {
        ht->hash_func = params->hash_func;
        ht->init_val  = params->init_val;
    } else {
        ht->hash_func = default_hash_func;
        ht->init_val  = CNE_FBK_HASH_INIT_VAL_DEFAULT;
    }

    return ht;
}

/**
 * Free all memory used by a hash table.
 *
 * @param ht
 *   Hash table to deallocate.
 */
void
cne_fbk_hash_free(struct cne_fbk_hash_table *ht)
{

    if (ht == NULL)
        return;

    free(ht);
}
