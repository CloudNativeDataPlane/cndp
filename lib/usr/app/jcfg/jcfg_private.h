/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _JCFG_PRIVATE_H_
#define _JCFG_PRIVATE_H_

#include <sys/queue.h>
#include <pthread.h>

#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>
#include <json-c/json_visit.h>
#include <json-c/linkhash.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * JCFG client structure for Unix Domain Socket support.
 */
typedef struct jcfg_client_s {
    int s;                     /**< Accepted socket ID */
    jcfg_info_t *info;         /**< Pointer to jcfg data */
    pthread_barrier_t barrier; /**< A barrier to sync up threads being started */
} jcfg_client_t;

/**
 * Primary JCFG structure an internal structure.
 */
struct jcfg {
    struct jcfg_data data;    /**< Pointer to data section of jcfg */
    char *str;                /**< allocated string pointing to json or jsonc text */
    struct json_object *root; /**< JSON root object */
    struct json_tokener *tok; /**< pointer to tokener structure */
};

/**
 * Entry in queue list used by lport groups
 */
struct queue_list_entry {
    uint16_t v;                         /**< queue id */
    TAILQ_ENTRY(queue_list_entry) next; /**< next entry in the list */
};

/**
 * Queue list head used by lport groups
 */
TAILQ_HEAD(queue_list_head, queue_list_entry);

/**
 * Queue list structure used by lport groups
 */
struct queue_list {
    uint16_t min; /**< lowest queue id in the list */
    uint16_t max; /**< highest queue id in the list */
    uint16_t num; /**< number of queue ids in the list */

    struct queue_list_head head; /**< the queue list entries */
};

/**
 * Return the JSON file string
 *
 * @param cfg
 *   The jcfg structure pointer
 * @return
 *   The pointer to the jcfg string, which is the JSON text.
 */
static inline char *
jcfg_get_json_string(struct jcfg *cfg)
{
    return (cfg) ? cfg->str : NULL;
}

/**
 * Return the JSON file token structure pointer
 *
 * @param cfg
 *   The jcfg structure pointer
 * @return
 *   The pointer to the jcfg token, which is the JSON text after it is parsed into tokens.
 */
static inline struct json_tokener *
jcfg_get_json_token(struct jcfg *cfg)
{
    return (cfg) ? cfg->tok : NULL;
}

/**
 * Free the internal umem structure.
 * @internal
 *
 * @param hdr
 *   The generic header structure pointer.
 */
void jcfg_umem_free(jcfg_hdr_t *hdr);

#ifdef __cplusplus
}
#endif

#endif /* _JCFG_PRIVATE_H_ */
