/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <net/if.h>

#ifndef __NETLINK_PRIVATE_H
#define __NETLINK_PRIVATE_H

#include <cne_common.h>
#include <cne_rwlock.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DUMP_PARAMS_INIT(info, dump)                                            \
    {                                                                           \
        .dp_type = dump, .dp_fd = stdout, .dp_dump_msgtype = 1, .dp_data = info \
    }

#define NL_DEBUG(...)              \
    do {                           \
        if (netlink_debug)         \
            CNE_INFO(__VA_ARGS__); \
    } while (0)

#define NL_OBJ_DUMP(obj)                                                 \
    do {                                                                 \
        struct nl_dump_params dp = DUMP_PARAMS_INIT(info, NL_DUMP_LINE); \
        if (netlink_debug)                                               \
            nl_object_dump(obj, &dp);                                    \
    } while (0)

typedef void (*netlink_func_t)(struct netlink_info *info, struct nl_object *obj, int action);

/* Make sure these indexes match the cache_info array */
enum { CACHE_INFO_LINK, CACHE_INFO_ADDR, CACHE_INFO_NEIGH, CACHE_INFO_ROUTE, CACHE_INFO_MAX };

typedef struct {
    const char *name;       /**< name of cache entry */
    struct nl_cache *cache; /**< netlink cache entries */
    netlink_func_t func;    /**< function to cal to update/add netlink information */
} cache_info_t;

extern cache_info_t cache_info[];
extern int netlink_debug;

struct netlink_info {
    volatile int quit;          /**< Netlink quit flag for the thread monitoring netlink messages */
    stk_t *stk;                 /**< The stack instance pointer to be use to update information */
    pthread_t pid;              /**< The process ID from pthread_create() */
    struct nl_sock *sock;       /**< The socket instance pointer */
    struct nl_cache_mngr *mngr; /**< The netlink cache manager pointer */
};

#define CACHE_MAX_NAME_LENGTH 32

/**
 * @brief Find a cache information entry given the cache pointer.
 *
 * @param cache
 *   The netlink cache pointer.
 * @return
 *   NULL on failure or pointer to cache_info_t structure.
 */
static inline cache_info_t *
cache_find_by_ptr(struct nl_cache *cache)
{
    if (cache) {
        for (int i = 0; i < CACHE_INFO_MAX; i++)
            if (cache_info[i].cache == cache)
                return &cache_info[i];
    }
    return &cache_info[CACHE_INFO_MAX];
}

/**
 * @brief Find the cache information given the entry name
 *
 * @param name
 *   The name of the cache entry to locate.
 * @return
 *   NULL on failure or pointer to cache_info_t structure.
 */
static inline cache_info_t *
cache_find_by_name(const char *name)
{
    if (name) {
        for (int i = 0; i < CACHE_INFO_MAX; i++)
            if (!strncasecmp(cache_info[i].name, name, strnlen(name, CACHE_MAX_NAME_LENGTH)))
                return &cache_info[i];
    }
    return &cache_info[CACHE_INFO_MAX];
}

/**
 * @brief Find the cache_info_t entry given the index value.
 *
 * @param index
 *   The index value into the cache_info_t table.
 * @return
 *   NULL on failure or pointer to cache_info_t structure.
 */
static inline cache_info_t *
cache_find_by_index(int index)
{
    if (index < 0 || index > CACHE_INFO_MAX)
        index = CACHE_INFO_MAX;

    return &cache_info[index];
}

/**
 * @brief Internal function pointer to update cache_info_t structures.
 *
 * @param info
 *   The cache_info_t structure pointer to update.
 * @param obj
 *   The netlink object pointer to be used to update the cache_info_t structure.
 * @param action
 *   The type of action to perform on a cache_info_t structure.
 * @return
 *   N/A
 */
void __nl_link(struct netlink_info *info, struct nl_object *obj, int action);
void __nl_addr(struct netlink_info *info, struct nl_object *obj, int action);
void __nl_route(struct netlink_info *info, struct nl_object *obj, int action);
void __nl_neigh(struct netlink_info *info, struct nl_object *obj, int action);

#ifdef __cplusplus
}
#endif

#endif /* __NETLINK_PRIVATE_H */
