/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation.
 * Copyright (c) 2014 6WIND S.A.
 */

#ifndef __KVARGS_H_
#define __KVARGS_H_

/**
 * @file
 *
 * CNE Argument parsing
 *
 * This module can be used to parse arguments whose format is
 * key1=value1;key2=value2;key3=value3;...
 *
 * The same key can appear several times with the same or a different
 * value. The arguments are stored as a list of key/values
 * associations and not as a dictionary.
 *
 * This file provides some helpers that are especially used by virtual
 * ethernet devices at initialization for arguments parsing.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KVARGS_PTR,
    KVARGS_INT8,
    KVARGS_UINT8,
    KVARGS_INT16,
    KVARGS_UINT16,
    KVARGS_INT32,
    KVARGS_UINT32,
    KVARGS_INT64,
    KVARGS_UINT64,
    KVARGS_LAST_TYPE
} kvargs_type_t;

/**
 * Maximum number of key/value associations
 */
#define KVARGS_MAX 64

/**
 * Separator characters used between each pair
 */
#define KVARGS_PAIRS_DELIM_1 ","
#define KVARGS_PAIRS_DELIM_2 ";"

/**
 * Separator character used between key and value
 */
#define KVARGS_KV_DELIM "="

/**
 * Type of callback function used by kvargs_process()
 */
typedef int (*arg_handler_t)(const char *key, const char *value, void *opaque);

/**
 * A key/value association
 */
struct kvargs_pair {
    char *key;   /**< the name (key) of the association  */
    char *value; /**< the value associated to that key */
};

/**
 * Store a list of key/value associations
 */
struct kvargs {
    char *str;                            /**< copy of the argument string */
    unsigned count;                       /**< number of entries in the list */
    struct kvargs_pair pairs[KVARGS_MAX]; /**< list of key/values */
};

/**
 * Allocate a kvargs and store key/value associations from a string
 *
 * The function allocates and fills a kvargs structure from a given
 * string whose format is key1=value1,key2=value2,...
 *
 * The structure can be freed with kvargs_free().
 *
 * @param args
 *   The input string containing the key/value associations
 * @param valid_keys
 *   A list of valid keys (table of const char *, the last must be NULL).
 *   This argument is ignored if NULL
 *
 * @return
 *   - A pointer to an allocated kvargs structure on success
 *   - NULL on error
 */
struct kvargs *kvargs_parse(const char *args, const char *const valid_keys[]);

/**
 * Allocate a kvargs and store key/value associations from a string.
 * This version will consider any byte from valid_ends as a possible
 * terminating character, and will not parse beyond any of their occurrence.
 *
 * The function allocates and fills an kvargs structure from a given
 * string whose format is key1=value1,key2=value2,...
 *
 * The structure can be freed with kvargs_free().
 *
 * @param args
 *   The input string containing the key/value associations
 *
 * @param valid_keys
 *   A list of valid keys (table of const char *, the last must be NULL).
 *   This argument is ignored if NULL
 *
 * @param valid_ends
 *   Acceptable terminating characters.
 *   If NULL, the behavior is the same as ``kvargs_parse``.
 *
 * @return
 *   - A pointer to an allocated kvargs structure on success
 *   - NULL on error
 */
struct kvargs *kvargs_parse_delim(const char *args, const char *const valid_keys[],
                                  const char *valid_ends);

/**
 * Free a kvargs structure
 *
 * Free a kvargs structure previously allocated with
 * kvargs_parse().
 *
 * @param kvlist
 *   The kvargs structure. No error if NULL.
 */
void kvargs_free(struct kvargs *kvlist);

/**
 * Call a handler function for each key/value matching the key
 *
 * For each key/value association that matches the given key, calls the
 * handler function with the for a given arg_name passing the value on the
 * dictionary for that key and a given extra argument.
 *
 * @param kvlist
 *   The kvargs structure. No error if NULL.
 * @param key_match
 *   The key on which the handler should be called, or NULL to process handler
 *   on all associations
 * @param handler
 *   The function to call for each matching key
 * @param opaque_arg
 *   A pointer passed unchanged to the handler
 *
 * @return
 *   - 0 on success
 *   - A negative value on error
 */
int kvargs_process(const struct kvargs *kvlist, const char *key_match, arg_handler_t handler,
                   void *opaque_arg);

/**
 * Process the kvargs by type of k/v pair
 *
 * @param kvlist
 *   The kvargs structure. No error if NULL.
 * @param key_match
 *   The key on which the handler should be called, or NULL to process handler
 *   on all associations
 * @param typ
 *   parse based on the type of argument
 * @param opaque_arg
 *   A pointer passed unchanged to the handler
 *
 * @return
 *   - 0 on success
 *   - A negative value on error
 */
int kvargs_process_type(const struct kvargs *kvlist, const char *key_match, kvargs_type_t typ,
                        void *opaque_arg);

/**
 * Helper routine to parse and return a pointer value
 */
static inline int
kvargs_ptr(const struct kvargs *kv, const char *key, void *arg)
{
    return kvargs_process_type(kv, key, KVARGS_PTR, arg);
}

/**
 * Helper routine to parse and return a int8 value
 */
static inline int
kvargs_int8(const struct kvargs *kv, const char *key, void *arg)
{
    return kvargs_process_type(kv, key, KVARGS_INT8, arg);
}

/**
 * Helper routine to parse and return a uint8 value
 */
static inline int
kvargs_uint8(const struct kvargs *kv, const char *key, void *arg)
{
    return kvargs_process_type(kv, key, KVARGS_UINT8, arg);
}

/**
 * Helper routine to parse and return a int16 value
 */
static inline int
kvargs_int16(const struct kvargs *kv, const char *key, void *arg)
{
    return kvargs_process_type(kv, key, KVARGS_INT16, arg);
}

/**
 * Helper routine to parse and return a uint16 value
 */
static inline int
kvargs_uint16(const struct kvargs *kv, const char *key, void *arg)
{
    return kvargs_process_type(kv, key, KVARGS_UINT16, arg);
}

/**
 * Helper routine to parse and return a int32 value
 */
static inline int
kvargs_int32(const struct kvargs *kv, const char *key, void *arg)
{
    return kvargs_process_type(kv, key, KVARGS_INT32, arg);
}

/**
 * Helper routine to parse and return a uint32 value
 */
static inline int
kvargs_uint32(const struct kvargs *kv, const char *key, void *arg)
{
    return kvargs_process_type(kv, key, KVARGS_UINT32, arg);
}

/**
 * Helper routine to parse and return a int64 value
 */
static inline int
kvargs_int64(const struct kvargs *kv, const char *key, void *arg)
{
    return kvargs_process_type(kv, key, KVARGS_INT64, arg);
}

/**
 * Helper routine to parse and return a uint64 value
 */
static inline int
kvargs_uint64(const struct kvargs *kv, const char *key, void *arg)
{
    return kvargs_process_type(kv, key, KVARGS_UINT64, arg);
}

/**
 * Count the number of associations matching the given key
 *
 * @param kvlist
 *   The kvargs structure
 * @param key_match
 *   The key that should match, or NULL to count all associations
 * @return
 *   The number of entries
 */
unsigned kvargs_count(const struct kvargs *kvlist, const char *key_match);

/**
 * Generic kvarg handler for string comparison.
 *
 * This function can be used for a generic string comparison processing
 * on a list of kvargs.
 *
 * @param key
 *   kvarg pair key.
 *
 * @param value
 *   kvarg pair value.
 *
 * @param opaque
 *   Opaque pointer to a string.
 *
 * @return
 *   0 if the strings match.
 *   !0 otherwise or on error.
 *
 *   Unless strcmp, comparison ordering is not kept.
 *   In order for kvargs_process to stop processing on match error,
 *   a negative value is returned even if strcmp had returned a positive one.
 */
int kvargs_strcmp(const char *key, const char *value, void *opaque);

#ifdef __cplusplus
}
#endif

#endif
