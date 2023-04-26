/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation.
 * Copyright (c) 2014 6WIND S.A.
 */

#include <string.h>             // for strcmp, memset, strdup, strcspn, strpbrk
#include <stdlib.h>             // for NULL, strtol, strtoul, free, abs, malloc
#include <cne_strings.h>        // for cne_strtok
#include <errno.h>              // for EINVAL
#include <stdint.h>             // for int16_t, int32_t, int64_t, int8_t, uint16_t

#include "kvargs.h"
#include "cne_common.h"        // for __cne_unused

/**
 * Receive a string with a list of arguments following the pattern
 * key=value,key=value,... and insert them into the list.
 * strtok() is used so the params string will be copied to be modified.
 */
static int
kvargs_tokenize(struct kvargs *kvlist, const char *params)
{
    char *pairs[KVARGS_MAX] = {NULL};
    const char *delim       = KVARGS_PAIRS_DELIM_1;

    /* Grab a copy of the const string */
    kvlist->str = strdup(params);
    if (kvlist->str == NULL)
        return -1;

    /* If we have list or '[' in the text then use ';' instead of ',' delimiters */
    if (strpbrk(kvlist->str, "[]"))
        delim = KVARGS_PAIRS_DELIM_2;

    kvlist->count = cne_strtok(kvlist->str, delim, pairs, KVARGS_MAX);
    if (kvlist->count <= 0)
        return -1;

    memset(kvlist->pairs, 0, sizeof(kvlist->pairs));

    for (unsigned int i = 0; i < kvlist->count; i++) {
        char *pair[3];

        if (cne_strtok(pairs[i], KVARGS_KV_DELIM, pair, 3) != 2)
            return -1;

        kvlist->pairs[i].key   = pair[0];
        kvlist->pairs[i].value = pair[1];
    }

    return 0;
}

/**
 * Determine whether a key is valid or not by looking
 * into a list of valid keys.
 */
static int
is_valid_key(const char *const valid[], const char *key_match)
{
    const char *const *valid_ptr;

    for (valid_ptr = valid; *valid_ptr != NULL; valid_ptr++) {
        if (strcmp(key_match, *valid_ptr) == 0)
            return 1;
    }
    return 0;
}

/**
 * Determine whether all keys are valid or not by looking
 * into a list of valid keys.
 */
static int
check_for_valid_keys(struct kvargs *kvlist, const char *const valid[])
{
    unsigned i, ret;
    struct kvargs_pair *pair;

    for (i = 0; i < kvlist->count; i++) {
        pair = &kvlist->pairs[i];
        ret  = is_valid_key(valid, pair->key);
        if (!ret)
            return -1;
    }
    return 0;
}

/**
 * Return the number of times a given arg_name exists in the key/value list.
 * E.g. given a list = { rx = 0, rx = 1, tx = 2 } the number of args for
 * arg "rx" will be 2.
 */
unsigned
kvargs_count(const struct kvargs *kvlist, const char *key_match)
{
    const struct kvargs_pair *pair;
    unsigned i, ret;

    ret = 0;
    for (i = 0; i < kvlist->count; i++) {
        pair = &kvlist->pairs[i];
        if (key_match == NULL || strcmp(pair->key, key_match) == 0)
            ret++;
    }

    return ret;
}

static int
get_ptr(const char *key __cne_unused, const char *value, void *arg)
{
    char **ptr = arg;

    if (value == NULL || arg == NULL)
        return -EINVAL;

    *ptr = (char *)(uintptr_t)value;

    return 0;
}

static int
get_int8(const char *key __cne_unused, const char *value, void *arg)
{
    int8_t *i8 = arg;

    if (value == NULL || arg == NULL)
        return -EINVAL;

    *i8 = (int8_t)strtol(value, NULL, 0);

    return 0;
}

static int
get_int16(const char *key __cne_unused, const char *value, void *arg)
{
    int16_t *i16 = arg;

    if (value == NULL || arg == NULL)
        return -EINVAL;

    *i16 = (int16_t)strtol(value, NULL, 0);

    return 0;
}

static int
get_int32(const char *key __cne_unused, const char *value, void *arg)
{
    int32_t *i32 = arg;

    if (value == NULL || arg == NULL)
        return -EINVAL;

    *i32 = (int32_t)strtol(value, NULL, 0);

    return 0;
}

static int
get_int64(const char *key __cne_unused, const char *value, void *arg)
{
    int64_t *i64 = arg;

    if (value == NULL || arg == NULL)
        return -EINVAL;

    *i64 = (int64_t)strtol(value, NULL, 0);

    return 0;
}

static int
get_uint8(const char *key __cne_unused, const char *value, void *arg)
{
    uint8_t *u8 = arg;

    if (value == NULL || arg == NULL)
        return -EINVAL;

    *u8 = (uint8_t)strtoul(value, NULL, 0);

    return 0;
}

static int
get_uint16(const char *key __cne_unused, const char *value, void *arg)
{
    uint16_t *u16 = arg;

    if (value == NULL || arg == NULL)
        return -EINVAL;

    *u16 = (uint16_t)strtoul(value, NULL, 0);

    return 0;
}

static int
get_uint32(const char *key __cne_unused, const char *value, void *arg)
{
    uint32_t *u32 = arg;

    if (value == NULL || arg == NULL)
        return -EINVAL;

    *u32 = (uint32_t)strtoul(value, NULL, 0);

    return 0;
}

static int
get_uint64(const char *key __cne_unused, const char *value, void *arg)
{
    uint64_t *u64 = arg;

    if (value == NULL || arg == NULL)
        return -EINVAL;

    *u64 = (uint64_t)strtoul(value, NULL, 0);

    return 0;
}

/*
 * For each matching key, call the given handler function.
 */
int
kvargs_process(const struct kvargs *kvlist, const char *key_match, arg_handler_t handler,
               void *opaque_arg)
{
    const struct kvargs_pair *pair;
    unsigned i;

    if (kvlist == NULL)
        return 0;

    if (handler == NULL)
        return -1;

    for (i = 0; i < kvlist->count; i++) {
        pair = &kvlist->pairs[i];
        if (key_match == NULL || strcmp(pair->key, key_match) == 0) {
            if ((*handler)(pair->key, pair->value, opaque_arg) < 0)
                return -1;
        }
    }
    return 0;
}

int
kvargs_process_type(const struct kvargs *kvlist, const char *key_match, kvargs_type_t typ,
                    void *opaque_arg)
{
    arg_handler_t handler = NULL;

    if (kvlist == NULL)
        return 0;

    switch (typ) {
    case KVARGS_PTR:
        handler = get_ptr;
        break;
    case KVARGS_INT8:
        handler = get_int8;
        break;
    case KVARGS_UINT8:
        handler = get_uint8;
        break;
    case KVARGS_INT16:
        handler = get_int16;
        break;
    case KVARGS_UINT16:
        handler = get_uint16;
        break;
    case KVARGS_INT32:
        handler = get_int32;
        break;
    case KVARGS_UINT32:
        handler = get_uint32;
        break;
    case KVARGS_INT64:
        handler = get_int64;
        break;
    case KVARGS_UINT64:
        handler = get_uint64;
        break;
    default:
        return -1;
    }

    return kvargs_process(kvlist, key_match, handler, opaque_arg);
}

/* Free the kvargs structure */
void
kvargs_free(struct kvargs *kvlist)
{
    if (!kvlist)
        return;

    free(kvlist->str);
    free(kvlist);
}

/*
 * Parse the arguments "key=value,key=value,..." string and return
 * an allocated structure that contains a key/value list. Also
 * check if only valid keys were used.
 */
struct kvargs *
kvargs_parse(const char *args, const char *const valid_keys[])
{
    struct kvargs *kvlist;

    if (args == NULL || args[0] == '\0')
        return NULL;

    kvlist = malloc(sizeof(*kvlist));
    if (kvlist == NULL)
        return NULL;
    memset(kvlist, 0, sizeof(*kvlist));

    if (kvargs_tokenize(kvlist, args) < 0) {
        kvargs_free(kvlist);
        return NULL;
    }

    if (valid_keys != NULL && check_for_valid_keys(kvlist, valid_keys) < 0) {
        kvargs_free(kvlist);
        return NULL;
    }

    return kvlist;
}

struct kvargs *
kvargs_parse_delim(const char *args, const char *const valid_keys[], const char *valid_ends)
{
    struct kvargs *kvlist = NULL;
    char *copy;
    size_t len;

    if (valid_ends == NULL)
        return kvargs_parse(args, valid_keys);

    copy = strdup(args);
    if (copy == NULL)
        return NULL;

    len       = strcspn(copy, valid_ends);
    copy[len] = '\0';

    kvlist = kvargs_parse(copy, valid_keys);

    free(copy);
    return kvlist;
}

int
kvargs_strcmp(const char *key __cne_unused, const char *value, void *opaque)
{
    const char *str = opaque;

    return -abs(strcmp(str, value));
}
