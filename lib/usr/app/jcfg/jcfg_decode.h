/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _JCFG_DECODE_H_
#define _JCFG_DECODE_H_

/**
 * @file
 * The internal decode APIs and defines for JCFG.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <sys/queue.h>
#include <pthread.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>
#include <json-c/json_visit.h>
#include <json-c/linkhash.h>
#include <stddef.h>        // for size_t
#include <stdint.h>        // for uint64_t

#include "jcfg.h"        // for obj_value_t, jcfg_list_t

struct json_object;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Add an object pointer to a jcfg_list_t structure
 *
 * The jcfg_list_t.list array uses realloc() to grow the list as needed.
 *
 * @param lst
 *   The pointer to a jcfg_list_ structure
 * @param obj
 *   The object pointer to add to the list array.
 * @return
 *   -1 on error or 0 - N for the location of the object in the array.
 */
int jcfg_list_add(jcfg_list_t *lst, void *obj);

/**
 * Decode the default,umem,lport, ... sections in the JSON file (private or internal)
 *
 * These are private functions and each supports the different sections in the JSON file format.
 *
 * @param obj
 *   The json object to decode from JSON object
 * @param flags
 *   The flags used by the JSON-C parser
 * @param parent
 *   The JSON-C parent of this object.
 * @param key
 *   The pointer to the key value of the JSON object
 * @param index
 *   The new index value returned from JSON parsing to be placed in this index pointer location
 * @param arg
 *   The user supplied argument to be passed to the callback routines
 * @return
 *   The JSON parsing flags are returned, including OK and error
 */
int _decode_defaults(struct json_object *obj, int flags, struct json_object *parent,
                     const char *key, size_t *index, void *arg);
int _decode_lports(struct json_object *obj, int flags, struct json_object *parent, const char *key,
                   size_t *index, void *arg);
int _decode_umems(struct json_object *obj, int flags, struct json_object *parent, const char *key,
                  size_t *index, void *arg);
int _decode_lgroups(struct json_object *obj, int flags, struct json_object *parent, const char *key,
                    size_t *index, void *arg);
int _decode_threads(struct json_object *obj, int flags, struct json_object *parent, const char *key,
                    size_t *index, void *arg);
int _decode_lport_groups(struct json_object *obj, int flags, struct json_object *parent,
                         const char *key, size_t *index, void *arg);
int _decode_application(struct json_object *obj, int flags, struct json_object *parent,
                        const char *key, size_t *index, void *arg);
int _decode_options(struct json_object *obj, int flags, struct json_object *parent, const char *key,
                    size_t *index, void *arg);

/** Finish lport_group decoding after all sections have been decoded
 *
 * This function creates logical ports and assigns them to threads, which can
 * only be done after all other sections have been decoded.
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param arg
 *   The user supplied argument (currently unused)
 * @return
 *   0 on success or -1 on error
 */
int jcfg_decode_lport_groups_end(jcfg_info_t *jinfo, void *arg);

/**
 * Decoder value get routine for scalar object.
 *
 * @param val
 *   The obj_value_t pointer to extract the value into 'v' return pointer.
 * @param v
 *   The location to put the returned object value.
 * @return
 *   0 on success or -1 on error
 */
int __decoder_val_get(obj_value_t *val, uint64_t *v);

/**
 * Decoder value get routine for array object.
 *
 * @param val
 *   The obj_value_t pointer to extract the values into 'arr' return pointer.
 * @param arr
 *   The location to put the array of returned object values.
 * @return
 *   0 on success or -1 on error
 */
int __decoder_array_val_get(obj_value_t *val, obj_value_t **arr);

/**
 * Decode a common object given its type and value.
 *
 * @param val
 *   The object value pointer to decode the object from JSON to JCFG
 * @param obj
 *   The JSON object to decode
 * @param type
 *   The type of JSON object to decode
 * @return
 *   0 on success or -1 on error
 */
int __decode_object(obj_value_t *val, struct json_object *obj, enum json_type type);

#ifdef __cplusplus
}
#endif

#endif /* _JCFG_DECODE_H_ */
