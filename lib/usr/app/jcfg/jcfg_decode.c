/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <string.h>                    // for strcmp, NULL, strdup, size_t
#include <json-c/json_object.h>        // for json_object_get_type, json_object_ar...
#include <json-c/json_visit.h>         // for json_c_visit_userfunc, JSON_C_VISIT_...
#include <strings.h>                   // for strcasecmp
#include <sys/queue.h>                 // for STAILQ_FOREACH, STAILQ_ENTRY, STAILQ...
#include <stdlib.h>                    // for calloc, free

#include "jcfg.h"                // for obj_value_t, jcfg_data, jcfg_thd_t
#include "jcfg_private.h"        // for jcfg
#include "jcfg_decode.h"
#include "cne_log.h"           // for CNE_LOG_ERR, CNE_ERR, CNE_ERR_RET
#include "cne_common.h"        // for CNE_INIT_PRIO, CNE_PRIORITY_STATE

struct json_object;

/**
 * The data to hold the section and function pointer for each section decoder.
 */
struct jcfg_decoder {
    STAILQ_ENTRY(jcfg_decoder) next;
    const char *section;
    json_c_visit_userfunc *func;
};

/**
 * Set of decoders defined as the default decoders. These entries are allocated
 * for each new section decoder. It is a simple allocator finding the first free
 * entry.
 */
static STAILQ_HEAD(, jcfg_decoder) decoder_head;

#define _foreach(_t, _h)                          \
    do {                                          \
        _t *obj;                                  \
                                                  \
        STAILQ_FOREACH (obj, _h, next) {          \
            if (func(jinfo, obj, arg, idx++) < 0) \
                return -1;                        \
        }                                         \
    } while (0)

int
jcfg_object_foreach(jcfg_info_t *jinfo, jcfg_cb_type_t cbtype, jcfg_cb_t *func, void *arg)
{
    struct jcfg *cfg;
    int idx = 0;

    if (!jinfo)
        return -1;
    cfg = jinfo->cfg;

    // clang-format off
    switch(cbtype) {
    case JCFG_APPLICATION_TYPE:
        _foreach(jcfg_opt_t, &cfg->data.application);
        break;
    case JCFG_DEFAULT_TYPE:
        _foreach(jcfg_opt_t, &cfg->data.defaults);
        break;
    case JCFG_OPTION_TYPE:
        _foreach(jcfg_opt_t, &cfg->data.options);
        break;
    case JCFG_UMEM_TYPE:
        _foreach(jcfg_umem_t, &cfg->data.umems);
        break;
    case JCFG_LPORT_TYPE:
        _foreach(jcfg_lport_t, &cfg->data.lports);
        break;
    case JCFG_LGROUP_TYPE:
        _foreach(jcfg_lgroup_t, &cfg->data.lgroups);
        break;
    case JCFG_THREAD_TYPE:
        _foreach(jcfg_thd_t, &cfg->data.threads);
        break;
    case JCFG_LPORT_GROUP_TYPE:
        _foreach(jcfg_lport_group_t, &cfg->data.lport_groups);
        break;
    case JCFG_USER_TYPE:
        _foreach(jcfg_user_t, &cfg->data.users);
        break;
    default:
        return -1;
    }
    // clang-format on

    return 0;
}

#define _search_foreach(_t, _h)           \
    do {                                  \
        _t *obj;                          \
                                          \
        STAILQ_FOREACH (obj, _h, next) {  \
            if (!strcmp(name, obj->name)) \
                return obj;               \
        }                                 \
    } while (0)

void *
jcfg_object_lookup(jcfg_info_t *jinfo, jcfg_cb_type_t cbtype, const char *name)
{
    struct jcfg *cfg;

    if (!jinfo)
        return NULL;
    cfg = jinfo->cfg;

    // clang-format off
    switch(cbtype) {
    case JCFG_APPLICATION_TYPE:
        _search_foreach(jcfg_opt_t, &cfg->data.application);
        break;
    case JCFG_DEFAULT_TYPE:
        _search_foreach(jcfg_opt_t, &cfg->data.defaults);
        break;
    case JCFG_OPTION_TYPE:
        _search_foreach(jcfg_opt_t, &cfg->data.options);
        break;
    case JCFG_UMEM_TYPE:
        _search_foreach(jcfg_umem_t, &cfg->data.umems);
        break;
    case JCFG_LPORT_TYPE:
        _search_foreach(jcfg_lport_t, &cfg->data.lports);
        break;
    case JCFG_LGROUP_TYPE:
        _search_foreach(jcfg_lgroup_t, &cfg->data.lgroups);
        break;
    case JCFG_THREAD_TYPE:
        _search_foreach(jcfg_thd_t, &cfg->data.threads);
        break;
    case JCFG_LPORT_GROUP_TYPE:
        _search_foreach(jcfg_lport_group_t, &cfg->data.lport_groups);
        break;
    case JCFG_USER_TYPE:
        _search_foreach(jcfg_user_t, &cfg->data.users);
        break;
    default:
        return NULL;
    }
    // clang-format on

    return NULL;
}

int
__decoder_val_get(obj_value_t *val, uint64_t *v)
{
    if (!val || !v)
        return -1;

    switch (val->type) {
    case BOOLEAN_OPT_TYPE:
        *(int *)v = val->boolean;
        return BOOLEAN_OPT_TYPE;
    case STRING_OPT_TYPE:
        *(char **)v = val->str;
        return STRING_OPT_TYPE;
    case INTEGER_OPT_TYPE:
        *(int64_t *)v = val->value;
        return INTEGER_OPT_TYPE;
    case ARRAY_OPT_TYPE:
        return -1;
    case OBJECT_OPT_TYPE:
        return -1;
    default:
        return -1;
    }
    return 0;
}

int
__decoder_array_val_get(obj_value_t *val, obj_value_t **arr)
{
    if (!val || !arr)
        return -1;

    *arr = val;
    if (val->type == ARRAY_OPT_TYPE) {
        if (val->array_sz == 0)
            return ARRAY_OPT_TYPE;

        switch (val->arr[0]->type) {
        case BOOLEAN_OPT_TYPE:
            return BOOLEAN_OPT_TYPE;
        case STRING_OPT_TYPE:
            return STRING_OPT_TYPE;
        case INTEGER_OPT_TYPE:
            return INTEGER_OPT_TYPE;
        case ARRAY_OPT_TYPE:
            return -1;
        case OBJECT_OPT_TYPE:
            return -1;
        default:
            break;
        }
    }

    return -1;
}

int
__decode_object(obj_value_t *val, struct json_object *obj, enum json_type type)
{
    switch (type) {
    case json_type_string:
        val->str  = strdup(json_object_get_string(obj));
        val->type = STRING_OPT_TYPE;
        break;
    case json_type_int:
        val->value = json_object_get_int64(obj);
        val->type  = INTEGER_OPT_TYPE;
        break;
    case json_type_boolean:
        val->boolean = json_object_get_boolean(obj);
        val->type    = BOOLEAN_OPT_TYPE;
        break;
    case json_type_array:
        /* Get some array info*/
        val->array_sz = json_object_array_length(obj);
        val->type     = ARRAY_OPT_TYPE;

        /* Assume all objects in the array are of the same type */
        type = json_object_get_type(json_object_array_get_idx(obj, 0));

        /* Allocate the array of obj_value_t pointers*/
        val->arr = calloc(val->array_sz, sizeof(obj_value_t *));

        /* Populate the array */
        for (int i = 0; i < val->array_sz; i++) {
            struct json_object *aval = json_object_array_get_idx(obj, i);

            if (type != json_object_get_type(aval)) {
                CNE_ERR("Parsing objects array field failed - multiple types in array\n");
                free(val->arr);
                return JSON_C_VISIT_RETURN_ERROR;
            }

            val->arr[i] = calloc(1, sizeof(obj_value_t));
            __decode_object(val->arr[i], aval, type);
        }
        break;
    case json_type_object:
        val->type = OBJECT_OPT_TYPE;
        break;
    default:
        CNE_ERR("Parsing field failed - type is not supported\n");
        return JSON_C_VISIT_RETURN_ERROR;
    }

    return JSON_C_VISIT_RETURN_CONTINUE;
}

static int
_decode_sections_start(struct json_object *obj, int flags, struct json_object *parent,
                       const char *key, size_t *index, void *arg)
{
    json_c_visit_userfunc *func = NULL;
    enum json_type type;
    int ret = JSON_C_VISIT_RETURN_CONTINUE;

    type = json_object_get_type(obj);

    if (flags == JSON_C_VISIT_SECOND)
        return ret;

    if (key && type == json_type_object)
        func = jcfg_get_decoder(key);

    if (func) {
        ret = func(obj, flags, parent, key, index, arg);
        if (ret == JSON_C_VISIT_RETURN_ERROR)
            CNE_ERR("Failed to decode '%s'\n", key);
    }

    return ret;
}

static int
_decode_sections_end(jcfg_info_t *jinfo, void *arg)
{
    struct jcfg *cfg;
    jcfg_data_t *data;
    jcfg_lport_t *lport;
    jcfg_thd_t *thd;

    if (!jinfo || !(cfg = jinfo->cfg))
        return -1;

    data = &cfg->data;
    STAILQ_FOREACH (lport, &data->lports, next) {
        lport->umem = jcfg_lookup_umem(jinfo, lport->umem_name);
        if (!lport->umem) {
            CNE_ERR("UMEM '%s' not found\n", lport->umem_name);
            return -1;
        }
    }
    STAILQ_FOREACH (thd, &data->threads, next) {
        thd->group = jcfg_lookup_lgroup(jinfo, thd->group_name);
        if (!thd->group) {
            CNE_ERR("Group '%s' not found\n", thd->group_name);
            return -1;
        }
        for (int i = 0; i < thd->lport_cnt; i++) {
            thd->lports[i] = jcfg_lookup_lport(jinfo, thd->lport_names[i]);
            if (!thd->lports[i]) {
                CNE_ERR("lport '%s' not found\n", thd->lport_names[i]);
                return -1;
            }
        }
    }

    return jcfg_decode_lport_groups_end(jinfo, arg);
}

int
jcfg_decode(jcfg_info_t *jinfo, const char *key, void *arg)
{
    struct jcfg *cfg;
    struct json_object *obj;
    int ret;

    if (!jinfo || !(cfg = jinfo->cfg))
        return -1;

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("[yellow]>>>>> [green]Decode JCFG sections[]\n");

    obj = (key) ? jcfg_object_by_name(jinfo, key) : cfg->root;
    if (!obj)
        CNE_ERR_RET("Unable to locate '%s'\n", key);

    if (!arg)
        arg = jinfo;

    ret = json_c_visit(obj, 0, _decode_sections_start, arg);
    if (ret == JSON_C_VISIT_RETURN_ERROR)
        return -1;

    ret = _decode_sections_end(jinfo, arg);

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("[yellow]>>>>> [green]Done Decoding JCFG sections[]\n\n");

    return ret;
}

static struct jcfg_decoder *
_decoder_alloc(const char *section, json_c_visit_userfunc *func)
{
    struct jcfg_decoder *d;

    d = calloc(1, sizeof(struct jcfg_decoder));
    if (d) {
        d->section = section;
        d->func    = func;
    }

    return d;
}

json_c_visit_userfunc *
jcfg_get_decoder(const char *section)
{
    struct jcfg_decoder *d;

    if (!section)
        CNE_NULL_RET("section name is NULL\n");

    STAILQ_FOREACH (d, &decoder_head, next) {
        if (!strcasecmp(d->section, section))
            return d->func;
    }
    return NULL;
}

int
jcfg_add_decoder(const char *section, json_c_visit_userfunc *func)
{
    struct jcfg_decoder *d;

    if (!section || !func)
        CNE_ERR_RET("section or function is NULL\n");

    if (jcfg_get_decoder(section))
        CNE_ERR_RET("Decoder section '%s' already exists\n", section);

    d = _decoder_alloc(section, func);
    if (!d)
        CNE_ERR_RET("unable to allocate a empty decoder structure");

    STAILQ_INSERT_TAIL(&decoder_head, d, next);

    return 0;
}

int
jcfg_del_decoder(const char *section)
{
    struct jcfg_decoder *d;

    if (!section)
        CNE_ERR_RET("section name is NULL\n");

    STAILQ_FOREACH (d, &decoder_head, next) {
        if (d && !strcasecmp(d->section, section)) {
            STAILQ_REMOVE(&decoder_head, d, jcfg_decoder, next);
            free(d);
            return 0;
        }
    }
    return -1;
}

CNE_INIT_PRIO(jcfg_initialize, STATE)
{
    STAILQ_INIT(&decoder_head);

    jcfg_add_decoder(APP_TAG, _decode_application);
    jcfg_add_decoder(DEFAULT_TAG, _decode_defaults);
    jcfg_add_decoder(OPTION_TAG, _decode_options);
    jcfg_add_decoder(UMEM_TAG, _decode_umems);
    jcfg_add_decoder(LPORT_TAG, _decode_lports);
    jcfg_add_decoder(LGROUP_TAG, _decode_lgroups);
    jcfg_add_decoder(THREAD_TAG, _decode_threads);
    jcfg_add_decoder(LPORT_GROUP_TAG, _decode_lport_groups);
}
