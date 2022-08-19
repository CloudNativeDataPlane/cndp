/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <string.h>                    // for strdup
#include <json-c/json_object.h>        // for json_object_get_type
#include <json-c/json_visit.h>         // for JSON_C_VISIT_RETURN_ERROR, json_c_visit
#include <stdint.h>                    // for uint64_t
#include <stdio.h>                     // for size_t, NULL
#include <stdlib.h>                    // for calloc, free
#include <strings.h>                   // for strcasecmp
#include <sys/queue.h>                 // for STAILQ_FOREACH, STAILQ_INSERT_TAIL

#include "jcfg.h"                // for jcfg_opt_t, jcfg_info_t, jcfg_data_t
#include "jcfg_private.h"        // for jcfg
#include "jcfg_print.h"          // for __print_object
#include "jcfg_decode.h"         // for __decode_object, __decoder_array_val...
#include "cne_common.h"          // for __cne_unused
#include "cne_log.h"             // for CNE_ERR, CNE_LOG_ERR

struct json_object;

static int
_default_print(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_opt_t *opt = obj;

    __print_object(obj, &opt->val);

    return 0;
}

int
jcfg_default_get(jcfg_info_t *jinfo, const char *name, uint64_t *val)
{
    struct jcfg *cfg;
    jcfg_opt_t *def;

    if (!name || !val || !jinfo || !jinfo->cfg)
        return -1;

    cfg = jinfo->cfg;
    STAILQ_FOREACH (def, &cfg->data.defaults, next) {
        if (!strcasecmp(name, def->name))
            return __decoder_val_get(&def->val, val);
    }

    return -1;
}

int
jcfg_default_array_get(jcfg_info_t *jinfo, const char *name, obj_value_t **val_arr)
{
    struct jcfg *cfg;
    jcfg_opt_t *opt;

    if (!name || !val_arr || !jinfo || !jinfo->cfg)
        return -1;

    cfg = jinfo->cfg;
    STAILQ_FOREACH (opt, &cfg->data.defaults, next) {
        if (!strcasecmp(name, opt->name))
            return __decoder_array_val_get(&opt->val, val_arr);
    }

    return -1;
}

static int
__default_objs(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
               const char *key, size_t *index __cne_unused, void *arg)
{
    jcfg_info_t *jinfo = arg;
    enum json_type type;
    int ret = JSON_C_VISIT_RETURN_CONTINUE;

    if (flags == JSON_C_VISIT_SECOND)
        return ret;

    type = json_object_get_type(obj);

    if (key) {
        struct jcfg *cfg  = jinfo->cfg;
        jcfg_data_t *data = &cfg->data;
        jcfg_opt_t *def;

        def = calloc(1, sizeof(jcfg_opt_t));
        if (def) {
            def->cbtype = JCFG_DEFAULT_TYPE;
            def->name   = strdup(key);

            ret = __decode_object(&def->val, obj, type);
            if (ret == JSON_C_VISIT_RETURN_ERROR) {
                free(def->name);
                free(def);
            } else {
                STAILQ_INSERT_TAIL(&data->defaults, def, next);
                data->default_count++;
            }
        } else
            ret = JSON_C_VISIT_RETURN_ERROR;
    }
    return ret;
}

int
_decode_defaults(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
                 const char *key __cne_unused, size_t *index __cne_unused, void *arg)
{
    enum json_type type;
    jcfg_info_t *jinfo = arg;
    int ret;

    if (flags == JSON_C_VISIT_SECOND)
        return JSON_C_VISIT_RETURN_CONTINUE;

    type = json_object_get_type(obj);

    if (type != json_type_object)
        return JSON_C_VISIT_RETURN_ERROR;

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("[magenta]%s[]: {\n", key);

    ret = json_c_visit(obj, 0, __default_objs, jinfo);
    if (ret == JSON_C_VISIT_RETURN_ERROR)
        CNE_ERR("Unable to parse defaults\n");

    if (jinfo->flags & JCFG_DEBUG_DECODING) {
        jcfg_defaults_foreach(jinfo, _default_print, NULL);
        cne_printf("}\n");
    }

    return ret ? ret : JSON_C_VISIT_RETURN_SKIP;
}
