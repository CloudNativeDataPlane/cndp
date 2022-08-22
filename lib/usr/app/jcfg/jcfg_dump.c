/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <json-c/json_object.h>        // for json_object_get_type, json_object_ar...
#include <json-c/json_util.h>          // for json_type_to_name
#include <json-c/json_visit.h>         // for json_c_visit, JSON_C_VISIT_SECOND
#include <stdio.h>                     // for printf, NULL, size_t

#include "jcfg.h"                // for jcfg_info_t, jcfg_object_by_name
#include "jcfg_private.h"        // for jcfg
#include "cne_common.h"          // for __cne_unused
#include "cne_log.h"             // for CNE_LOG_WARNING, CNE_WARN

struct json_object;

static int ident;

static int
_walk_objects(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
              const char *key, size_t *index __cne_unused, void *arg __cne_unused)
{
    enum json_type type;
    const char *str;

    type = json_object_get_type(obj);
    str  = json_type_to_name(type);

    if ((type == json_type_object || type == json_type_array) && flags != JSON_C_VISIT_SECOND) {
        cne_printf("%*s>>> %s : '%s'", ident, "", key ? "Key " : "Type", key ? key : str);
        if (type == json_type_array)
            cne_printf(" Array Length: %ld", json_object_array_length(obj));
        cne_printf("\n");
        ident += 2;
    } else if ((type == json_type_object || type == json_type_array) &&
               flags == JSON_C_VISIT_SECOND) {
        ident -= 2;
        cne_printf("%*s<<< %s : '%s'\n", ident, "", key ? "Key " : "Type", key ? key : str);
    } else {
        if (key)
            cne_printf("%*s'%-10s' = ", ident, "", key);
        else
            cne_printf("%*s<%-10s> = ", ident, "", str);
        // clang-format off
        switch(type) {
        case json_type_null:    cne_printf("Null Object"); break;
        case json_type_boolean: cne_printf("%s", json_object_get_boolean(obj)? "true" : "false"); break;
        case json_type_double:  cne_printf("%g", json_object_get_double(obj)); break;
        case json_type_int:     cne_printf("%d", json_object_get_int(obj)); break;
        case json_type_string:  cne_printf("'%s'", json_object_get_string(obj)); break;

        case json_type_object:  cne_printf("Object"); break;
        case json_type_array:   cne_printf("Array[%ld]", json_object_array_length(obj)); break;
        }
        // clang-format on
        cne_printf("\n");
    }

    return JSON_C_VISIT_RETURN_CONTINUE;
}

int
jcfg_dump_object(struct json_object *obj)
{
    if (!obj)
        return -1;

    cne_printf("** Start: Type: '%s'\n", json_type_to_name(json_object_get_type(obj)));

    ident += 2;
    if (json_c_visit(obj, 0, _walk_objects, NULL))
        return -1;
    ident -= 2;

    cne_printf("** Finish: Type: '%s'\n\n", json_type_to_name(json_object_get_type(obj)));

    return 0;
}

int
jcfg_dump_at(jcfg_info_t *jinfo, const char *key)
{
    struct json_object *obj;

    obj = jcfg_object_by_name(jinfo, key);
    if (!obj) {
        CNE_WARN("Unable to locate '%s'\n", key);
        return -1;
    }

    return jcfg_dump_object(obj);
}

int
jcfg_dump(jcfg_info_t *jinfo)
{
    struct jcfg *cfg;

    if (!jinfo || !jinfo->cfg)
        return -1;
    cfg = jinfo->cfg;

    return jcfg_dump_object(cfg->root);
}
