/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <string.h>                    // for strdup
#include <json-c/json_object.h>        // for json_object_get_type
#include <json-c/json_visit.h>         // for JSON_C_VISIT_RETURN_ERROR, json_c_visit
#include <stdio.h>                     // for size_t, NULL
#include <stdlib.h>                    // for calloc, free
#include <sys/queue.h>                 // for STAILQ_INSERT_TAIL

#include "jcfg.h"                // for jcfg_opt_t, jcfg_info_t, jcfg_data_t
#include "jcfg_private.h"        // for jcfg
#include "jcfg_print.h"          // for __print_application
#include "jcfg_decode.h"         // for __decode_object, _decode_application
#include "cne_common.h"          // for __cne_unused
#include "cne_log.h"             // for CNE_ERR, CNE_LOG_ERR

struct json_object;

static int
_app_print(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_opt_t *opt = obj;

    __print_application(obj, &opt->val);

    return 0;
}

static int
_app_obj(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
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
        jcfg_opt_t *app;

        app = calloc(1, sizeof(jcfg_opt_t));
        if (app) {
            app->cbtype = JCFG_APPLICATION_TYPE;
            app->name   = strdup(key);

            ret = __decode_object(&app->val, obj, type);
            if (ret == JSON_C_VISIT_RETURN_ERROR) {
                free(app->name);
                free(app);
            } else {
                STAILQ_INSERT_TAIL(&data->application, app, next);
                data->app_count++;
            }
        } else
            ret = JSON_C_VISIT_RETURN_ERROR;
    }
    return ret;
}

int
_decode_application(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
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

    ret = json_c_visit(obj, 0, _app_obj, jinfo);
    if (ret == JSON_C_VISIT_RETURN_ERROR)
        CNE_ERR("Parsing options failed\n");

    if (jinfo->flags & JCFG_DEBUG_DECODING) {
        jcfg_application_foreach(jinfo, _app_print, NULL);
        cne_printf("}\n");
    }

    return ret ? ret : JSON_C_VISIT_RETURN_SKIP;
}
