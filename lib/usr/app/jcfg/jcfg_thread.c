/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <string.h>                    // for strdup, strchr
#include <json-c/json_object.h>        // for json_object_get_string, json_object_...
#include <json-c/json_visit.h>         // for json_c_visit, JSON_C_VISIT_RETURN_CO...
#include <stdio.h>                     // for size_t, NULL
#include <stdlib.h>                    // for calloc, free, realloc
#include <strings.h>                   // for strcasecmp
#include <sys/queue.h>                 // for STAILQ_INSERT_TAIL

#include "jcfg.h"                // for jcfg_thd_t, jcfg_info_t, jcfg_data_t
#include "jcfg_private.h"        // for jcfg
#include "jcfg_decode.h"         // for jcfg_list_add, _decode_threads
#include "cne_common.h"          // for __cne_unused
#include "cne_log.h"             // for CNE_LOG_ERR, CNE_ERR, CNE_ERR_RET

struct json_object;

jcfg_thd_t *
jcfg_thd_by_index(jcfg_info_t *jinfo, int idx)
{
    jcfg_data_t *data;
    jcfg_list_t *lst;

    if (!jinfo)
        return NULL;
    data = jinfo->cfg;
    lst  = &data->thd_list;

    return (jcfg_thd_t *)((idx < lst->cnt) ? lst->list[idx] : NULL);
}

static int
_thd(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
     const char *key __cne_unused, size_t *index __cne_unused, void *arg)
{
    jcfg_thd_t *thd = arg;
    int ret         = JSON_C_VISIT_RETURN_CONTINUE;

    if (!key || flags == JSON_C_VISIT_SECOND)
        return ret;

    if (json_object_is_type(obj, json_type_string)) {
        if (!strcasecmp(key, "group")) {
            if (thd->group_name)
                free(thd->group_name);
            thd->group_name = strdup(json_object_get_string(obj));
        } else if (!strcasecmp(key, "description"))
            thd->desc = strdup(json_object_get_string(obj));
    } else if (json_object_is_type(obj, json_type_array)) {
        if (!strcasecmp(key, "lports")) {
            int arrlen = json_object_array_length(obj);

            for (int i = 0; i < arrlen; i++) {
                struct json_object *val = json_object_array_get_idx(obj, i);

                if ((thd->lport_cnt + 1) >= thd->lport_sz) {
                    thd->lport_sz++;
                    thd->lport_names = realloc(thd->lport_names, thd->lport_sz * sizeof(char *));
                    if (!thd->lport_names)
                        CNE_ERR_RET("realloc returned null - thd->lport_names is null pointer\n");
                }
                thd->lport_names[thd->lport_cnt++] = strdup(json_object_get_string(val));
            }
            thd->lports = calloc(thd->lport_sz, sizeof(void *));
        }
    } else
        ret = JSON_C_VISIT_RETURN_ERROR;

    return ret;
}

static int
_thd_obj(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
         const char *key, size_t *index __cne_unused, void *arg)
{
    jcfg_info_t *jinfo = arg;
    enum json_type type;
    int ret = JSON_C_VISIT_RETURN_CONTINUE;

    if (flags == JSON_C_VISIT_SECOND)
        return ret;

    type = json_object_get_type(obj);

    if (key && type == json_type_object) {
        struct jcfg *cfg  = jinfo->cfg;
        jcfg_data_t *data = &cfg->data;
        jcfg_thd_t *thd;

        thd = calloc(1, sizeof(jcfg_thd_t));
        if (thd) {
            char *p = strchr(key, ':');
            int idx;

            thd->cbtype      = JCFG_THREAD_TYPE;
            thd->name        = strdup(key);
            thd->group_name  = strdup("default");
            thd->thread_type = strdup(key);
            if (p && thd->thread_type)
                thd->thread_type[p - key] = '\0';

            idx = jcfg_list_add(&data->thd_list, thd);
            if (idx < 0)
                CNE_ERR_RET("Failed to add thread object to list\n");
            thd->idx = idx;

            ret = json_c_visit(obj, 0, _thd, thd);

            if (ret == JSON_C_VISIT_RETURN_CONTINUE) {
                STAILQ_INSERT_TAIL(&data->threads, thd, next);
                data->thread_count++;
                if (jinfo->flags & JCFG_DEBUG_DECODING) {
                    cne_printf("   '[cyan]%-10s[]': [green]group[]: '[magenta]%-10s[]', "
                               "[green]lports[] [magenta]%d[] [ ",
                               thd->name, thd->group_name, thd->lport_cnt);
                    for (int i = 0; i < thd->lport_cnt; i++)
                        cne_printf("'[magenta]%s[]' ", thd->lport_names[i]);
                    cne_printf("], [green]desc[]:'[yellow]%s[]'\n", thd->desc);
                }
            } else
                free(thd);
        } else
            ret = JSON_C_VISIT_RETURN_ERROR;
    }
    return ret;
}

int
_decode_threads(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
                const char *key __cne_unused, size_t *index __cne_unused, void *arg)
{
    jcfg_info_t *jinfo = arg;
    enum json_type type;
    int ret;

    if (flags == JSON_C_VISIT_SECOND)
        return JSON_C_VISIT_RETURN_CONTINUE;

    type = json_object_get_type(obj);

    if (type != json_type_object)
        return JSON_C_VISIT_RETURN_ERROR;

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("[magenta]%s[]: {\n", key);

    ret = json_c_visit(obj, 0, _thd_obj, jinfo);
    if (ret == JSON_C_VISIT_RETURN_ERROR)
        CNE_ERR("Parsing thread failed\n");

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("}\n");

    return ret ? ret : JSON_C_VISIT_RETURN_SKIP;
}
