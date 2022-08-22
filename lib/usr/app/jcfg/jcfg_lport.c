/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <string.h>                    // for strcmp, strdup, strchr
#include <json-c/json_object.h>        // for json_object_get_string, json_object_...
#include <json-c/json_visit.h>         // for json_c_visit, JSON_C_VISIT_RETURN_CO...
#include <stdlib.h>                    // for NULL, calloc, free, size_t
#include <sys/queue.h>                 // for STAILQ_INSERT_TAIL
#include <stdint.h>                    // for uint32_t

#include "jcfg.h"                // for jcfg_lport_t, jcfg_info_t, jcfg_data_t
#include "jcfg_private.h"        // for jcfg
#include "jcfg_decode.h"         // for jcfg_list_add, _decode_lports
#include "cne_common.h"          // for __cne_unused
#include "cne_log.h"             // for CNE_LOG_ERR, CNE_ERR, CNE_ERR_RET
#include "cne_strings.h"
#include "cne_lport.h"

struct json_object;

jcfg_lport_t *
jcfg_lport_by_index(jcfg_info_t *jinfo, int idx)
{
    jcfg_data_t *data;
    jcfg_list_t *lst;

    if (!jinfo)
        return NULL;
    data = jinfo->cfg;
    lst  = &data->lport_list;

    return (jcfg_lport_t *)((idx < lst->cnt) ? lst->list[idx] : NULL);
}

char *
jcfg_lport_region(jcfg_lport_t *lport, uint32_t *objcnt)
{
    jcfg_umem_t *umem;

    if (!lport || !lport->umem || !objcnt)
        return NULL;

    umem = lport->umem;
    if (!umem->mm)
        return NULL;

    /* Make sure we have a valid lport region index */
    if (lport->region_idx >= umem->region_cnt)
        return NULL;

    /* Return the count of buffers in the region */
    *objcnt = umem->rinfo[lport->region_idx].bufcnt;

    return umem->rinfo[lport->region_idx].addr;
}

#define JCFG_OPT_NUM 2

static int
_lport(struct json_object *obj, int flags, struct json_object *parent __cne_unused, const char *key,
       size_t *index __cne_unused, void *arg)
{
    jcfg_lport_t *lport = arg;
    enum json_type type;
    char *pmd_opt[JCFG_OPT_NUM] = {0};
    char *pmd_str               = NULL;
    int ret                     = JSON_C_VISIT_RETURN_CONTINUE;

    if (flags == JSON_C_VISIT_SECOND)
        return ret;

    type = json_object_get_type(obj);
    if (key && type != json_type_object) {
        size_t keylen = strnlen(key, JCFG_MAX_STRING_SIZE);

        if (!strncmp(key, JCFG_LPORT_PMD_NAME, keylen)) {
            pmd_str = strdup(json_object_get_string(obj));
            cne_strtok(pmd_str, ":", pmd_opt, 2);
            lport->pmd_name = pmd_opt[0];

            if (pmd_opt[1] != NULL)
                lport->pmd_opts = pmd_opt[1];
        } else if (!strncmp(key, JCFG_LPORT_UMEM_NAME, keylen))
            lport->umem_name = strndup(json_object_get_string(obj), JCFG_MAX_STRING_SIZE);
        else if (!strncmp(key, JCFG_LPORT_REGION_NAME, keylen))
            lport->region_idx = json_object_get_int(obj);
        else if (!strncmp(key, JCFG_LPORT_QID_NAME, keylen))
            lport->qid = json_object_get_int(obj);
        else if (!strncmp(key, JCFG_LPORT_DESC_NAME, keylen) ||
                 !strncmp(key, JCFG_LPORT_DESCRIPTION_NAME, keylen))
            lport->desc = strdup(json_object_get_string(obj));
        else if (!strncmp(key, JCFG_LPORT_BUSY_TIMEOUT_NAME, keylen))
            lport->busy_timeout = (uint16_t)json_object_get_int(obj);
        else if (!strncmp(key, JCFG_LPORT_BUSY_BUDGET_NAME, keylen))
            lport->busy_budget = (uint16_t)json_object_get_int(obj);
        else if (!strncmp(key, JCFG_LPORT_UNPRIVILEGED_NAME, keylen))
            lport->flags |= json_object_get_boolean(obj) ? LPORT_UNPRIVILEGED : 0;
        else if (!strncmp(key, JCFG_LPORT_FORCE_WAKEUP_NAME, keylen))
            lport->flags |= json_object_get_boolean(obj) ? LPORT_FORCE_WAKEUP : 0;
        else if (!strncmp(key, JCFG_LPORT_SKB_MODE_NAME, keylen))
            lport->flags |= json_object_get_boolean(obj) ? LPORT_SKB_MODE : 0;
        else if (!strncmp(key, JCFG_LPORT_BUSY_POLL_NAME, keylen) ||
                 !strncmp(key, JCFG_LPORT_BUSY_POLLING_NAME, keylen))
            lport->flags |= json_object_get_boolean(obj) ? LPORT_BUSY_POLLING : 0;
        else
            CNE_WARN("Unknown lport key (%s)\n", key);
    }

    return ret;
}

static int
_lport_obj(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
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
        jcfg_lport_t *lport;
        int idx;

        lport = calloc(1, sizeof(jcfg_lport_t));
        if (lport) {
            char *c = strchr(key, ':');

            lport->cbtype = JCFG_LPORT_TYPE;
            lport->name   = strdup(key);
            lport->netdev = strdup(key);
            if (c && lport->netdev) /* Trim the name to remove ':' and other characters */
                lport->netdev[c - key] = '\0';

            idx = jcfg_list_add(&data->lport_list, lport);
            if (idx < 0)
                CNE_ERR_RET("Failed to add lport object to list\n");
            lport->lpid = idx;

            ret = json_c_visit(obj, 0, _lport, lport);
            if (ret == JSON_C_VISIT_RETURN_CONTINUE) {
                STAILQ_INSERT_TAIL(&data->lports, lport, next);
                data->lport_count++;

                if (jinfo->flags & JCFG_DEBUG_DECODING)
                    cne_printf("   '[cyan]%s[]': [green]netdev[]: '[magenta]%s[]' [green]pmd[] "
                               "'[magenta]%s[]', [green]lport[] [magenta]%d[] [green]qid[] "
                               "[magenta]%d[], [green]umem[] '[magenta]%s[]', [green]region[] "
                               "[magenta]%d[], [green]desc[] '[yellow]%s[]'\n",
                               lport->name, lport->netdev, lport->pmd_name, lport->lpid, lport->qid,
                               lport->umem_name, lport->region_idx, lport->desc);
            } else
                free(lport);
        } else
            ret = JSON_C_VISIT_RETURN_ERROR;
    }
    return ret;
}

int
_decode_lports(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
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

    ret = json_c_visit(obj, 0, _lport_obj, arg);
    if (ret == JSON_C_VISIT_RETURN_ERROR)
        CNE_ERR("Parsing lport failed\n");

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("}\n");

    return ret ? ret : JSON_C_VISIT_RETURN_SKIP;
}
