/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <string.h>                    // for strcmp, strdup, strlen
#include <cne_mmap.h>                  // for mmap_type_by_name, mmap_name_by_type
#include <json-c/json_object.h>        // for json_object_get_int, json_object_get...
#include <json-c/json_visit.h>         // for json_c_visit, JSON_C_VISIT_RETURN_CO...
#include <stdint.h>                    // for uint32_t
#include <stdlib.h>                    // for calloc, free, size_t, NULL
#include <sys/queue.h>                 // for STAILQ_INSERT_TAIL

#include "jcfg.h"                // for jcfg_umem_t, jcfg_default_get_u32
#include "jcfg_private.h"        // for jcfg
#include "jcfg_decode.h"         // for jcfg_list_add, _decode_umems
#include "cne_common.h"          // for __cne_unused
#include "cne_log.h"             // for CNE_LOG_ERR, CNE_ERR, CNE_ERR_RET

struct json_object;

jcfg_umem_t *
jcfg_umem_by_index(jcfg_info_t *jinfo, int idx)
{
    jcfg_data_t *data;
    jcfg_list_t *lst;

    if (!jinfo)
        return NULL;
    data = jinfo->cfg;
    lst  = &data->umem_list;

    return (jcfg_umem_t *)((idx < lst->cnt) ? lst->list[idx] : NULL);
}

static int
_umem(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
      const char *key __cne_unused, size_t *index __cne_unused, void *arg)
{
    jcfg_umem_t *umem = arg;
    enum json_type type;

    if (flags == JSON_C_VISIT_SECOND)
        return JSON_C_VISIT_RETURN_CONTINUE;

    type = json_object_get_type(obj);
    if (key && type != json_type_object) {
        if ((!strcmp(key, "desc") || !strcmp(key, "description")))
            umem->desc = strdup(json_object_get_string(obj));
        else if (!strcmp(key, "bufcnt"))
            umem->bufcnt = json_object_get_int(obj) * 1024;
        else if (!strcmp(key, "regions")) {
            umem->region_cnt = json_object_array_length(obj);

            if (umem->region_cnt > UMEM_MAX_REGIONS) {
                CNE_ERR("UMEM region count %d > %d max\n", umem->region_cnt, UMEM_MAX_REGIONS);
                return JSON_C_VISIT_RETURN_ERROR;
            }

            umem->rinfo = calloc(umem->region_cnt, sizeof(region_info_t));
            if (!umem->rinfo) {
                CNE_ERR("Unable to allocate UMEM regions (%d)\n", umem->region_cnt);
                return JSON_C_VISIT_RETURN_ERROR;
            }

            for (int i = 0; i < umem->region_cnt; i++) {
                struct json_object *val = json_object_array_get_idx(obj, i);

                umem->rinfo[i].bufcnt = json_object_get_int(val) * 1024;
            }
        } else if (!strcmp(key, "bufsz"))
            umem->bufsz = json_object_get_int(obj) * 1024;
        else if (!strcmp(key, "rxdesc"))
            umem->rxdesc = json_object_get_int(obj) * 1024;
        else if (!strcmp(key, "txdesc"))
            umem->txdesc = json_object_get_int(obj) * 1024;
        else if (!strcmp(key, "mtype")) {
            const char *str = json_object_get_string(obj);
            if (str && strlen(str) > 0)
                umem->mtype = mmap_type_by_name(str);
        } else if (!strcmp(key, "shared_umem"))
            umem->shared_umem = json_object_get_boolean(obj) ? 1 : 0;
    }

    return JSON_C_VISIT_RETURN_CONTINUE;
}

static int
_umem_obj(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
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
        jcfg_umem_t *umem;

        umem = calloc(1, sizeof(jcfg_umem_t));
        if (umem) {
            uint32_t u32;
            int idx;
            char *v;

            umem->cbtype = JCFG_UMEM_TYPE;
            umem->name   = strdup(key);
            idx          = jcfg_list_add(&data->umem_list, umem);
            if (idx < 0)
                CNE_ERR_RET("Failed to add UMEM object to list\n");
            umem->idx = idx;

            if (jcfg_default_get_string(jinfo, "mtype", &v) == 0)
                umem->mtype = mmap_type_by_name((const char *)v);
            if (jcfg_default_get_u32(jinfo, "rxdesc", &u32) == 0)
                umem->rxdesc = u32;
            if (jcfg_default_get_u32(jinfo, "txdesc", &u32) == 0)
                umem->txdesc = u32;
            if (jcfg_default_get_u32(jinfo, "bufcnt", &u32) == 0)
                umem->bufcnt = u32;
            if (jcfg_default_get_u32(jinfo, "bufsz", &u32) == 0)
                umem->bufsz = u32;

            ret = json_c_visit(obj, 0, _umem, umem);
            if (ret == JSON_C_VISIT_RETURN_CONTINUE) {

                if (umem->region_cnt == 0)
                    umem->rinfo[umem->region_cnt++].bufcnt = umem->bufcnt;

                STAILQ_INSERT_TAIL(&data->umems, umem, next);
                data->umem_count++;

                if (jinfo->flags & JCFG_DEBUG_DECODING) {
                    cne_printf("   '[cyan]%s[]': [green]regions [magenta]%d[] [ ", umem->name,
                               umem->region_cnt);
                    for (int i = 0; i < umem->region_cnt; i++) {
                        cne_printf("[magenta]%d[] ", umem->rinfo[i].bufcnt);
                    }
                    cne_printf("], [green]bufsz [magenta]%d[], [green]mtype[] '[magenta]%s[]', "
                               "[green]rxdesc [magenta]%d[], [green]txdesc [magenta]%d[], "
                               "[green]desc[] '[yellow]%s[]'\n",
                               umem->bufsz, mmap_name_by_type(umem->mtype), umem->rxdesc,
                               umem->txdesc, umem->desc);
                }
            } else
                free(umem);
        } else
            ret = JSON_C_VISIT_RETURN_ERROR;
    }
    return ret;
}

int
_decode_umems(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
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

    ret = json_c_visit(obj, 0, _umem_obj, jinfo);
    if (ret == JSON_C_VISIT_RETURN_ERROR)
        CNE_ERR("Parsing UMEMs failed\n");

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("}\n");

    return ret ? ret : JSON_C_VISIT_RETURN_SKIP;
}

void
jcfg_umem_free(jcfg_hdr_t *hdr)
{
    jcfg_umem_t *umem = (jcfg_umem_t *)hdr;

    if (!umem)
        return;

    free(umem->rinfo);
    mmap_free(umem->mm);
    umem->rinfo = NULL;
    umem->mm    = NULL;
}
