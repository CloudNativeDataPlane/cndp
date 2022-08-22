/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <string.h>                    // for strdup, strchr
#include <json-c/json_object.h>        // for json_object_is_type, json_object_get...
#include <json-c/json_visit.h>         // for json_c_visit, JSON_C_VISIT_RETURN_CO...
#include <sched.h>                     // for CPU_SET, CPU_ISSET, CPU_SETSIZE, CPU...
#include <stdio.h>                     // for size_t
#include <stdlib.h>                    // for atoi, free, calloc
#include <sys/queue.h>                 // for STAILQ_INSERT_TAIL
#include <sys/sysinfo.h>

#include "jcfg.h"                // for jcfg_lgroup_t, jcfg_info_t, jcfg_data_t
#include "jcfg_private.h"        // for jcfg
#include "jcfg_decode.h"         // for _decode_lgroups
#include "cne_common.h"          // for __cne_unused
#include "cne_log.h"             // for CNE_ERR, CNE_LOG_ERR

struct json_object;

static inline int
validate_cpu(int cpu)
{
    if (cpu < 0 || cpu >= get_nprocs())
        CNE_ERR_RET_VAL(JSON_C_VISIT_RETURN_ERROR, "[magenta]Invalid CPU [orange]%d[]\n", cpu);

    return JSON_C_VISIT_RETURN_CONTINUE;
}

static inline int
validate_cpu_range(int start, int last)
{
    int ret;

    ret = validate_cpu(start);
    if (ret == 0)
        ret = validate_cpu(last);

    return ret;
}

#define VALID_CPU(_c, _lbl)     \
    do {                        \
        ret = validate_cpu(_c); \
        if (ret)                \
            goto _lbl;          \
    } while (/*CONSTCOND*/ 0)

#define VALID_CPU_RANGE(_s, _l, _lbl)     \
    do {                                  \
        ret = validate_cpu_range(_s, _l); \
        if (ret)                          \
            goto _lbl;                    \
    } while (/*CONSTCOND*/ 0)

static int
_lgroup(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
        const char *key __cne_unused, size_t *index __cne_unused, void *arg)
{
    jcfg_lgroup_t *lg = arg;
    int ret           = JSON_C_VISIT_RETURN_CONTINUE;

    if (flags == JSON_C_VISIT_SECOND)
        return ret;

    CNE_DEBUG("[magenta]CPUs configured [orange]%d [magenta]available [orange]%d[]\n",
              get_nprocs_conf(), get_nprocs());

    if (json_object_is_type(obj, json_type_int)) {
        int cpu = json_object_get_int(obj);

        VALID_CPU(cpu, leave);

        CPU_SET(cpu, &lg->lcore_bitmap);
        lg->lcore_cnt++;
    } else if (json_object_is_type(obj, json_type_string)) {
        char *p, *str = strdup(json_object_get_string(obj));

        if (!str) {
            ret = JSON_C_VISIT_RETURN_ERROR;
            CNE_ERR_GOTO(leave, "CPU string invalid\n");
        }

        p = strchr(str, '-');
        if (p) {
            int start = 0, last = 0;

            *p++  = '\0';
            start = atoi(str);
            last  = atoi(p);

            VALID_CPU_RANGE(start, last, free_str);

            while (start <= last) {
                CPU_SET(start, &lg->lcore_bitmap);
                lg->lcore_cnt++;
                start++;
            }
        } else {
            int cpu = atoi(str);

            VALID_CPU(cpu, free_str);

            CPU_SET(cpu, &lg->lcore_bitmap);
            lg->lcore_cnt++;
        }
    free_str:
        free(str);
    }

leave:
    return ret;
}

static int
_lgroup_array(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
              const char *key __cne_unused, size_t *index __cne_unused, void *arg)
{
    int ret = JSON_C_VISIT_RETURN_CONTINUE;

    if (flags == JSON_C_VISIT_SECOND)
        return ret;

    if (json_object_is_type(obj, json_type_array))
        ret = json_c_visit(obj, 0, _lgroup, arg);

    return ret;
}

static int
_lgroup_obj(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
            const char *key, size_t *index __cne_unused, void *arg)
{
    jcfg_info_t *jinfo = arg;
    enum json_type type;
    int ret = JSON_C_VISIT_RETURN_CONTINUE;

    if (flags == JSON_C_VISIT_SECOND)
        return ret;

    type = json_object_get_type(obj);

    if (key && type == json_type_array) {
        struct jcfg *cfg  = jinfo->cfg;
        jcfg_data_t *data = &cfg->data;
        jcfg_lgroup_t *lg;

        lg = calloc(1, sizeof(jcfg_lgroup_t));
        if (lg) {
            lg->cbtype = JCFG_LGROUP_TYPE;
            lg->name   = strdup(key);

            CPU_ZERO(&lg->lcore_bitmap);

            ret = json_c_visit(obj, 0, _lgroup_array, lg);
            if (ret == JSON_C_VISIT_RETURN_CONTINUE) {
                STAILQ_INSERT_TAIL(&data->lgroups, lg, next);
                data->lgroup_count++;

                if (jinfo->flags & JCFG_DEBUG_DECODING) {
                    cne_printf("   '[cyan]%-10s[]': [green]lcores[]: [magenta]%d[] [ ", lg->name,
                               lg->lcore_cnt);
                    for (int i = 0; i < CPU_SETSIZE; i++)
                        if (CPU_ISSET(i, &lg->lcore_bitmap))
                            cne_printf("[magenta]%d[] ", i);
                    cne_printf("]\n");
                }
            } else
                free(lg);
        } else
            ret = JSON_C_VISIT_RETURN_ERROR;
    }
    return ret;
}

int
_decode_lgroups(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
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

    ret = json_c_visit(obj, 0, _lgroup_obj, jinfo);
    if (ret == JSON_C_VISIT_RETURN_ERROR)
        CNE_ERR("Parsing thread failed\n");

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("}\n");

    return ret ? ret : JSON_C_VISIT_RETURN_SKIP;
}
