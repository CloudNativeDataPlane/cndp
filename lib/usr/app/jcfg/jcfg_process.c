/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdio.h>             // for NULL
#include <cne_common.h>        // for cne_countof

#include "jcfg.h"        // for jcfg_info_t, JCFG_DEBUG_PARSING, jcfg_opt_t
#include "jcfg_process.h"
#include "jcfg_print.h"        // for __print_lgroup, __print_lport, __print_thread
#include "cne_log.h"           // for CNE_ERR_RET, CNE_LOG_ERR

static int
process_application(jcfg_info_t *j, void *obj, void *arg, int idx)
{
    jcfg_opt_t *opt = obj;

    if (j->flags & JCFG_DEBUG_PARSING)
        __print_application(obj, &opt->val);

    if (j->cb && j->cb(j, obj, arg, idx))
        return -1;

    return 0;
}

static int
process_defaults(jcfg_info_t *j, void *obj, void *arg, int idx)
{
    jcfg_opt_t *opt = obj;

    if (j->flags & JCFG_DEBUG_PARSING)
        __print_default(obj, &opt->val);

    if (j->cb && j->cb(j, obj, arg, idx))
        return -1;

    return 0;
}

static int
process_option(jcfg_info_t *j, void *obj, void *arg, int idx)
{
    jcfg_opt_t *opt = obj;

    if (j->flags & JCFG_DEBUG_PARSING)
        __print_option(obj, &opt->val);

    if (j->cb && j->cb(j, obj, arg, idx))
        return -1;

    return 0;
}

static int
process_user(jcfg_info_t *j, void *obj, void *arg, int idx)
{
    jcfg_opt_t *opt = obj;

    if (j->flags & JCFG_DEBUG_PARSING)
        __print_user(obj, &opt->val);

    if (j->cb && j->cb(j, obj, arg, idx))
        return -1;

    return 0;
}

static int
process_umem(jcfg_info_t *j, void *obj, void *arg, int idx)
{
    if (j->flags & JCFG_DEBUG_PARSING)
        __print_umem(obj, NULL);

    if (j->cb && j->cb(j, obj, arg, idx))
        return -1;

    return 0;
}

static int
process_lport(jcfg_info_t *j, void *obj, void *arg, int idx)
{
    if (j->flags & JCFG_DEBUG_PARSING)
        __print_lport(obj, NULL);

    if (j->cb && j->cb(j, obj, arg, idx))
        return -1;

    return 0;
}

static int
process_lgroup(jcfg_info_t *j, void *obj, void *arg, int idx)
{
    if (j->flags & JCFG_DEBUG_PARSING)
        __print_lgroup(obj, NULL);

    if (j->cb && j->cb(j, obj, arg, idx))
        return -1;

    return 0;
}

static int
process_thread(jcfg_info_t *j, void *obj, void *arg, int idx)
{
    if (j->flags & JCFG_DEBUG_PARSING)
        __print_thread(obj, NULL);

    if (j->cb && j->cb(j, obj, arg, idx))
        return -1;

    return 0;
}

static int
process_lport_group(jcfg_info_t *j, void *obj, void *arg, int idx)
{
    if (j->flags & JCFG_DEBUG_PARSING)
        __print_lport_group(obj, NULL);

    if (j->cb && j->cb(j, obj, arg, idx))
        return -1;

    return 0;
}

int
jcfg_process(jcfg_info_t *jinfo, int flags, jcfg_parse_cb_t *cb, void *cb_arg)
{
    const char *tags[] = JCFG_TAG_NAMES;
    // clang-format off
    struct {
        jcfg_cb_type_t cbtype;
        jcfg_cb_t *pfunc;
    } process[] = {
        { JCFG_APPLICATION_TYPE,   process_application },
        { JCFG_DEFAULT_TYPE,       process_defaults },
        { JCFG_OPTION_TYPE,        process_option },
        { JCFG_UMEM_TYPE,          process_umem },
        { JCFG_LPORT_TYPE,         process_lport },
        { JCFG_LGROUP_TYPE,        process_lgroup },
        { JCFG_THREAD_TYPE,        process_thread },
        { JCFG_LPORT_GROUP_TYPE,   process_lport_group },
        { JCFG_USER_TYPE,          process_user }
    };
    // clang-format on

    if (!jinfo)
        return -1;

    jinfo->cb    = cb;
    jinfo->flags = flags;

    if (flags & JCFG_DEBUG_PARSING)
        cne_printf("[yellow]>>>>> [green]Process JCFG sections[]\n");

    for (int i = 0; i < cne_countof(process); i++) {
        jcfg_cb_type_t cbtype = process[i].cbtype;

        if (cbtype >= JCFG_MAX_TYPES)
            CNE_ERR_RET("Unknown tag type %d\n", cbtype);

        if (flags & JCFG_DEBUG_PARSING)
            cne_printf("[yellow]=== [green]%s[]:\n", tags[cbtype]);

        if (jcfg_object_foreach(jinfo, cbtype, process[i].pfunc, cb_arg)) {
            cne_printf(" [red]*** %s: Error ***[]\n", __func__);
            return -1;
        }
    }

    if (flags & JCFG_DEBUG_PARSING)
        cne_printf("[yellow]>>>>> [green]Done Processing sections[]\n\n");

    return 0;
}
