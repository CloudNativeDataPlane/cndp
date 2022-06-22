/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corp, Inc.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <stdio.h>                     // for NULL, printf, snprintf, size_t, EOF
#include <string.h>                    // for strcmp, strdup
#include <getopt.h>                    // for getopt_long, option
#include <dirent.h>                    // for closedir, dirent, opendir, readdir, DIR
#include <tst_info.h>                  // for tst_end, tst_start, TST...
#include <jcfg.h>                      // for jcfg_destroy, jcfg_info_t, jcfg_user_t
#include <jcfg_private.h>              // for jcfg
#include <jcfg_process.h>              // for jcfg_process
#include <jcfg_print.h>                // for __print_object
#include <jcfg_decode.h>               // for __decode_object
#include <json-c/json_object.h>        // for json_object_get_type
#include <json-c/json_visit.h>         // for JSON_C_VISIT_RETURN_ERROR, json_c_visit
#include <stdlib.h>                    // for calloc, free
#include <sys/queue.h>                 // for STAILQ_INSERT_TAIL

#include "jcfg_test.h"
#include "cne_common.h"        // for __cne_unused, CNE_SET_USED
#include "cne_log.h"           // for CNE_LOG_ERR, CNE_ERR, CNE_ERR_RET

struct json_object;

#ifndef JSON_TEST_DIR
#define JSON_TEST_DIR "test/testcne/files/json"
#endif

#define USER1_DATA_TAG "user1-data"

static int
_user_print(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_opt_t *opt = obj;

    __print_object(obj, &opt->val);

    return 0;
}

static int
_user_obj(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
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
        jcfg_user_t *usr;

        usr = calloc(1, sizeof(jcfg_user_t));
        if (usr) {
            usr->cbtype = JCFG_OPTION_TYPE;
            usr->name   = strdup(key);

            ret = __decode_object(&usr->val, obj, type);
            if (ret == JSON_C_VISIT_RETURN_ERROR) {
                free(usr->name);
                free(usr);
            } else {
                STAILQ_INSERT_TAIL(&data->users, usr, next);
                data->user_count++;
            }
        } else
            ret = JSON_C_VISIT_RETURN_ERROR;
    }
    return ret;
}

static int
_user1_decode(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
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
        cne_printf("'[magenta]%s[]': {\n", key);

    ret = json_c_visit(obj, 0, _user_obj, jinfo);
    if (ret == JSON_C_VISIT_RETURN_ERROR)
        CNE_ERR("Parsing user failed\n");

    if (jinfo->flags & JCFG_DEBUG_DECODING) {
        jcfg_user_foreach(jinfo, _user_print, NULL);
        cne_printf("}\n");
    }

    return ret ? ret : JSON_C_VISIT_RETURN_SKIP;
}

static int
process_callback(jcfg_info_t *j __cne_unused, void *_obj, void *arg, int idx)
{
    CNE_SET_USED(_obj);
    CNE_SET_USED(arg);
    CNE_SET_USED(idx);

    return 0;
}

static int
test_json_files(const char *path, int flags)
{
    DIR *pdir           = NULL;
    struct dirent *pent = NULL;
    jcfg_info_t *jinfo  = NULL;
    char fullpath[1024];

    pdir = opendir(path);
    if (!pdir)
        return -1;

    while ((pent = readdir(pdir))) {
        if (pent->d_type == DT_DIR)
            continue;

        cne_printf("\n** Process file  : %s\n\n", pent->d_name);
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, pent->d_name);

        if (!strcmp(pent->d_name, "test-strings.jsonc"))
            TST_ASSERT_GOTO(jcfg_add_decoder(USER1_DATA_TAG, _user1_decode) >= 0,
                            "jcfg_add_decoder(%s) failed\n", err, USER1_DATA_TAG);

        jinfo = jcfg_parser(flags, fullpath);
        if (!jinfo)
            continue;

        if (jcfg_process(jinfo, flags, process_callback, NULL)) {
            closedir(pdir);
            CNE_ERR_RET("*** Invalid configuration ***\n");
        }

        if (!strcmp(pent->d_name, "test-strings.jsonc"))
            TST_ASSERT_GOTO(jcfg_del_decoder(USER1_DATA_TAG) == 0, "jcfg_del_decoder(%s) failed\n",
                            err, USER1_DATA_TAG);

        cne_printf("** Done\n");

        jcfg_destroy(jinfo);
        jinfo = NULL;
    }
    closedir(pdir);

    if (jinfo)
        jcfg_destroy(jinfo);

    return 0;
err:
    closedir(pdir);
    if (jinfo)
        jcfg_destroy(jinfo);
    return -1;
}

int
jcfg_main(int argc, char **argv)
{
    tst_info_t *tst;
    int opt, flags = JCFG_PARSE_FILE;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "VDP", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            flags |= JCFG_INFO_VERBOSE;
            break;
        case 'D':
            flags |= JCFG_DEBUG_DECODING;
            break;
        case 'P':
            flags |= JCFG_DEBUG_PARSING;
            break;
        default:
            break;
        }
    }

    tst = tst_start("JCFG");

    if (flags & JCFG_INFO_VERBOSE)
        jcfg_dump_info();

    if (test_json_files(JSON_TEST_DIR, flags))
        goto leave;

    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_end(tst, TST_FAILED);
    return -1;
}
