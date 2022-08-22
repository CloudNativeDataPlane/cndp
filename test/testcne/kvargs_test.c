/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdio.h>             // for NULL, snprintf, EOF
#include <string.h>            // for strcmp, strncmp
#include <getopt.h>            // for getopt_long, option
#include <cne_common.h>        // for CNE_SET_USED, __cne_unused
#include <tst_info.h>          // for TST_ASSERT_EQUAL_AND_CLEANUP, tst_end, TST_A...
#include <kvargs.h>            // for kvargs_free, kvargs_parse, kvargs_count, kva...

#include "kvargs_test.h"

/* incrementd in handler, to check it is properly called once per
 * key/value association */
static unsigned count;

static void
_cleanup(void *arg)
{
    kvargs_free((struct kvargs *)arg);
}

/* this handler increment the "count" variable at each call and check
 * that the key is "check" and the value is "value%d" */
static int
check_handler(const char *key, const char *value, __cne_unused void *opaque)
{
    char buf[16];

    /* we check that the value is "check" */
    if (strcmp(key, "check"))
        return -1;

    /* we check that the value is "value$(count)" */
    snprintf(buf, sizeof(buf), "value%d", count);
    if (strncmp(buf, value, sizeof(buf)))
        return -1;

    count++;
    return 0;
}

/* test a valid case */
static int
test_valid_kvargs(void)
{
    struct kvargs *kvlist;
    const char *args;
    const char *valid_keys_list[] = {"foo", "check", NULL};
    const char **valid_keys;
    int ret;

    /* empty args is valid */
    args       = "";
    valid_keys = NULL;
    kvlist     = kvargs_parse(args, valid_keys);
    TST_ASSERT_NULL_AND_CLEANUP(kvlist, "error on NULL args", kvargs_free, kvlist);
    kvargs_free(kvlist);

    /* first test without valid_keys */
    args       = "foo=1234,check=value0,check=value1";
    valid_keys = NULL;
    kvlist     = kvargs_parse(args, valid_keys);
    TST_ASSERT_NOT_NULL(kvlist, "error on NULL valid_keys");

    /* call check_handler() for all entries with key="check" */
    count = 0;
    ret   = kvargs_process(kvlist, "check", check_handler, NULL);
    TST_ASSERT_SUCCESS_AND_CLEANUP(ret, "to process (%s) %d", _cleanup, kvlist, args, ret);

    TST_ASSERT_EQUAL_AND_CLEANUP(count, 2, "invalid count value %d", _cleanup, kvlist, count);

    count = 0;
    /* call check_handler() for all entries with key="unexistant_key" */
    ret = kvargs_process(kvlist, "nonexistent_key", check_handler, NULL);
    TST_ASSERT_SUCCESS_AND_CLEANUP(ret, "failed to process (%s)", _cleanup, kvlist, args);

    TST_ASSERT_EQUAL_AND_CLEANUP(count, 0, "invalid count value %d", _cleanup, kvlist, count);

    /* count all entries with key="foo" */
    count = kvargs_count(kvlist, "foo");
    TST_ASSERT_EQUAL_AND_CLEANUP(count, 1, "invalid count value %d", _cleanup, kvlist, count);

    /* count all entries */
    count = kvargs_count(kvlist, NULL);
    TST_ASSERT_EQUAL_AND_CLEANUP(count, 3, "invalid count value %d", _cleanup, kvlist, count);

    /* count all entries with key="unexistant_key" */
    count = kvargs_count(kvlist, "unexistant_key");
    TST_ASSERT_EQUAL_AND_CLEANUP(count, 0, "invalid count value %d", _cleanup, kvlist, count);

    kvargs_free(kvlist);

    /* second test using valid_keys */
    args       = "foo=droids,check=value0,check=value1,check=wrong_value";
    valid_keys = valid_keys_list;
    kvlist     = kvargs_parse(args, valid_keys);
    TST_ASSERT_NOT_NULL(kvlist, "error on NULL valid_keys");

    /* call check_handler() on all entries with key="check", it
     * should fail as the value is not recognized by the handler */
    ret = kvargs_process(kvlist, "check", check_handler, NULL);
    TST_ASSERT_FAIL_AND_CLEANUP(ret, "should be invalid check value", _cleanup, kvlist);

    count = kvargs_count(kvlist, "check");
    TST_ASSERT_EQUAL_AND_CLEANUP(count, 3, "invalid count value %d", _cleanup, kvlist, count);

    kvargs_free(kvlist);

    /* third test using list as value, when you have list then use ';' instead of ',' */
    args       = "foo=[0,1];check=value2";
    valid_keys = valid_keys_list;
    kvlist     = kvargs_parse(args, valid_keys);
    TST_ASSERT_NOT_NULL(kvlist, "error on NULL valid_keys");

    TST_ASSERT_SUCCESS_AND_CLEANUP(strcmp(kvlist->pairs[0].value, "[0,1]"), "value not '[0,1]'",
                                   _cleanup, kvlist);

    count = kvlist->count;
    TST_ASSERT_EQUAL_AND_CLEANUP(count, 2, "count not 2 (%d)", _cleanup, kvlist, count);
    kvargs_free(kvlist);

    return 0;
}

/* test several error cases */
static int
test_invalid_kvargs(void)
{
    struct kvargs *kvlist;
    /* list of argument that should fail */
    const char *args_list[] = {"wrong-key=x",     /* key not in valid_keys_list */
                               "foo=1,foo=",      /* empty value */
                               "foo=1,foo",       /* no value */
                               "foo=1,=2",        /* no key */
                               "foo=1;foo=2",     /* Use ';' when no '[]' are present */
                               "foo=[1,2],foo=2", /* Use ',' when '[]' are present */
                               ";=",              /* also test with a smiley */
                               NULL};
    const char **args;
    const char *valid_keys_list[] = {"foo", "check", NULL};
    const char **valid_keys       = valid_keys_list;

    for (args = args_list; *args != NULL; args++) {

        kvlist = kvargs_parse(*args, valid_keys);
        TST_ASSERT_NULL_AND_CLEANUP(kvlist, "invalid keys not detected", _cleanup, kvlist);
    }
    return 0;
}

int
kvargs_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "V", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("KVARGS");

    if (test_valid_kvargs() < 0)
        goto leave;

    if (test_invalid_kvargs() < 0)
        goto leave;

    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_end(tst, TST_FAILED);

    return -1;
}
