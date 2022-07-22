/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#include <stdio.h>             // for NULL, snprintf, EOF
#include <string.h>            // for strcmp, strncmp
#include <getopt.h>            // for getopt_long, option
#include <cne_common.h>        // for CNE_SET_USED, __cne_unused
#include <tst_info.h>          // for TST_ASSERT_EQUAL_AND_CLEANUP, tst_end, TST_A...
#include <pthread.h>
#include <cne_tailq.h>

#include "tailqs_test.h"

static struct cne_tailq_elem tst_dummy_tailq = {
    .name = "dummy",
};
CNE_REGISTER_TAILQ(tst_dummy_tailq)

static struct cne_tailq_elem tst_dummy_dyn_tailq = {
    .name = "dummy_dyn",
};
static struct cne_tailq_elem tst_dummy_dyn2_tailq = {
    .name = "dummy_dyn",
};

static struct cne_tailq_entry d_elem;
static struct cne_tailq_entry d_dyn_elem;

static int
test_tailq_early(void)
{
    struct cne_tailq_entry_head *d_head;

    d_head = CNE_TAILQ_CAST(tst_dummy_tailq.head, cne_tailq_entry_head);
    if (d_head == NULL)
        CNE_ERR_RET_VAL(1, "%s has not been initialised\n", tst_dummy_tailq.name);

    /* check we can add an item to it */
    TAILQ_INSERT_TAIL(d_head, &d_elem, next);

    return 0;
}

static int
test_tailq_create(void)
{
    struct cne_tailq_entry_head *d_head;

    /* create a tailq and check its non-null (since we are post init) */
    if ((cne_tailq_register(&tst_dummy_dyn_tailq) < 0) || (tst_dummy_dyn_tailq.head == NULL))
        CNE_ERR_RET_VAL(1, "allocating %s\n", tst_dummy_dyn_tailq.name);

    d_head = CNE_TAILQ_CAST(tst_dummy_dyn_tailq.head, cne_tailq_entry_head);

    /* check we can add an item to it */
    TAILQ_INSERT_TAIL(d_head, &d_dyn_elem, next);

    if (strcmp(tst_dummy_dyn2_tailq.name, tst_dummy_dyn_tailq.name))
        CNE_ERR_RET_VAL(1, "comparing tailq names do not match as expected\n");

    /* try allocating again, and check for failure */
    if (!cne_tailq_register(&tst_dummy_dyn2_tailq))
        CNE_ERR_RET_VAL(1, "registering the same tailq %s did not fail\n",
                        tst_dummy_dyn2_tailq.name);

    return 0;
}

static int
test_tailq_lookup(void)
{
    /* run successful  test - check result is found */
    struct cne_tailq_entry_head *d_head;
    struct cne_tailq_entry *d_ptr;

    d_head = CNE_TAILQ_LOOKUP(tst_dummy_tailq.name, cne_tailq_entry_head);
    /* tst_dummy_tailq has been registered by EAL_REGISTER_TAILQ */
    if (d_head == NULL || d_head != CNE_TAILQ_CAST(tst_dummy_tailq.head, cne_tailq_entry_head))
        CNE_ERR_RET_VAL(1, "tailq lookup failed for %s\n", tst_dummy_tailq.name);

    TAILQ_FOREACH (d_ptr, d_head, next)
        if (d_ptr != &d_elem)
            CNE_ERR_RET_VAL(1, "tailq returned from lookup - expected element not found\n");

    d_head = CNE_TAILQ_LOOKUP(tst_dummy_dyn_tailq.name, cne_tailq_entry_head);
    /* tst_dummy_dyn_tailq has been registered by test_tailq_create */
    if (d_head == NULL || d_head != CNE_TAILQ_CAST(tst_dummy_dyn_tailq.head, cne_tailq_entry_head))
        CNE_ERR_RET_VAL(1, "tailq lookup for %s\n", tst_dummy_dyn_tailq.name);

    TAILQ_FOREACH (d_ptr, d_head, next)
        if (d_ptr != &d_dyn_elem)
            CNE_ERR_RET_VAL(1, "tailq returned from lookup - expected element not found\n");

    /* now try a bad/error lookup */
    d_head = CNE_TAILQ_LOOKUP("coucou", cne_tailq_entry_head);
    if (d_head != NULL)
        CNE_ERR_RET_VAL(1, "lookup does not return NULL for invalid tailq name\n");

    return 0;
}

static int
test_tailq(void)
{
    int ret = 0;

    ret |= test_tailq_early();
    ret |= test_tailq_create();
    ret |= test_tailq_lookup();

    return ret;
}

int
tailqs_main(int argc __cne_unused, char **argv __cne_unused)
{
    tst_info_t *tst;

    tst = tst_start("TailQs");

    if (test_tailq()) {
        tst_end(tst, TST_FAILED);
        return -1;
    }

    tst_end(tst, TST_PASSED);

    return 0;
}
