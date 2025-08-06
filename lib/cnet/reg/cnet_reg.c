/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2025 Intel Corporation
 */

#include <cne_per_thread.h>        // for CNE_DEFINE_PER_THREAD
#include <stdlib.h>                // for qsort

#include "cnet_const.h"        // for CNET_MAX_INITS, cfunc_t, CNET_INIT, CNET...
#include "cne_stdio.h"         // for cne_printf
#include "cnet_reg.h"
#include "cne_log.h"        // for CNE_ERR, CNE_LOG_ERR

struct stk_s;

CNE_DEFINE_PER_THREAD(struct stk_s *, stk);

struct cvec {
    uint16_t len;  /**< Number of pointers in vector list */
    uint16_t tlen; /**< Total number of vectors */
    uint16_t pad0; /**< pad */
    cnet_register_t list[CNET_MAX_INITS];
};

// clang-format off
static struct cvec instance_inits = {
    .len = 0,
    .tlen = CNET_MAX_INITS
};
// clang-format on

void
cnet_add_instance(const char *name, int pri, cfunc_t create, cfunc_t destroy)
{
    struct cvec *cv = &instance_inits;

    if (!name | (name[0] == '\0'))
        CNE_ERR("instance name is NULL or zero length\n");

    if (cv->len >= cv->tlen)
        CNE_ERR("*** Increase CNET_MAX_INITS\n");
    else {
        cnet_register_t *f = &cv->list[cv->len++];

        f->priority  = pri;
        f->name      = name;
        f->s_create  = create;
        f->s_destroy = destroy;
    }
}

static int
cnet_compar(const void *p1, const void *p2)
{
    const cnet_register_t *f1 = (const cnet_register_t *)p1;
    const cnet_register_t *f2 = (const cnet_register_t *)p2;

    return f1->priority - f2->priority;
}

static int
__do_calls(struct cvec *cv, struct stk_s *stk, int typ)
{
    /* Sort the priorities into the correct order */
    qsort(cv->list, cv->len, sizeof(cnet_register_t), cnet_compar);

    for (int i = 0; i < cv->len; i++) {
        cnet_register_t *f = &cv->list[i];

        switch (typ) {
        case CNET_INIT:
            if (f->s_create && (f->s_create(stk) < 0))
                return -1;
            break;

        case CNET_STOP:
            if (f->s_destroy && (f->s_destroy(stk) < 0))
                return -1;
            break;
        }
    }
    return 0;
}

int
cnet_do_instance_calls(struct stk_s *stk, int typ)
{
    return __do_calls(&instance_inits, stk, typ);
}

void
cne_register_dump(void)
{
    struct cvec *sv = &instance_inits;

    /* Sort the priorities into the correct order */
    qsort(sv->list, sv->len, sizeof(cnet_register_t), cnet_compar);

    cne_printf("[yellow]Registered CNET-Stack[]\n");
    for (int i = 0; i < sv->len; i++) {
        cnet_register_t *f = &sv->list[i];

        cne_printf("  [orange]%-12s[]: [magenta]create [green]%-5s [magenta]destroy [green]%-5s "
                   "[magenta]priority [yellow]%2d.%d[]\n",
                   f->name, f->s_create ? "true" : "false", f->s_destroy ? "true" : "false",
                   f->priority >> 8, f->priority & 0xFF);
    }
}
