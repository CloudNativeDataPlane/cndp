/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation
 */

#include <stdio.h>             // for fflush, vprintf, stdout
#include <stdlib.h>            // for free, abort, calloc, srand
#include <stdarg.h>            // for va_end, va_list, va_start
#include <string.h>            // for strdup
#include <cne_system.h>        // for cne_lcore_id, cne_socket_id
#include <cne_log.h>           // for cne_panic
#include <stdatomic.h>         // for atomic_fetch_add, atomic_load, atomic_uint

#include "tst_info.h"
#include "cne_stdio.h"        // for cne_printf

struct tst_stat {
    atomic_uint fail;
    atomic_uint pass;
    atomic_uint skip;
};

/* Global test statistics updated by tst_end(). */
static struct tst_stat tst_stats;

int
tst_exit_code(void)
{
    if (atomic_load(&tst_stats.fail))
        return EXIT_FAILURE;
    else if (atomic_load(&tst_stats.skip))
        return EXIT_SKIPPED;
    return EXIT_SUCCESS;
}

uint32_t
tst_summary(void)
{
    uint32_t fail = atomic_load(&tst_stats.fail);

    cne_printf("-------------\n");
    cne_printf("Test Summary:\n");
    cne_printf("-------------\n");
    cne_printf("[red]Fail: %u[]\n", fail);
    cne_printf("[green]Pass: %u[]\n", atomic_load(&tst_stats.pass));
    cne_printf("[yellow]Skip: %u[]\n", atomic_load(&tst_stats.skip));

    return fail;
}

tst_info_t *
tst_start(const char *msg)
{
    tst_info_t *tst;

    tst = calloc(1, sizeof(tst_info_t));
    if (!tst) {
        cne_printf("[red]Error[]: [magenta]Failed to allocate tst_info_t structure[]\n");
        abort();
    }

    tst->lid  = cne_lcore_id();
    tst->sid  = cne_socket_id(tst->lid);
    tst->name = strdup(msg);

    srand(0x56063011);

    cne_printf("[cyan]>>>> [yellow]%s [green]tests[]: [magenta]Lcore ID [red]%d[], [magenta]Socket "
               "ID [red]%d[]\n",
               tst->name, tst->lid, tst->sid);

    return tst;
}

void
tst_end(tst_info_t *tst, int result)
{
    if (!tst)
        cne_panic("tst cannot be NULL\n");

    cne_printf("[cyan]<<<< [yellow]%s [green]Tests[]: [magenta]done.[]\n\n", tst->name);

    if (result == TST_PASSED)
        atomic_fetch_add(&tst_stats.pass, 1);
    else if (result == TST_SKIPPED)
        atomic_fetch_add(&tst_stats.skip, 1);
    else
        atomic_fetch_add(&tst_stats.fail, 1);
    free(tst->name);
    free(tst);
}

void
tst_skip(const char *fmt, ...)
{
    va_list va_list;

    va_start(va_list, fmt);
    cne_printf("[yellow]  ** [green]SKIP[] - [green]TEST[]: [cyan]");
    cne_vprintf(fmt, va_list);
    cne_printf("[]\n");
    va_end(va_list);

    fflush(stdout);
}

void
tst_ok(const char *fmt, ...)
{
    va_list va_list;

    va_start(va_list, fmt);
    cne_printf("[yellow]  ** [green]PASS[] - [green]TEST[]: [cyan]");
    cne_vprintf(fmt, va_list);
    cne_printf("[]\n");
    va_end(va_list);

    fflush(stdout);
}

void
tst_error(const char *fmt, ...)
{
    va_list va_list;

    va_start(va_list, fmt);
    cne_printf("[yellow]  >> [red]FAIL[] - [green]TEST[]: [cyan]");
    cne_vprintf(fmt, va_list);
    cne_printf("[]\n");
    va_end(va_list);

    fflush(stdout);
}

void
tst_info(const char *fmt, ...)
{
    va_list va_list;

    va_start(va_list, fmt);
    cne_printf("\n[yellow]  == [blue]INFO[] - [green]TEST[]: [cyan]");
    cne_vprintf(fmt, va_list);
    cne_printf("[]\n");
    va_end(va_list);

    fflush(stdout);
}
