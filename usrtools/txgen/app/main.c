/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <execinfo.h>        // for backtrace, backtrace_symbols
#include <signal.h>          // for SIGUSR2, kill, SIGHUP, SIGSEGV, SIGPIPE
#include <cne.h>             // for cne_init, cne_on_exit, copyright_msg, pow...
#include <stdint.h>          // for int32_t
#include <stdio.h>           // for printf, fflush, size_t, NULL, stdout
#include <stdlib.h>          // for free
#include <string.h>          // for memset

#include "txgen.h"        // for txgen, txgen_t, PRINT_LABELS_FLAG
#include "display.h"
#include "cli-functions.h"        // for txgen_cli_create, txgen_cli_start
#include "parse-args.h"           // for parse_args
#include "cli.h"                  // for cli_destroy
#include "cne_common.h"           // for __cne_unused, cne_countof
#include "cne_log.h"              // for CNE_DEBUG, CNE_LOG_DEBUG, CNE_PRINT, cne_...
#include "cne_system.h"           // for cne_get_timer_hz
#include "jcfg.h"                 // for jcfg_thd_t, jcfg_lport_t, jcfg_info_t
#include "pktdev_api.h"           // for pktdev_close
#include "cmds.h"

#define MAX_BACKTRACE 32

#define foreach_thd_lport(_t, _lp) \
    for (int _i = 0; _i < _t->lport_cnt && (_lp = _t->lports[_i]); _i++, _lp = _t->lports[_i])

static int
_thread_quit(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_thd_t *thd = obj;
    jcfg_lport_t *lport;

    thd->quit = 1;

    if (thd->lport_cnt == 0) {
        CNE_DEBUG("No lports attached to thread '%s'\n", thd->name);
        return 0;
    } else
        CNE_DEBUG("Close %d lport%s for thread '%s'\n", thd->lport_cnt,
                  (thd->lport_cnt == 1) ? "" : "s", thd->name);

    foreach_thd_lport (thd, lport) {
        CNE_PRINT(">>>    lport %d - '%s'\n", lport->lpid, lport->name);
        if (pktdev_close(lport->lpid) < 0)
            CNE_ERR("pktdev_close() returned error\n");
    }
    return 0;
}

static void
__on_exit(int val, void *arg, int exit_type)
{
    void *array[MAX_BACKTRACE];
    size_t size;
    char **strings;
    txgen_t *tx = arg;
    size_t i;

    CNE_DEBUG("called with val %d, exit type %d\n", val, exit_type);

    switch (exit_type) {
    case CNE_CAUGHT_SIGNAL:
        switch (val) {
        case SIGSEGV:
            cne_printf("\nTXGen got a Segment Fault\n");
            goto dump;
        case SIGHUP:
            kill(0, SIGTERM);
            break;
        case SIGUSR1:
            cne_printf("\nTXGen received a SIGUSR1\n");
            break;
        case SIGUSR2:
            cne_printf("\nTXGen received a SIGUSR2\n");
            break;
        default:
            cne_printf("\nTXGen received signal %d\n", val);
            break;
        }
        break;

    case CNE_CALLED_EXIT:
        if (tx) {
            CNE_PRINT(">>> Closing lport(s)\n");
            jcfg_thread_foreach(tx->jinfo, _thread_quit, NULL);
            CNE_PRINT(">>> Done.");
        } else
            CNE_WARN("txgen pointer is NULL\n");

        vt_setw(1);                   /* Reset the window size, from possible crash run. */
        cne_printf_pos(999, 1, "\n"); /* Move the cursor to the bottom of the screen again */
        cli_destroy();
        break;

    case CNE_USER_EXIT:
        break;

    default:
        break;
    }

    return;

dump:
    vt_setw(1);                   /* Reset the window size, from possible crash run. */
    cne_printf_pos(100, 1, "\n"); /* Move the cursor to the bottom of the screen again */
    cli_destroy();

    cne_printf("\n");

    size    = backtrace(array, MAX_BACKTRACE);
    strings = backtrace_symbols(array, size);

    cne_printf("Obtained %zd stack frames.\n", size);

    for (i = 0; i < size; i++)
        cne_printf("%s\n", strings[i]);

    free(strings);
}

/**
 *
 * main - Main routine to setup txgen.
 *
 * DESCRIPTION
 * Main routine to setup txgen.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
int
main(int argc, char **argv)
{
    int signals[] = {SIGSEGV, SIGHUP, SIGPIPE, SIGUSR2, SIGUSR2};
    int32_t ret;

    vt_setw(1);     /* Reset the window size, from possible crash run. */
    vt_pos(100, 1); /* Move the cursor to the bottom of the screen again */

    cne_printf("\n[yellow]%s[] [green]%s[]\n\n", copyright_msg(), powered_by());

    memset(&txgen, 0, sizeof(txgen));

    txgen.ident = 0x1234;
    txgen.hz    = cne_get_timer_hz(); /* Get the starting HZ value. */

    display_pause();      /* Set the screen to be paused as we do not need it updating now */
    txgen_force_update(); /* force the first screen update after the screen is not paused. */

    /* initialize CNE */
    ret = cne_init();
    if (ret < 0)
        cne_panic("cne_init() failed");

    cne_on_exit(__on_exit, &txgen, signals, cne_countof(signals));

    if (txgen_cli_create() < 0)
        cne_panic("Failed to create CLI");

    /* parse application arguments (after the CNE ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        cne_panic("TXGen parsing arguments failed");

    vt_erase(tty_num_rows()); /* Scroll the screen up */
    display_resume();

    txgen_cli_start(); /* Loop handling keyboard input */

    return 0;
}
