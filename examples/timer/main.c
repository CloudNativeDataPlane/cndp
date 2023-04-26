/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Intel Corporation
 */

#include <stdio.h>             // for NULL, snprintf
#include <stdint.h>            // for uint64_t
#include <cne_common.h>        // for __cne_unused
#include <cne.h>               // for cne_id
#include <cne_timer.h>         // for cne_timer_dump_stats, cne_timer_init, cne_ti...
#include <cli.h>               // for cli_path_string, cli_add_bin_path, cli_add_tree
#include <cne_cycles.h>        // for cne_rdtsc, cne_rdtsc_precise

#include "main.h"
#include "cne_system.h"        // for cne_get_timer_hz, cne_lcore_id
#include "cne_stdio.h"         // for cne_printf, cne_printf_pos
#include "vt100_out.h"         // for vt_cls

static volatile int timer_stop;
static uint64_t timer_start;

static void
single_timer(struct cne_timer *tim __cne_unused, void *arg __cne_unused)
{
    uint64_t hz = cne_get_timer_hz();

    double timer_end = (double)(cne_rdtsc() - timer_start);
    if (hz)
        cne_printf("Single timer fired in [green]%.2f[] seconds on thread %d\n\n", timer_end / hz,
                   cne_id());
    else
        cne_printf("Single timer fired in [green]inf[] seconds on thread %d\n\n", cne_id());

    timer_stop = 1;
}

static void
periodical_timer(struct cne_timer *tim __cne_unused, void *arg)
{
    uint64_t hz = cne_get_timer_hz();
    int *count  = arg;

    double timer_end = (double)(cne_rdtsc() - timer_start);
    if (hz)
        cne_printf("Periodical timer fired in [green]%.2f[] seconds on thread %d\n", timer_end / hz,
                   cne_id());
    else
        cne_printf("Periodical timer fired in [green]inf[] seconds on thread %d\n", cne_id());

    timer_start = cne_rdtsc();

    (*count)++;

    if (*count > 10)
        timer_stop = 1;
}

static int
timer_cmd(int argc, char **argv)
{
    struct cne_timer tim0;
    int count;

    (void)argc;
    (void)argv;

    cne_timer_subsystem_init();

    cne_timer_init(&tim0);

    cne_timer_reset(&tim0, cne_get_timer_hz() * 2, SINGLE, cne_id(), single_timer, NULL);
    cne_printf("\nSet a single use timer for 2 seconds\n");

    timer_stop  = 0;
    timer_start = cne_rdtsc();
    while (timer_stop == 0) {
        cne_timer_manage();
    }
    cne_timer_dump_stats(NULL);

    cne_timer_stop(&tim0);
    cne_timer_init(&tim0);

    count = 0;
    cne_timer_reset(&tim0, cne_get_timer_hz() / 2, PERIODICAL, cne_id(), periodical_timer, &count);
    cne_printf("\nSet a periodical timer for every 1/2 second\n");

    timer_stop  = 0;
    timer_start = cne_rdtsc();
    while (timer_stop == 0) {
        cne_timer_manage();
    }
    cne_printf("\n");
    cne_timer_dump_stats(NULL);
    cne_timer_stop(&tim0);

    return 0;
}

static int
rdtsc_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    uint64_t count = 0, hz;
    uint64_t tsc_start, tsc_end, delta;

    hz = cne_get_timer_hz();

    tsc_start = cne_rdtsc();
    tsc_end   = tsc_start + hz;

    while (cne_rdtsc() < tsc_end)
        count++;

    delta = (tsc_end - tsc_start);
    cne_printf("TSC start [blue]%lu[] - end [blue]%lu[] = [red]%lu[]\n", tsc_start, tsc_end, delta);
    if (count)
        cne_printf("   loop count: [green]%lu[] ([green]%lu[]) cycles\n", count, delta / count);
    else
        cne_printf("   loop count: [green]%lu[] ([green]inf[]) cycles\n", count);

    count     = 0;
    tsc_start = cne_rdtsc_precise();
    tsc_end   = tsc_start + hz;

    while (cne_rdtsc_precise() < tsc_end)
        count++;

    delta = (tsc_end - tsc_start);
    cne_printf("Precise TSC start [blue]%lu[] - end [blue]%lu[] = [red]%lu[]\n", tsc_start, tsc_end,
               delta);
    if (count)
        cne_printf("   loop count: [green]%lu[] ([green]%lu[]) cycles\n", count, delta / count);
    else
        cne_printf("   loop count: [green]%lu[] ([green]inf[]) cycles\n", count);

    return 0;
}

// clang-format off
static struct cli_tree default_tree[] = {
    c_dir("/bin"),

    c_cmd("timer", timer_cmd, "Run a timer test"),
    c_cmd("perf",  rdtsc_cmd, "Run a simple rdtsc performance test"),

    c_end()
};
// clang-format on

static int
init_tree(void)
{
    /* Add the system default commands in /sbin directory */
    if (cli_default_tree_init())
        return -1;

    /* Add the directory tree */
    if (cli_add_tree(cli_root_node(), default_tree))
        return -1;

    /* Make sure the txgen commands are executable in search path */
    if (cli_add_bin_path("/bin"))
        return -1;

    return 0;
}

static int
my_prompt(int cont __cne_unused)
{
    char buff[256];
    int n;

    n = snprintf(buff, sizeof(buff), "cndp-cli:%s> ", cli_path_string(NULL, NULL));

    cne_printf("[green]cndp-cli:%s[]> ", cli_path_string(NULL, NULL));

    return n;
}

static int
setup_cli(void)
{
    if (cli_create(NULL)) {
        cne_printf("cli_create() failed\n");
        return -1;
    }

    if (cli_setup_with_tree(init_tree)) {
        cne_printf("cli_setup_with_tree() failed\n");
        return -1;
    }

    cli_set_prompt(my_prompt);

    vt_cls();

    /* put cursor at the bottom of the window */
    cne_printf_pos(128, 1, "\n");

    return 0;
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    if (setup_cli() < 0)
        return -1;

    cne_printf("[green] Timer Test[], [magenta]lcore[] [red]%d[]\n", cne_lcore_id());

    /* Loop waiting for commands or ^C is pressed */
    cli_start("CNDP Timer Example, use 'ls -rl' or 'chelp -a' to see all commands");

    cli_destroy();

    return 0;
}
