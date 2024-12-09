/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Intel Corporation
 */

#include <stdint.h>            // for uint64_t
#include <cne_common.h>        // for CNE_SET_USED, __cne_unused, cne_countof
#include <cne_mmap.h>          // for mmap_sizes_t, mmap_stats_t
#include <cne_lport.h>         // for lport_stats_t
#include <pktdev.h>            // for pktdev_info
#include <cne_log.h>
#include <cli.h>           // for cli_path_string, cli_add_bin_path, cli_add_tree
#include <txbuff.h>        // for txbuff
#include <csock.h>

#include "main.h"
#include "pktmbuf.h"        // for pktmbuf_t

struct struct_sizes {
    const char *name;
    uint64_t size;
    uint64_t expected;
};

static csock_t *accept_c;

static union {
    uint64_t d; /** Stopped long variable */
    void *v;
} app_stopped = {.v = NULL};

static void
__on_exit(int val, void *arg __cne_unused, int exit_type)
{
    switch (exit_type) {
    case CNE_CAUGHT_SIGNAL:
        /* Terminate the application if not USR1 signal, allows for GDB breakpoint setting */
        if (val == SIGUSR1)
            return;

        cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with signal [green]%d[]\n", val);
        csock_close(accept_c);
        cli_set_quit_flag();
        app_stopped.d = 1;
        break;

    case CNE_CALLED_EXIT:
        if (val)
            cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with status [green]%d[]\n", val);
        csock_close(accept_c);
        cli_set_quit_flag();
        break;

    case CNE_USER_EXIT:
        csock_close(accept_c);
        cli_set_quit_flag();
        app_stopped.d = 1;
        break;

    default:
        break;
    }
}

static int
sizeof_cmd(int argc, char **argv)
{
    // clang-format off
    struct struct_sizes ssizes[] = {
        {"mmap_sizes_t", sizeof(mmap_sizes_t)},
        {"mmap_stats_t", sizeof(mmap_stats_t)},
        {"pktmbuf_t", sizeof(pktmbuf_t), 64},
        {"lport_stats", sizeof(lport_stats_t)},
        {"pktdev_info", sizeof(struct pktdev_info)},
        {"txbuff", sizeof(struct txbuff)},
    };
    // clang-format on
    int i;

    CNE_SET_USED(argc);
    CNE_SET_USED(argv);

    cne_printf("[magenta]*** Sizeof:[]\n");

    for (i = 0; i < cne_countof(ssizes); i++) {
        if (ssizes[i].name == NULL)
            break;
        cne_printf("  [magenta]%-24s[]= [green]%ld[]", ssizes[i].name, ssizes[i].size);
        if (ssizes[i].expected && (ssizes[i].size != ssizes[i].expected))
            cne_printf("  [red]*** Size Error expected %ld ***[]", ssizes[i].expected);
        cne_printf("\n");
    }

    return 0;
}

static int
stop_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    cli_set_quit_flag();
    app_stopped.d = 1;

    return 0;
}

// clang-format off
static struct cli_tree default_tree[] = {
    c_dir("/bin"),

    c_cmd("stop", stop_cmd, "Stop the CNDP application"),
    c_cmd("sizeof", sizeof_cmd, "Size of structures"),

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

    /* Make sure the cli commands are executable in search path */
    if (cli_add_bin_path("/bin"))
        return -1;

    return 0;
}

static int
my_prompt(int cont __cne_unused)
{
    char *p = cli_path_string(NULL, NULL);

    if (!p)
        p = (char *)(uintptr_t)"PathError";

    cne_printf("[orange]cli[]:[magenta]%s[yellow]>[] ", p);

    return (strnlen(p, 128) + strnlen("cli:> ", 7));
}

static void *
client_handler(csock_t *c)
{
    if (c) {
        int fd_in, fd_out;

        accept_c = c;

        fd_in = fd_out = csock_get_fd(c);

        tty_setup(fd_in, fd_out);

        if (cli_create(NULL))
            CNE_NULL_RET("cli_create() failed\n");

        if (cli_setup_with_tree(init_tree))
            CNE_NULL_RET("cli_setup_with_tree() failed\n");

        cli_set_prompt(my_prompt);

        /* Loop waiting for commands or ^C/^X is pressed */
        cli_start("CNDP Example CLI, use 'ls -lr' or 'chelp -a' to see all commands");

        cli_destroy();
        csock_close(c);
        tty_destroy();
    }

    return app_stopped.v;
}

static void
usage(int err)
{
    cne_printf("[cyan]cli[]: [yellow]CLI Test example[]\n");
    cne_printf("  [magenta]Options[]:\n");
    cne_printf("    [yellow]-s,--socket host[]  - [green]The local domain path or host:port[]\n");
    cne_printf("    [yellow]-h,--help[]         - [green]This help message[]\n");
    exit(err);
}

int
main(int argc, char *argv[])
{
    csock_t *c = NULL;
    // clang-format off
    struct option lgopts[] = {
        { "socket",     1, NULL, 's' },
        { "help",       no_argument, NULL, 'h' },
        { NULL, 0, 0, 0 }
    };
    // clang-format on
    char host_str[CSOCK_MAX_SOCK_INFO_LENGTH] = {0};
    csock_cfg_t cfg                           = {0};
    int option_index, opt;

    option_index = 0;
    while ((opt = getopt_long(argc, argv, "hs:", lgopts, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 's': /* Setup up UDS or TCP socket to remote host:port */
            strlcpy(host_str, optarg, sizeof(host_str));
            break;
        default:
            break;
        }
    }

    if (cne_init() < 0)
        CNE_ERR_GOTO(out, "Failed to init CNE\n");

    cne_on_exit(__on_exit, NULL, NULL, 0);

    cfg.flags     = CSOCK_IS_SERVER;
    cfg.host_addr = host_str;
    cfg.client_fn = client_handler;

    c = csock_create(&cfg);
    if (!c)
        CNE_ERR_GOTO(out, "csock_create() failed\n");

    cne_printf("*** [yellow]CLI [green]Example application using [lightgoldenrod]%s[]\n",
               (host_str[0] == '\0') ? "stdio" : host_str);

    if (csock_server_start(c) < 0)
        CNE_ERR_GOTO(out, "csock_server_start() failed\n");

    csock_destroy(c);

    return 0;
out:
    csock_destroy(c);
    return -1;
}
