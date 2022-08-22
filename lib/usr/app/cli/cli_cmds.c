/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include "generic/cne_cycles.h"
// IWYU pragma: no_include <bits/getopt_core.h>
#include <stdio.h>              // for snprintf, NULL, fclose, fread, popen
#include <cne_version.h>        // for cne_version
#include <alloca.h>             // for alloca
#include <stdint.h>             // for uint16_t, uint32_t, uint8_t, uintptr_t
#include <stdlib.h>             // for atoi
#include <string.h>             // for strlen, strcmp, memset
#include <unistd.h>             // for usleep
#include <limits.h>             // for INT_MAX
#include <sys/queue.h>          // for TAILQ_FOREACH
#include <uds.h>
#include <xskdev.h>        // for xskdev_dump_all

#include "cli.h"              // for cli_node, c_cmd, cli_usage, is_directory
#include "cli_input.h"        // for cli_clear_screen, cli_pause
#include "cli_cmds.h"
#include "cli_cmap.h"          // for cmap, lc_info_t, (anonymous union)::(a...
#include "cli_map.h"           // for cli_mapping, cli_map
#include "cli_file.h"          // for cli_file_handler, is_file_eq, is_file_...
#include "cli_help.h"          // for cli_cmd_error, cli_help_add, cli_help_...
#include "cli_env.h"           // for cli_env_del, cli_env_get, cli_env_set
#include "cne_log.h"           // for CNE_ERR_RET_VAL, CNE_LOG_ERR
#include "cli_search.h"        // for args_t, arg_u, cli_scan_directory, cli...
#include "cne_common.h"        // for __cne_unused
#include "cne_cycles.h"        // IWYU pragma: keep
#include "cne_system.h"        // for cne_get_timer_hz
#include "cli_vt100.h"         // for vt100_escape
#include "cne_stdio.h"         // for cne_printf

static int
__print_help(struct cli_node *node, char *search)
{
    struct cli_node *cmd;

    if (!node)
        node = get_cwd();
    else if (!is_directory(node))
        return -1;

    TAILQ_FOREACH (cmd, &node->items, next) {
        if (is_executable(cmd)) {
            if (search) {
                if (strcmp(cmd->name, search) == 0) {
                    cne_printf("  %-16s %s\n", cmd->name, cmd->short_desc);
                    return 1;
                }
            } else
                cne_printf("  %-16s %s\n", cmd->name, cmd->short_desc);
        }
    }
    return 0;
}

static int
chelp_cmd(int argc, char **argv)
{
    struct cli *cli = this_cli;
    struct cli_node *bin;
    char *search = NULL;
    int i, opt, all = 0;

    optind = 0;
    while ((opt = getopt(argc, argv, "a?")) != -1) {
        switch (opt) {
        case '?':
            cli_usage();
            return 0;
        case 'a':
            all = 1;
            break;
        default:
            break;
        }
    }
    if (optind < argc)
        search = argv[optind];

    cne_printf("*** CLI Help ***\n");
    cne_printf("  Use <command> -? to show usage for a command\n");
    cne_printf("  Use !<NN> to execute a history line\n");
    cne_printf("  Use @<host command> to execute a host binary\n");
    cne_printf("  Use Up/Down arrows to access history commands\n\n");
    cne_printf("  Use 'chelp -a' to list all commands\n");

    if (all == 0) {
        /* Look in the current directory first for a command */
        cne_printf("*** Current directory commands ***\n");

        return __print_help(NULL, search);
    }

    cne_printf("*** All executable commands in path ***\n");

    /* Did not find a command in local then look in the bin dirs */
    for (i = 0; i < CLI_MAX_BINS; i++) {
        bin = cli->bins[i];
        if (bin == NULL)
            continue;

        cne_printf("%s:\n", bin->name);

        if (__print_help(bin, search))
            return 0;
    }

    return 0;
}

static int
cd_cmd(int argc, char **argv)
{
    struct cli_node *node;

    if (argc > 1) {
        if (!strcmp(argv[1], "-?")) {
            cli_usage();
            return 0;
        }

        if (!cli_find_node(argv[1], &node)) {
            cne_printf("** Invalid directory: %s\n", argv[1]);
            return -1;
        }
        set_cwd(node);
    }

    return 0;
}

static int
pwd_cmd(int argc, char **argv)
{
    char *str = cli_cwd_path();

    if (argc > 1 && !strcmp(argv[1], "-?")) {
        cli_usage();
        return 0;
    }

    /* trim off the trailing '/' if needed */
    if (strlen(str) > 1)
        str[strlen(str) - 1] = '\0';

    cne_printf("%s\n", str);
    return 0;
}

static int
__list_long_dir(struct cli_node *node, uint32_t type __cne_unused, args_t *args)
{
    uint16_t flags = args->arg1.u16[3];
    uint16_t spc   = args->arg2.u16[0];

    if (is_alias(node))
        cne_printf("  %*s[magenta]%-16s[] [orange]%s[] : [green]%s[]\n", spc, "", node->name,
                   cli_node_type(node), node->alias_str);
    else if (is_command(node))
        cne_printf("  %*s[orange]%-16s[] [cyan]%s[] : [green]%s[]\n", spc, "", node->name,
                   cli_node_type(node), node->short_desc);
    else
        cne_printf("  %*s[cyan]%-16s[] [magenta]%s[]\n", spc, "", node->name, cli_node_type(node));

    if ((flags & CLI_RECURSE_FLAG) && is_directory(node)) {
        args->arg2.u16[0] += 2;
        cli_scan_directory(node, __list_long_dir, type, args);
        args->arg2.u16[0] = spc;
    }

    return 0;
}

static int
__list_dir(struct cli_node *node, uint32_t flag __cne_unused, args_t *args)

{
    char buf[CLI_NAME_LEN + 1];
    uint16_t cnt   = args->arg1.u16[0];
    uint16_t mlen  = args->arg1.u16[1];
    uint16_t col   = args->arg1.u16[2];
    uint16_t flags = args->arg1.u16[3];

    if (!node)
        return -1;

    if (is_directory(node)) {
        char dbuf[CLI_NAME_LEN + 1];

        snprintf(dbuf, sizeof(dbuf), "%s/", node->name);
        snprintf(buf, sizeof(buf), "%-*s", mlen, dbuf);
        cne_printf("[magenta]%s[]", buf);
    } else if (is_command(node)) {
        snprintf(buf, sizeof(buf), "%-*s", mlen, node->name);
        cne_printf("[orange]%s[]", buf);
    } else {
        snprintf(buf, sizeof(buf), "%-*s", mlen, node->name);
        cne_printf("[cyan]%s[]", buf);
    }
    if ((++cnt % col) == 0)
        cne_printf("\n");

    if ((flags & CLI_RECURSE_FLAG) && is_directory(node)) {
        cne_printf("\n");
        args->arg1.u16[0] = 0;
        cli_scan_directory(node, __list_dir, CLI_ALL_TYPE, args);
        args->arg1.u16[0] = cnt;
        cne_printf("\n");
    }

    args->arg1.u16[0] = cnt;
    return 0;
}

static int
ls_cmd(int argc, char **argv)
{
    struct cli_node *node = get_cwd();
    args_t args;
    uint32_t flags = 0;
    int opt;

    optind = 0;
    while ((opt = getopt(argc, argv, "?rl")) != -1) {
        switch (opt) {
        case '?':
            cli_usage();
            return 0;
        case 'r':
            flags |= CLI_RECURSE_FLAG;
            break;
        case 'l':
            flags |= CLI_LONG_LIST_FLAG;
            break;
        default:
            break;
        }
    }

    if (optind < argc)
        if (cli_find_node(argv[optind], &node) == 0) {
            cne_printf("Invalid directory (%s)!!\n", argv[optind]);
            return -1;
        }

    memset(&args, 0, sizeof(args));

    args.arg1.u16[0] = 0;
    args.arg1.u16[1] = 16;
    args.arg1.u16[2] = 80 / 16;
    args.arg1.u16[3] = flags;
    args.arg2.u16[0] = 0;

    if (flags & CLI_LONG_LIST_FLAG)
        cli_scan_directory(node, __list_long_dir, CLI_ALL_TYPE, &args);
    else
        cli_scan_directory(node, __list_dir, CLI_ALL_TYPE, &args);

    cne_printf("\n");
    return 0;
}

static int
scrn_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    cli_clear_screen();
    return 0;
}

static int
quit_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    cli_set_quit_flag();
    return 0;
}

static int
hist_cmd(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "-?"))
        cli_usage();
    else
        cli_history_list();
    return 0;
}

static int
more_cmd(int argc, char **argv)
{
    struct cli_node *node;
    char *buf, c;
    int i, len, n, k, lines = 24;
    int opt;

    optind = 0;
    while ((opt = getopt(argc, argv, "?n:")) != -1) {
        switch (opt) {
        case '?':
            cli_usage();
            return 0;
        case 'n':
            lines = atoi(optarg);
            break;
        default:
            break;
        }
    }

    if (optind >= argc)
        return 0;

    len = 256;
    buf = alloca(len + 1);
    if (!buf)
        return -1;

    for (i = optind; i < argc; i++) {
        k    = 0;
        node = cli_file_open(argv[i], "r");
        if (!node) {
            cne_printf("** (%s) is not a file\n", argv[i]);
            continue;
        }
        do {
            n = cli_readline(node, buf, len);
            if (n > 0)
                cne_printf("%s", buf); /* contains a newline */
            if (++k >= lines) {
                k = 0;
                c = cli_pause("More", NULL);
                if ((c == vt100_escape) || (c == 'q') || (c == 'Q'))
                    break;
            }
        } while (n > 0);
        cli_file_close(node);
    }

    cne_printf("\n");

    return 0;
}

/* Helper for building log strings.
 * The macro takes an existing string, a printf-like format string and optional
 * arguments. It formats the string and appends it to the existing string, while
 * avoiding possible buffer overruns.
 */
#define strncatf(dest, fmt, ...)                               \
    do {                                                       \
        char _buff[1024];                                      \
        snprintf(_buff, sizeof(_buff), fmt, ##__VA_ARGS__);    \
        strncat(dest, _buff, sizeof(dest) - strlen(dest) - 1); \
    } while (0)

static __inline__ uint8_t
sct(struct cmap *cm, uint8_t s, uint8_t c, uint8_t t)
{
    lc_info_t *lc = cm->linfo;
    uint8_t i;

    for (i = 0; i < cm->num_cores; i++, lc++)
        if (lc->sid == s && lc->cid == c && lc->tid == t)
            return lc->lid;

    return 0;
}

static int
core_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    struct cmap *c;
    int i;

    c = cmap_create();
    if (!c)
        return -1;

    cne_printf("CPU : %s, cache size %d KB\n", c->model, c->cache_size);
    cne_printf("      %d lcores, %u socket%s, %u core%s per socket and "
               "%u thread%s per core\n",
               c->num_cores, c->sid_cnt, c->sid_cnt > 1 ? "s" : "", c->cid_cnt,
               c->cid_cnt > 1 ? "s" : "", c->tid_cnt, c->tid_cnt > 1 ? "s" : "");

    cne_printf("Socket     : ");
    for (i = 0; i < c->sid_cnt; i++)
        cne_printf("%5d      ", i);
    cne_printf("\n");

    for (i = 0; i < c->cid_cnt; i++) {
        cne_printf("  Core %3d : {%3d,%3d}   ", i, sct(c, 0, i, 0), sct(c, 0, i, 1));
        if (c->sid_cnt > 1)
            cne_printf("{%3d,%3d}   ", sct(c, 1, i, 0), sct(c, 1, i, 1));
        if (c->sid_cnt > 2)
            cne_printf("{%3d,%3d}   ", sct(c, 2, i, 0), sct(c, 2, i, 1));
        if (c->sid_cnt > 3)
            cne_printf("{%3d,%3d}   ", sct(c, 3, i, 0), sct(c, 3, i, 1));
        cne_printf("\n");
    }

    cmap_free(c);

    return 0;
}

static int
huge_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    char buf[256];
    FILE *f;
    int n;

    f = popen("cat /proc/meminfo | grep -i huge", "r");
    if (!f)
        return -1;
    do {
        n = fread(buf, 1, sizeof(buf) - 1, f);
        if (n > 0) {
            buf[n] = '\0';
            cne_printf("%s", buf);
        }
    } while (n);
    pclose(f);

    return 0;
}

#ifdef CLI_DEBUG_CMDS
static int
sizes_cmd(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "-?")) {
        cli_usage();
        return 0;
    }

    cne_printf("  sizeof(struct cli)      %zu\n", sizeof(struct cli));
    cne_printf("  sizeof(struct cli_node) %zu\n", sizeof(struct cli_node));
    cne_printf("  sizeof(args_t)          %zu\n", sizeof(args_t));
    cne_printf("  Total number of Nodes   %d\n", this_cli->nb_nodes);
    cne_printf("  Number History lines    %d\n", this_cli->nb_hist);
    cne_printf("  CLI_DEFAULT_NB_NODES    %d\n", CLI_DEFAULT_NB_NODES);
    cne_printf("  CLI_DEFAULT_HIST_LINES  %d\n", CLI_DEFAULT_HIST_LINES);
    cne_printf("  CLI_MAX_SCRATCH_LENGTH  %d\n", CLI_MAX_SCRATCH_LENGTH);
    cne_printf("  CLI_MAX_PATH_LENGTH     %d\n", CLI_MAX_PATH_LENGTH);
    cne_printf("  CLI_NAME_LEN            %d\n", CLI_NAME_LEN);
    cne_printf("  CLI_MAX_ARGVS           %d\n", CLI_MAX_ARGVS);
    cne_printf("  CLI_MAX_BINS            %d\n", CLI_MAX_BINS);

    return 0;
}
#endif

static int
path_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    int i;
    char *str;

    cne_printf("  Path = .:");
    for (i = 1; i < CLI_MAX_BINS; i++) {
        if (this_cli->bins[i] == NULL)
            continue;
        str = cli_path_string(this_cli->bins[i], NULL);

        /* trim off the trailing '/' if needed */
        if (strlen(str) > 1)
            str[strlen(str) - 1] = '\0';

        cne_printf("%s:", str);
    }
    cne_printf("\n");

    return 0;
}

static const char *copyright =
    "   BSD LICENSE\n"
    "\n"
    "   Copyright (c) 2019-2022 Intel Corporation. All rights reserved.\n"
    "\n"
    "   Redistribution and use in source and binary forms, with or without\n"
    "   modification, are permitted provided that the following conditions\n"
    "   are met:\n"
    "\n"
    "     * Redistributions of source code must retain the above copyright\n"
    "       notice, this list of conditions and the following disclaimer.\n"
    "     * Redistributions in binary form must reproduce the above copyright\n"
    "       notice, this list of conditions and the following disclaimer in\n"
    "       the documentation and/or other materials provided with the\n"
    "       distribution.\n"
    "     * Neither the name of Intel Corporation nor the names of its\n"
    "       contributors may be used to endorse or promote products derived\n"
    "       from this software without specific prior written permission.\n"
    "\n"
    "   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
    "   \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
    "   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
    "   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
    "   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
    "   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
    "   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
    "   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
    "   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
    "   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
    "   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
    "\n"
    "   SPDX-License-Identifier: BSD-3-Clause\n";

static int
copyright_file(struct cli_node *node, char *buff, int len, uint32_t flags)
{

    if (is_file_open(flags)) {
        node->file_data = (char *)(uintptr_t)copyright;
        node->file_size = strlen(copyright);
        node->fflags    = CLI_DATA_RDONLY;
        if (is_file_eq(flags, (CLI_FILE_APPEND | CLI_FILE_WR)))
            node->foffset = node->file_size;
        return 0;
    }
    return cli_file_handler(node, buff, len, flags);
}

static int
version_file(struct cli_node *node, char *buff, int len, uint32_t flags)
{
    const char *data = cne_version();

    if (is_file_open(flags)) {
        node->file_data = (char *)(uintptr_t)data;
        node->file_size = strlen(data);
        node->fflags    = CLI_DATA_RDONLY;
        if (is_file_eq(flags, (CLI_FILE_APPEND | CLI_FILE_WR)))
            node->foffset = node->file_size;
        return 0;
    }
    return cli_file_handler(node, buff, len, flags);
}

static int
sleep_cmd(int argc, char **argv)
{
    uint32_t cnt;
    int seconds;

    if (argc != 2) {
        cne_printf("sleep expects one parameter\n");
        return -1;
    }

    seconds = atoi(argv[1]);

    if (seconds < 0 || seconds > INT_MAX)
        return -1;

    cnt = seconds * 4;

    if (cne_get_timer_hz() == 0) {
        cne_printf("cne_get_timer_hz() returned zero\n");
        return 0;
    }

    while (cnt--) {
        usleep(250 * 1000);
    }
    return 0;
}

static int
delay_cmd(int argc, char **argv)
{
    int cnt, ms;

    if (argc != 2) {
        cne_printf("delay expects one parameter\n");
        return -1;
    }

    ms = atoi(argv[1]);
    if (ms < 0 || ms > INT_MAX)
        return -1;

    cnt = (ms / 1000) * 4;

    while (cnt--) {
        usleep(250 * 1000);
        ms -= 250;
    }
    if (ms > 0)
        usleep(ms * 1000);
    return 0;
}

static int
mkdir_cmd(int argc, char **argv)
{
    if (argc != 2) {
        cne_printf("Must have at least one path/driectory\n");
        return -1;
    }

    if (!cli_add_dir(argv[1], get_cwd()))
        return -1;
    return 0;
}

static int
rm_cmd(int argc, char **argv)
{
    struct cli_node *node;

    if (argc != 2) {
        cne_printf("usage: rm [dir|file|command]\n");
        return -1;
    }

    if (!cli_find_node(argv[1], &node)) {
        cne_printf("Unable to find: %s\n", argv[1]);
        return -1;
    }

    return cli_remove_node(node);
}

static char *
ver_cmd(const char *val __cne_unused)
{
    return (char *)(uintptr_t)cne_version();
}

// clang-format off
static struct cli_map cli_env_map[] = {
    {10, "env"},
    {11, "env show"},
    {20, "env get %s"},
    {30, "env set %s %s"},
    {40, "env del %s"},
    {-1, NULL}
};

static const char *cli_env_help[] = {
    "env                       - Display current environment variables",
    "env get <string>          - Get the requested variable",
    "env set <string> <string> - Set the given variable to string",
    "env del <string>          - Delete the given variable",
    NULL
};
// clang-format on

static int
env_cmd(int argc, char **argv)
{
    struct cli_map *m;

    m = cli_mapping(cli_env_map, argc, argv);
    if (!m) {
        cli_cmd_error("Environment command error:", "Env", argc, argv);
        return -1;
    }
    switch (m->index) {
    case 10: /* FALLTHRU */
    case 11:
        cli_env_show(this_cli->env);
        break;
    case 20:
        cne_printf("  \"%s\" = \"%s\"\n", argv[2], cli_env_get(this_cli->env, argv[2]));
        break;
    case 30:
        cli_env_set(this_cli->env, argv[2], argv[3]);
        break;
    case 40:
        cli_env_del(this_cli->env, argv[2]);
        break;
    default:
        cli_help_show_group("env");
        return -1;
    }
    return 0;
}

static int
script_cmd(int argc, char **argv)
{
    int i;

    if (argc <= 1)
        return -1;

    for (i = 1; i < argc; i++)
        if (cli_execute_cmdfile(argv[1]))
            return -1;
    return 0;
}

static int
echo_cmd(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++)
        cne_printf("%s ", argv[i]);
    cne_printf("\n");
    return 0;
}

static int
version_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    cne_printf("Version: %s\n", cne_version());
    return 0;
}

// clang-format off
static struct cli_map xsk_map[] = {
    {10, "xsk"},
    {11, "xsk stats"},
    {20, "xsk queues"},
    {30, "xsk all"},
    {-1, NULL}
    };
// clang-format on
static int
xsk_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    struct cli_map *m;

    m = cli_mapping(xsk_map, argc, argv);
    if (!m)
        return cli_cmd_error("command is invalid", "xsk", argc, argv);

    switch (m->index) {
    case 10:
        xskdev_dump_all(0);
        break;
    case 11:
        xskdev_dump_all(XSKDEV_STATS_FLAG);
        break;
    case 20:
        xskdev_dump_all(XSKDEV_RX_FQ_TX_CQ_FLAG);
        break;
    case 30:
        xskdev_dump_all(XSKDEV_STATS_FLAG | XSKDEV_RX_FQ_TX_CQ_FLAG);
        return 0;
    default:
        return cli_cmd_error("Command invalid", "xsk", argc, argv);
    }

    return 0;
}

static int
pktmbuf_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    pktmbuf_info_dump();
    return 0;
}

// clang-format off
static struct cli_tree cli_default_tree[] = {
    c_file("copyright",    copyright_file,      "CNDP copyright information"),
    c_file("cndp-version", version_file,        "CNDP version"),
    c_bin("/sbin"),

    c_cmd("delay",      delay_cmd,      "delay a number of milliseconds"),
    c_cmd("sleep",      sleep_cmd,      "delay a number of seconds"),
    c_cmd("chelp",      chelp_cmd,      "CLI help - display information for CNDP"),
    c_cmd("?",          chelp_cmd,      "CLI help - display information for CNDP"),
    c_cmd("mkdir",      mkdir_cmd,      "create a directory"),
    c_cmd("rm",         rm_cmd,         "remove a file or directory"),
    c_cmd("ls",         ls_cmd,         "ls [-lr] <dir> # list current directory"),
    c_cmd("cd",         cd_cmd,         "cd <dir> # change working directory"),
    c_cmd("pwd",        pwd_cmd,        "pwd # display current working directory"),
    c_cmd("scrn.clear", scrn_cmd,       "scrn.clear # clear the screen"),
    c_cmd("quit",       quit_cmd,       "quit # quit the application"),
    c_cmd("q",          quit_cmd,       "q # quit the application"),
    c_cmd("history",    hist_cmd,       "history # display the current history"),
    c_cmd("more",       more_cmd,       "more <file> # display a file content"),
#ifdef CLI_DEBUG_CMDS
    c_cmd("sizes",      sizes_cmd,      "sizes # display some internal sizes"),
#endif
    c_cmd("cmap",       core_cmd,       "cmap # display the core mapping"),
    c_cmd("hugepages",  huge_cmd,       "hugepages # display hugepage info"),
    c_cmd("path",       path_cmd,       "display the execution path for commands"),
    c_cmd("script",     script_cmd,     "load and process cli command files"),
    c_cmd("echo",       echo_cmd,       "simple echo a string to the screen"),
    c_cmd("version",    version_cmd,    "Display version information"),
    c_cmd("env",        env_cmd,        "Show/del/get/set environment variables"),
    c_cmd("xsk",        xsk_cmd,        "xskdev information [stats|queues|all]"),
    c_cmd("pktmbuf",    pktmbuf_cmd,    "dump all pktmbuf information structures"),

    /* The following are environment variables */
    c_str("SHELL",      NULL,           "CLI shell"),
    c_str("CNDP_VER",   ver_cmd,        ""),
    c_end()
};
// clang-format on

int
cli_default_tree_init(void)
{
    int ret = 0;

    if (this_cli->flags & CLI_DEFAULT_TREE)
        return ret;

    this_cli->flags |= CLI_DEFAULT_TREE;

    /* Add the list of commands/dirs in cli_cmds.c file */
    if ((ret = cli_add_tree(NULL, cli_default_tree)) == 0)
        cli_help_add("Env", cli_env_map, cli_env_help);

    if (ret < 0) {
        this_cli->flags &= ~CLI_DEFAULT_TREE;
        CNE_ERR_RET_VAL(ret, "Unable to add commands or directories\n");
    }

    return ret;
}
