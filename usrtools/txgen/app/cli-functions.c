/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

#include "cli-functions.h"

#include <stdio.h>                // for NULL, snprintf
#include <string.h>               // for strchr
#include <net/cne_ether.h>        // for cne_ether_aton
#include <cne_common.h>           // for __cne_unused, CNE_MIN
#include <cli.h>                  // for c_cmd, c_alias, cli_add_bin_path, cli_add_...
#include <cli_map.h>              // for cli_mapping, cli_map, cli_map_list_search
#include <net/ethernet.h>         // for ETHER_CRC_LEN
#include <stdint.h>               // for uint16_t, uint32_t
#include <stdlib.h>               // for atoi, strtoul

#include "txgen.h"          // for foreach_port, estate, txgen, txgen_t, MIN_...
#include "cmds.h"           // for txgen_clear_display, txgen_update_display
#include "display.h"        // for display_set_color, txgen_set_theme_item
#include "cne_inet.h"
#include "_pcap.h"           // for pcap_info_t, _pcap_info
#include "cli_help.h"        // for cli_cmd_error, cli_help_add, CLI_HELP_PAUSE
#include "cne_log.h"
#include "jcfg.h"              // for jcfg_lport_t
#include "pktdev_api.h"        // for pktdev_port_count
#include "port-cfg.h"          // for port_info_t
#include "portlist.h"          // for portlist_parse, portlist_t

static inline uint16_t
valid_pkt_size(char *val)
{
    uint16_t pkt_size;

    if (!val)
        return (MIN_PKT_SIZE + ETHER_CRC_LEN);

    pkt_size = atoi(val);

    if (pkt_size < MIN_PKT_SIZE)
        pkt_size = MIN_PKT_SIZE;

    if (pkt_size > MAX_PKT_SIZE)
        pkt_size = MAX_PKT_SIZE;

    return pkt_size;
}

/**********************************************************/
static const char *title_help[] = {
    "   *** TXGen Help information ***",
    "",
    NULL,
};

static const char *status_help[] = {
    "",
    "       Flags: P-             - Promiscuous mode enabled",
    "                ------       - Modes Single",
    "Notes: <state>       - Use enable|disable or on|off to set the state.",
    "       <portlist>    - a list of lports (no spaces) as 2,4,6-9,12 or 3-5,8 or 5 or the "
    "word 'all'",
    CLI_HELP_PAUSE,
    NULL};

// clang-format off
#define set_types   \
    "count|"        /*  0 */ \
    "size|"         /*  1 */ \
    "rate|"         /*  2 */ \
    "burst|"        /*  3 */ \
    "sport|"        /*  4 */ \
    "dport|"        /*  5 */ \
    "ttl"           /*  6 */

static struct cli_map set_map[] = {
    {10, "set %P %|" set_types " %d"},
    {20, "set %P type ipv4"},
    {21, "set %P proto %|udp|tcp|icmp"},
    {22, "set %P src mac %m"},
    {23, "set %P dst mac %m"},
    {24, "set %P pattern %|abc|none|user|zero"},
    {25, "set %P user pattern %s"},
    {30, "set %P src ip %4"},
    {31, "set %P dst ip %4"},
    {-1, NULL}
    };
// clang-format on

static const char *set_help[] = {
    "",
    "    note: <portlist>               - a list of lports (no spaces) e.g. 2,4,6-9,12 or the "
    "word 'all'",
    "set <portlist> count <value>       - number of packets to transmit",
    "set <portlist> size <value>        - size of the packet to transmit",
    "set <portlist> rate <percent>      - Packet rate in percentage",
    "set <portlist> burst <value>       - number of packets in a burst",
    "set <portlist> tx_cycles <value>   - DEBUG to set the number of cycles per TX burst",
    "set <portlist> sport <value>       - Source lport number for TCP",
    "set <portlist> dport <value>       - Destination lport number for TCP",
    "set <portlist> ttl <value>         - Set the TTL value for the single lport more",
    "set <portlist> src|dst mac <addr>  - Set MAC addresses 00:11:22:33:44:55 or "
    "0011:2233:4455 format",
    "set <portlist> type ipv4           - Set the packet type",
    "set <portlist> proto udp|tcp|icmp  - Set the packet protocol to UDP or TCP or ICMP per "
    "lport",
    "set <portlist> pattern <type>      - Set the fill pattern type",
    "                 type - abc        - Default pattern of abc string",
    "                        none       - No fill pattern, maybe random data",
    "                        zero       - Fill of zero bytes",
    "                        user       - User supplied string of max 16 bytes",
    "set <portlist> user pattern <string> - A 16 byte string, must set 'pattern user' command",
    "set <portlist> [src|dst] ip ipaddr - Set IP addresses, Source must include network mask "
    "e.g. 10.1.2.3/24",
    CLI_HELP_PAUSE,
    NULL};

static int
set_cmd(int argc, char **argv)
{
    portlist_t portlist;
    char *what, *p;
    int value, n;
    struct cli_map *m;
    struct in_addr ip;
    int prefixlen;

    m = cli_mapping(set_map, argc, argv);
    if (!m)
        return cli_cmd_error("Set command is invalid", "Set", argc, argv);

    portlist_parse(argv[1], &portlist);

    what  = argv[2];
    value = atoi(argv[3]);
    // clang-format off
    switch(m->index) {
        case 10:
            n = cli_map_list_search(m->fmt, argv[2], 2);
            foreach_port(portlist, _do(
                switch(n) {
                    case 0: single_set_tx_count(info, value); break;
                    case 1: single_set_pkt_size(info, valid_pkt_size(argv[3])); break;
                    case 2: single_set_tx_rate(info, argv[3]); break;
                    case 3: single_set_tx_burst(info, value); break;
                    case 4: single_set_port_value(info, what[0], value); break;
                    case 5: single_set_port_value(info, what[0], value); break;
                    case 6: single_set_ttl_value(info, value); break;
                    default:
                        return cli_cmd_error("Set command is invalid", "Set", argc, argv);
                }) );
            break;
        case 20:
            foreach_port(portlist, single_set_pkt_type(info, argv[3]));
            break;
        case 21:
            foreach_port(portlist, single_set_proto(info, argv[3]));
            break;
        case 22:
            {
                struct ether_addr eaddr;
                struct ether_addr *addr = cne_ether_aton(argv[4], &eaddr);

                if (addr == NULL)
                    return cli_cmd_error("Ethernet address is invalid", "Set", argc, argv);

                foreach_port(portlist, single_set_src_mac(info, addr));
                break;
            }
        case 23:
            {
                struct ether_addr eaddr;
                struct ether_addr *addr = cne_ether_aton(argv[4], &eaddr);

                if (addr == NULL)
                    return cli_cmd_error("Ethernet address is invalid", "Set", argc, argv);

                foreach_port(portlist, single_set_dst_mac(info, addr));
                break;
            }
        case 24:
            foreach_port(portlist, pattern_set_type(info, argv[3]));
            break;
        case 25:
            foreach_port(portlist,
                 pattern_set_user_pattern(info, argv[3]));
            break;
        case 30:
            p = strchr(argv[4], '/');
            if (!p)
                CNE_ERR_RET("src IP address should contain subnet value, default /32 for IPv4, /128 for IPv6\n");
            *p++ = '\0';
            errno = 0;
            prefixlen = strtol(p, NULL, 10);
            if (errno)
                CNE_ERR_RET("IP address prefix length: %s\n", strerror(errno));
            if (!inet_aton(argv[4], &ip))
                CNE_ERR_RET("Invalid IP address: %s\n", strerror(errno));
            foreach_port(portlist,
                single_set_ipaddr(info, 's', &ip, prefixlen));
            break;
        case 31:
            /* Remove the /XX mask value if supplied */
            p = strchr(argv[4], '/');
            if (p) {
                CNE_WARN("Subnet mask not required, removing subnet mask value\n");
                *p = '\0';
            }
            if (!inet_aton(argv[4], &ip))
                CNE_ERR_RET("Invalid IP address: %s\n", strerror(errno));
            foreach_port(portlist,
                single_set_ipaddr(info, 'd', &ip, 0));
            break;
        default:
            return cli_cmd_error("Command invalid", "Set", argc, argv);
    }
    // clang-format on
    txgen_update_display();
    return 0;
}

// clang-format off
static struct cli_map pcap_map[] = {
    {10, "pcap %D"},
    {20, "pcap show"},
    {30, "pcap filter %P %s"},
    {-1, NULL}
};
// clang-format on

static const char *pcap_help[] = {
    "", "pcap show                          - Show PCAP information",
    "pcap <index>                       - Move the PCAP file index to the given packet number,  0 "
    "- rewind, -1 - end of file",
    CLI_HELP_PAUSE, NULL};

static int
pcap_cmd(int argc, char **argv)
{
    jcfg_lport_t *lport = txgen.info->lport;
    struct cli_map *m;
    pcap_info_t *pcap;
    uint32_t max_cnt;
    uint32_t value;

    m = cli_mapping(pcap_map, argc, argv);
    if (!m)
        return cli_cmd_error("PCAP command invalid", "PCAP", argc, argv);

    switch (m->index) {
    case 10:
        pcap  = txgen.info[lport->lpid].pcap;
        value = strtoul(argv[1], NULL, 10);

        if (pcap) {
            max_cnt = pcap->pkt_count;
            if (value >= max_cnt)
                pcap->pkt_idx = max_cnt - CNE_MIN(PCAP_PAGE_SIZE, (int)max_cnt);
            else
                pcap->pkt_idx = value;
            txgen.flags |= PRINT_LABELS_FLAG;
        } else
            cne_printf(" ** PCAP file is not loaded on port %d", lport->lpid);
        break;
    case 20:
        for (int i = 0; i < pktdev_port_count(); i++) {
            if (txgen.info[i].pcap)
                _pcap_info(txgen.info[i].pcap, i, 1);
            else
                cne_printf(" ** PCAP file is not loaded on port %d", lport->lpid);
        }
        break;
    default:
        return cli_cmd_error("PCAP command invalid", "PCAP", argc, argv);
    }
    txgen_update_display();
    return 0;
}

static struct cli_map start_map[] = {{10, "start %P"}, {20, "stop %P"}, {-1, NULL}};

static const char *start_help[] = {
    "",
    "start <portlist>                   - Start transmitting packets",
    "stop <portlist>                    - Stop transmitting packets",
    "stp                                - Stop all lports from transmitting",
    "str                                - Start all lports transmitting",
    CLI_HELP_PAUSE,
    NULL};

static int
start_stop_cmd(int argc, char **argv)
{
    struct cli_map *m;
    portlist_t portlist;

    m = cli_mapping(start_map, argc, argv);
    if (!m)
        return cli_cmd_error("Start/Stop command invalid", "Start", argc, argv);

    portlist_parse(argv[1], &portlist);

    switch (m->index) {
    case 10:
        foreach_port(portlist, txgen_start_transmitting(info));
        break;
    case 20:
        foreach_port(portlist, txgen_stop_transmitting(info));
        break;
    default:
        return cli_cmd_error("Start/Stop command invalid", "Start", argc, argv);
    }
    txgen_update_display();
    return 0;
}

// clang-format off
static struct cli_map theme_map[] = {
    {0, "theme"},
    {10, "theme %|on|off"},
    {20, "theme %s %s %s %s"},
    {30, "theme save %s"},
    {-1, NULL}
    };
// clang-format on

static const char *theme_help[] = {
    "",
    "theme <item> <fg> <bg> <attr>      - Set color for item with fg/bg color and attribute "
    "value",
    "theme show                         - List the item strings, colors and attributes to the "
    "items",
    "theme save <filename>              - Save the current color theme to a file",
    CLI_HELP_PAUSE,
    NULL};

static int
theme_cmd(int argc, char **argv)
{
    struct cli_map *m;

    m = cli_mapping(theme_map, argc, argv);
    if (!m)
        return cli_cmd_error("Theme command invalid", "Theme", argc, argv);

    switch (m->index) {
    case 0:
        txgen_theme_show();
        break;
    case 10:
        txgen_theme_state(argv[1]);
        txgen_clear_display();
        break;
    case 20:
        txgen_set_theme_item(argv[1], argv[2], argv[3], argv[4]);
        break;
    case 30:
        txgen_theme_save(argv[2]);
        break;
    default:
        return cli_help_show_group("Theme");
    }
    return 0;
}

// clang-format off
#define ed_type "pcap|"      /*  0 */    \
        "capture|"         /*  1 */

static struct cli_map enable_map[] = {
    { 10, "enable %P %|" ed_type },
    { 20, "disable %P %|" ed_type },
    { 30, "enable screen" },
    { 31, "disable screen"},
    { -1, NULL }
};

static const char *enable_help[] = {
    "",
    "enable|disable <portlist> pcap     - Enable or Disable sending pcap packets on a portlist",
    "enable|disable <portlist> capture  - Enable/Disable packet capturing on a portlist, disable to save capture",
    "                                     Disable capture on a port to save the data into the current working directory"
    "enable|disable screen              - Enable/disable "
    "updating the screen and unlock/lock window",
    "    off                            - screen off shortcut",
    "    on                             - screen on shortcut",
    CLI_HELP_PAUSE,
    NULL};
// clang-format on

static int
en_dis_cmd(int argc, char **argv)
{
    struct cli_map *m;
    portlist_t portlist;
    int n, state;

    m = cli_mapping(enable_map, argc, argv);
    if (!m)
        return cli_cmd_error("Enable/Disable invalid command", "Enable", argc, argv);

    portlist_parse(argv[1], &portlist);

    switch (m->index) {
    case 10:
    case 20:
        n = cli_map_list_search(m->fmt, argv[2], 2);

        state = estate(argv[0]);

        switch (n) {
        case 0:
            foreach_port(portlist, enable_pcap(info, state));
            break;
        case 1:
            foreach_port(portlist, enable_capture(info, state));
            break;
        default:
            return cli_cmd_error("Enable/Disable invalid command or command not supported yet",
                                 "Enable", argc, argv);
        }
        break;
    case 30:
    case 31:
        state = estate(argv[0]);

        txgen_screen(state);
        break;
    default:
        return cli_cmd_error("Enable/Disable invalid command", "Enable", argc, argv);
    }
    txgen_update_display();
    return 0;
}

// clang-format off
static struct cli_map misc_map[] = {
    {10, "clear %P stats"},
    {30, "load %s"},
    {60, "save %s"},
    {70, "redisplay"},
    {100, "reset %P"},
    {110, "restart"},
    {-1, NULL}
    };

static const char *misc_help[] = {
    "",
    "save <path-to-file>                - Save a configuration file using the filename",
    "load <path-to-file>                - Load a command/script file from the given path",
    "clear <portlist> stats             - Clear the statistics",
    "clr                                - Clear all Statistices",
    "reset <portlist>                   - Reset the configuration the lports to the default",
    "rst                                - Reset the configuration for all lports",
    "lports per page [1-6]               - Set the number of lports displayed per page",
    "restart <portlist>                 - Restart or stop a ethernet lport and restart",
    CLI_HELP_PAUSE,
    NULL};
// clang-format on

static int
misc_cmd(int argc, char **argv)
{
    struct cli_map *m;
    portlist_t portlist;
    int paused;

    m = cli_mapping(misc_map, argc, argv);
    if (!m)
        return cli_cmd_error("Misc invalid command", "Misc", argc, argv);

    switch (m->index) {
    case 10:
        portlist_parse(argv[1], &portlist);
        foreach_port(portlist, txgen_clear_stats(info));
        txgen_clear_display();
        break;
    case 30:
        paused = display_is_paused();
        display_pause();
        if (cli_execute_cmdfile(argv[1]))
            cne_printf("load command failed for %s\n", argv[1]);
        if (paused)
            txgen_force_update();
        else
            display_resume();
        break;
    case 60:
        txgen_save(argv[1]);
        break;
    case 70:
        txgen_clear_display();
        break;
    case 100:
        portlist_parse(argv[1], &portlist);
        foreach_port(portlist, txgen_reset(info));
        break;
    case 110:
        portlist_parse(argv[1], &portlist);
        foreach_port(portlist, txgen_port_restart(info));
        break;
    default:
        return cli_cmd_error("Misc invalid command", "Misc", argc, argv);
    }
    return 0;
}

/**********************************************************/
/**********************************************************/
/****** CONTEXT (list of instruction) */

static int help_cmd(int argc, char **argv);

static struct cli_tree default_tree[] = {
    c_dir("/txgen/bin"),
    c_cmd("help", help_cmd, "help command"),

    c_cmd("clear", misc_cmd, "clear stats, ..."),
    c_alias("clr", "clear all stats", "clear all lport stats"),
    c_cmd("load", misc_cmd, "load command file"),
    c_cmd("save", misc_cmd, "save the current state"),
    c_cmd("redisplay", misc_cmd, "redisplay the screen"),
    c_alias("cls", "redisplay", "redraw screen"),
    c_cmd("reset", misc_cmd, "reset txgen configuration"),
    c_alias("rst", "reset all", "reset all lports"),
    c_cmd("restart", misc_cmd, "restart lport"),
    c_cmd("lport", misc_cmd, "Switch between lports"),

    c_cmd("theme", theme_cmd, "Set, save, show the theme"),
    c_cmd("enable", en_dis_cmd, "enable features"),
    c_cmd("disable", en_dis_cmd, "disable features"),
    c_cmd("start", start_stop_cmd, "start features"),
    c_cmd("stop", start_stop_cmd, "stop features"),
    c_alias("str", "start all", "start all lports sending packets"),
    c_alias("stp", "stop all", "stop all lports sending packets"),
    c_cmd("pcap", pcap_cmd, "pcap commands"),
    c_cmd("set", set_cmd, "set a number of options"),

    c_alias("on", "enable screen", "Enable screen updates"),
    c_alias("off", "disable screen", "Disable screen updates"),

    c_end()};

static int
init_tree(void)
{
    /* Add the system default commands in /sbin directory */
    if (cli_default_tree_init())
        return -1;

    /* Add the TXGen directory tree */
    if (cli_add_tree(cli_root_node(), default_tree))
        return -1;

    cli_help_add("Title", NULL, title_help);
    cli_help_add("Enable", enable_map, enable_help);
    cli_help_add("Set", set_map, set_help);
    cli_help_add("PCAP", pcap_map, pcap_help);
    cli_help_add("Start", start_map, start_help);
    cli_help_add("Misc", misc_map, misc_help);
    cli_help_add("Theme", theme_map, theme_help);
    cli_help_add("Status", NULL, status_help);

    /* Make sure the txgen commands are executable in search path */
    if (cli_add_bin_path("/txgen/bin"))
        return -1;

    return 0;
}

static int
my_prompt(int cont __cne_unused)
{
    int nb;
    char line[128];

    display_set_color("txgen.prompt");
    nb = snprintf(line, sizeof(line), "TXGen:%s> ", cli_path_string(NULL, NULL));
    cne_printf("%s", line);
    display_set_color("stats.stat.values");

    return nb;
}

int
txgen_cli_create(void)
{
    int ret = -1;

    if (!cli_create(NULL)) {
        if (!cli_setup_with_tree(init_tree)) {
            cli_set_prompt(my_prompt);
            ret = 0;
        }
    }
    return ret;
}

void
txgen_cli_start(void)
{
    cli_start(NULL);

    cli_destroy();
}

/**
 *
 * Display the help screen and pause if needed.
 *
 * DESCRIPTION
 * Display the help and use pause to show screen full of messages.
 *
 * RETURNS: N/A
 *
 * SEE ALSO:
 */
static int
help_cmd(int argc __cne_unused, char **argv __cne_unused)
{
    int paused;

    paused = display_is_paused();

    if (!paused)
        display_pause();

    vt_setw(1);
    vt_cls();
    vt_pos(1, 1);

    cli_help_show_all("** TXGen Help Information **");

    if (!paused) {
        vt_setw(txgen.last_row + 1);
        display_resume();
        txgen_clear_display();
    }
    return 0;
}
