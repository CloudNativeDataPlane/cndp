/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <stdio.h>        // for stdout, NULL
#include <regex.h>
#include <immintrin.h>             // for __m256i
#include <cnet.h>                  // for cnet, per_thread_cnet, this_cnet, cnet_l...
#include <cnet_stk.h>              // for per_thread_stk, this_stk, stk_entry, cne...
#include <cne_inet.h>              // for
#include <cnet_drv.h>              // for drv_entry
#include <cnet_pcb.h>              // for cnet_pcb_dump, cnet_pcb_dump_details
#include <cnet_tcp.h>              // for cnet_tcb_list, seg_entry
#include <cnet_route.h>            // for
#include <cnet_netif.h>            // for netif
#include <cnet_route4.h>           // for cnet_route4_show
#include <cnet_arp.h>              // for cnet_arp_show
#include <hmap.h>                  // for hmap_list_dump
#include <cnet_ip_common.h>        // for ip_info
#include <cnet_meta.h>             // for cnet_metadata
#include <cne_fib.h>               // for cne_fib, cne_fib_rule, cne_fib_rule_info
#include <cnet_ifshow.h>           // for cnet_ifshow
#include <cnet_rtshow.h>           // for cnet_rtshow
#include <emmintrin.h>             // for __m128i
#include <stdint.h>                // for uint16_t, uint64_t, uint8_t, int32_t
#include <stdlib.h>                // for atoi
#include <string.h>                // for strcmp, strerror
#include <cne_graph.h>             // for

#include <cli.h>        // for c_cmd, cli_add_tree, cli_usage, c_alias

#include "cne_common.h"        // for __cne_unused, CNE_PKTMBUF_HEADROOM
#include "cne_log.h"           // for cne_panic
#include "cne_vec.h"
#include "cnet_const.h"          // for CNET_COUNT_PER_VEC, __offsetof
#include "cnet_ipv4.h"           // for ipv4_entry
#include "cnet_protosw.h"        // for cnet_protosw_dump, protosw_entry
#include "cnet_netlink.h"
#include "pktdev_api.h"        // for pktdev_port_count, pktdev_start, pktdev_...
#include "pktmbuf.h"           // for DEFAULT_MBUF_SIZE, pktmbuf_t
#include "../chnl/chnl_priv.h"
#include "cnet_chnl.h"        // for chnl_list
#include <cnet_node_names.h>

#define _prt(_s)                                                           \
    do {                                                                   \
        snprintf(pbuff, sizeof(pbuff), "sizeof([cyan]struct %s[])", #_s);  \
        cne_printf("%-40s : [magenta]%4lu[]\n", pbuff, sizeof(struct _s)); \
    } while (0)

#define gfprintf(f, format, args...)                 \
    do {                                             \
        if (fprintf(f, format, ##args) < 0)          \
            CNE_ERR_RET("fprintf returned error\n"); \
        fflush(f);                                   \
    } while (0)

static int remove_pkt_drop = 1;

static int
dump_sizes(void)
{
    char pbuff[128];
    uint64_t total, tot;
    uint16_t stk_cnt, drv_cnt;

    stk_cnt = vec_len(this_cnet->stks);
    drv_cnt = vec_len(this_cnet->drvs);

    tot   = sizeof(struct cnet);
    total = tot;
    cne_printf("\n");
    _prt(pktmbuf_s);
    cne_printf("[cyan]%32s[] : [magenta]%4ld[]\n", "CNE_PKTMBUF_HEADROOM", CNE_PKTMBUF_HEADROOM);
    cne_printf("  		[cyan]Default size [magenta]%d [cyan]dataroom size [magenta]%'ld[]\n",
               DEFAULT_MBUF_SIZE,
               DEFAULT_MBUF_SIZE - (sizeof(struct pktmbuf_s) + CNE_PKTMBUF_HEADROOM));
    _prt(cnet_metadata);
    cne_printf("               [cyan]unused space in metadata structure [magenta]%lu[]\n",
               sizeof(struct cnet_metadata) - __offsetof(struct cnet_metadata, end_metadata));
    if (sizeof(struct cnet_metadata) > CNE_PKTMBUF_HEADROOM)
        cne_printf("      ** [red]Warning[] [cyan]cnet_metadata[] > CNE_PKTMBUF_HEADROOM\n");
    _prt(in_caddr);
    _prt(cnet);
    _prt(pcb_entry);
    _prt(pcb_key);
    _prt(msghdr);
    _prt(sockaddr);
    _prt(sockaddr_storage);

    tot = (sizeof(stk_t) * stk_cnt);
    total += tot;
    _prt(stk_s);
    cne_printf("%32s : * %5d([cyan]lcores[]) = [magenta]%lu[]\n", "", stk_cnt, tot);

    tot = (sizeof(struct netif) * (stk_cnt * drv_cnt));
    total += tot;
    _prt(netif);
    cne_printf("%32s : * %5d([cyan]netifs[]) = [magenta]%lu[]\n", "", (stk_cnt * drv_cnt), tot);

    tot = (sizeof(struct drv_entry) * drv_cnt);
    total += tot;
    _prt(drv_entry);
    cne_printf("%32s : * %5d([cyan]ports[])  = [magenta]%lu[]\n", "", drv_cnt, tot);

    tot = (sizeof(struct rt4_entry) * this_cnet->num_routes);
    total += tot;
    _prt(rt4_entry);
    cne_printf("%32s : * %5d([cyan]routes[]) = [magenta]%lu[]\n", "", this_cnet->num_routes, tot);

    tot = sizeof(struct ipv4_entry);
    total += tot;
    _prt(ipv4_entry);

    tot = (sizeof(struct arp_entry) * this_cnet->num_arps);
    total += tot;
    _prt(arp_entry);
    cne_printf("%32s : * %5d([cyan]routes[]) = [magenta]%lu[]\n", "", this_cnet->num_arps, tot);

    cne_printf("\n  Total memory used [magenta]%lu[] bytes\n", total);

    cne_printf("\n");
    _prt(protosw_entry);
    _prt(seg_entry);

    snprintf(pbuff, sizeof(pbuff), "sizeof([cyan]__m128i[])");
    cne_printf("%40s : [magenta]%4lu[]\n", pbuff, sizeof(__m128i));
    snprintf(pbuff, sizeof(pbuff), "sizeof([cyan]__m256i[])");
    cne_printf("%40s : [magenta]%4lu[]\n", pbuff, sizeof(__m256i));

    _prt(vec_hdr);

    return 0;
}

#define _off(e, v)                                                                     \
    do {                                                                               \
        pktmbuf_t m;                                                                   \
        uint32_t o = offsetof(pktmbuf_t, v);                                           \
        uint32_t s = sizeof(m.v);                                                      \
        cne_printf("  [cyan]%-14s[]: [magenta]sizeof [orange]%3u[], [magenta]offset "  \
                   "[orange]%3u[], [magenta]Next [orange]%3u[]",                       \
                   #v, s, o, o + s);                                                   \
        if (e != o)                                                                    \
            cne_printf(" [red]%s [orange]%d[]", (e != o) ? "Hole found:" : "", o - e); \
        cne_printf("\n");                                                              \
        e = o + s;                                                                     \
    } while (0)

static int
dump_mbuf(void)
{
    uint32_t e = 0;

    cne_printf("[magenta]Dump MBUF structure offsets, size [orange]%lu [magenta]bytes[]\n",
               sizeof(pktmbuf_t));

    _off(e, pooldata);
    _off(e, buf_addr);
    _off(e, hash);
    _off(e, meta_index);
    _off(e, data_off);
    _off(e, lport);
    _off(e, buf_len);
    _off(e, data_len);
    _off(e, packet_type);

    _off(e, refcnt);
    _off(e, rsvd16);
    _off(e, tx_offload);
    _off(e, ol_flags);
    _off(e, udata64);

    return 0;
}

// clang-format off
static struct cli_map info_map[] = {
    {10, "info"},
    {11, "info show"},
    {40, "info size"},
    {45, "info mbuf"},
    {-1, NULL}
    };
// clang-format on
static int
cmd_info(int argc, char **argv)
{
    struct cli_map *m;

    m = cli_mapping(info_map, argc, argv);
    if (!m)
        return cli_cmd_error("Info command is invalid", "Info", argc, argv);

    switch (m->index) {
    case 10:
    case 11:
        cnet_dump();
        return 0;
    case 40:
        return dump_sizes();
    case 45:
        return dump_mbuf();
    default:
        return cli_cmd_error("Command invalid", "Info", argc, argv);
    }

    return 0;
}

static int
cmd_chnl(int argc __cne_unused, char **argv __cne_unused)
{
    stk_t *stk;

    vec_foreach_ptr (stk, this_cnet->stks)
        chnl_list(stk);

    return 0;
}

static int
cmd_pcb(int argc __cne_unused, char **argv __cne_unused)
{
    stk_t *stk;

    vec_foreach_ptr (stk, this_cnet->stks)
        cnet_pcb_dump(stk);

    return 0;
}

static int
cmd_proto(int argc __cne_unused, char **argv __cne_unused)
{
    stk_t *stk;

    vec_foreach_ptr (stk, this_cnet->stks)
        cnet_protosw_dump(stk);

    return 0;
}

static int
cmd_hmap(int argc __cne_unused, char **argv __cne_unused)
{
    hmap_list_dump(stdout, 1);
    return 0;
}

/*
 * Local wrapper function to test mp is NULL and return or continue
 * to call mempool_dump() routine.
 */
static void
__obj_dump(const char *msg, struct cne_mempool *mp)
{
    if (mp == NULL)
        return;
    cne_printf("[magenta]=== [cyan]%s[]\n", msg);
    mempool_dump(mp);
}

static int
cmd_obj(int argc, char **argv)
{
    const char *pool  = (argc > 1) ? argv[1] : "all";
    bool all          = false;
    struct cnet *cnet = this_cnet;

    if (strcasecmp(pool, "all") == 0)
        all = true;

    if (all || !strcmp(pool, "rt4"))
        __obj_dump("rt4", cnet->rt4_obj);

    for (uint32_t i = 0; i < vec_len(cnet->stks); i++) {
        stk_t *stk = vec_at_index(cnet->stks, i);

        cne_printf("\n[yellow]******** [cyan]%s [yellow]********[]\n", stk->name);
        if (all || !strcmp(pool, "tcb"))
            __obj_dump("tcp", stk->tcb_objs);
        if (all || !strcmp(pool, "pcb"))
            __obj_dump("pcb", stk->pcb_objs);
        if (all || !strcmp(pool, "seg"))
            __obj_dump("seg", stk->seg_objs);
        if (all || !strcmp(pool, "arp"))
            __obj_dump("arp", cnet->arp_obj);
        if (all || !strcmp(pool, "chnl"))
            __obj_dump("chnl", stk->chnl_objs);
    }

    return 0;
}

static int
graph_header(FILE *f, const char *name)
{
    gfprintf(f, "digraph %s {\n\trankdir=LD; bgcolor=mistyrose\n", name);
    gfprintf(f, "\tlabel=<<font color='black'>Graph Name: </font>");
    gfprintf(f, "<font color='blue' point-size='20'> <b>%s</b></font>%s>\n", name,
             (remove_pkt_drop) ? "      <font color='black'><b>(pkt_drop removed)</b></font>" : "");
    gfprintf(f, "\tedge [color=blue, arrowsize=0.6]\n");
    gfprintf(f, "\tnode [margin=0.1 fontcolor=black fontsize=16 width=0.8 ");
    gfprintf(f, "shape=box color=black style=\"filled,rounded\"]\n");

    return 0;
}

static inline const char *
_node_style(char *name, int src)
{
    regex_t regex;
    int ret;
    struct node_style {
        int src;
        const char *pattern;
        const char *style;
    } styles[] = {
        // clang-format off
        { 0,                    "ip4_*",                 "[fillcolor=mediumspringgreen]" },
        { 0,                    "udp_*",                 "[fillcolor=cornsilk]" },
        { 0,                    PKT_DROP_NODE_NAME,      "[fillcolor=lightgrey]" },
        { 0,                    CHNL_CALLBACK_NODE_NAME, "[fillcolor=lightgrey]" },
        { 0,                    "chnl_*",                "[fillcolor=yellowgreen]" },
        { 0,                    KERNEL_RECV_NODE_NAME,   "[fillcolor=lightcoral]" },
        { 0,                    ETH_RX_NODE_NAME"*",     "[fillcolor=lavender]" },
        { 0,                    ARP_REQUEST_NODE_NAME,   "[fillcolor=mediumspringgreen]" },
        { 0,                    ETH_TX_NODE_NAME"*",     "[fillcolor=cyan]" },
        { 0,                    PUNT_KERNEL_NODE_NAME,   "[fillcolor=coral]" },
        { 0,                    PTYPE_NODE_NAME,         "[fillcolor=goldenrod]" },
        { 0,                    GTPU_INPUT_NODE_NAME,    "[fillcolor=lightskyblue]" },
        { 0,                    "tcp_*",                 "[fillcolor=lightpink]" },
        { CNE_NODE_SOURCE_F,    NULL,                    "[fillcolor=cyan]" },
        { CNE_NODE_INPUT_F,     NULL,                    "[fillcolor=lightskyblue]" },
        { 0,                    NULL,                    "[fillcolor=lightgrey]" }
        // clang-format on
    };

    for (int i = 0; i < cne_countof(styles); i++) {
        struct node_style *s = &styles[i];

        if (s->pattern && s->pattern[0]) {
            ret = regcomp(&regex, s->pattern, REG_NOSUB | REG_ICASE);
            if (ret) {
                char buff[256] = {0};

                (void)regerror(ret, &regex, buff, sizeof(buff));
                CNE_NULL_RET("regex compile error: %s\n", buff);
            }

            ret = regexec(&regex, name, 0, NULL, 0);
            regfree(&regex);
            if (ret == 0) /* Found a match */
                return s->style;
        } else {
            if (src == s->src)
                return s->style;
        }
    }
    return "";
}

static int
graph_body(FILE *f, char *name, char **adj_names, cne_edge_t nb_edges, int src)
{
    const char *s = _node_style(name, src);
    int edge_cnt  = nb_edges;

    if (remove_pkt_drop) {
        if (!strncmp(name, "pkt_drop", 8)) /* Skip the node named pkt_drop */
            return 0;

        for (int i = 0; i < nb_edges; i++) {
            if (adj_names[i] && !strncmp(adj_names[i], "pkt_drop", 8)) {
                memcpy(&adj_names[i], &adj_names[i + 1], (nb_edges - i) * sizeof(char *));
                edge_cnt--;
            }
        }
    }

    if (s && strlen(s) > 0)
        gfprintf(f, "\t{\"%s\" %s}", name, s);
    else
        gfprintf(f, "\t\"%s\"", name);

    if (edge_cnt > 1)
        gfprintf(f, "->{");
    else if (edge_cnt > 0)
        gfprintf(f, "->");

    for (int i = 0; i < edge_cnt; i++)
        gfprintf(f, "\"%s\"%s", adj_names[i], (i < (edge_cnt - 1)) ? " " : "");

    if (edge_cnt > 1)
        gfprintf(f, "}");
    gfprintf(f, "\n");

    return 0;
}

static int
graph_trailer(FILE *f)
{
    if (fprintf(f, "}\n") < 0)
        return -1;

    return 0;
}

static int
graph_write(const char *gname)
{
    char filename[256];
    FILE *f;

    if (snprintf(filename, sizeof(filename), "%s.dot", gname) < 0)
        CNE_ERR_RET("sprintf failed\n");

    f = fopen(filename, "w+");
    if (f) {
        // clang-format off
        cne_graph_export_t export = {
            .header  = graph_header,
            .body    = graph_body,
            .trailer = graph_trailer
        };
        // clang-format on

        if (cne_graph_export_cb(gname, f, &export) < 0) {
            fclose(f);
            unlink(filename);
            CNE_ERR_RET("[magenta]Failed to save graph [red]%s [magenta]to filename [cyan]%s[]\n",
                        gname, filename);
        }
        fclose(f);
        chmod(filename, 0666);
        cne_printf("[magenta]Saved graph [red]%s [magenta]to filename [cyan]%s[]\n", gname,
                   filename);
    } else
        CNE_ERR_RET("fopen(%s) failed\n", filename);
    return 0;
}

static int
graph_dot_save(const char *gname)
{
    if (!strncmp("all", gname, 3)) {
        for (int i = 0; i < cne_graph_max_count(); i++) {
            char *name = cne_graph_id_to_name(i);

            if (name)
                graph_write(name);
        }
    } else
        return graph_write(gname);
    return 0;
}

// clang-format off
static struct cli_map graph_map[] = {
    {10, "graph list"},
    {20, "graph nodes"},
    {21, "graph node %s"},
    {25, "graph dump"},
    {26, "graph dump %s"},
    {30, "graph dot"},
    {35, "graph dot %s"},
    {40, "graph stats"},
    {41, "graph stats %d"},
    {50, "graph drop"},
    {-1, NULL}
    };
// clang-format on
static int
cmd_graph(int argc, char **argv)
{
    struct cne_graph_cluster_stats_param s_param = {0};
    static struct cne_graph_cluster_stats *stats = NULL;
    const char *pattern                          = "cnet_*";
    struct cli_map *m;
    int cnt = 1;

    m = cli_mapping(graph_map, argc, argv);
    if (!m)
        return cli_cmd_error("command is invalid", "Graph", argc, argv);

    switch (m->index) {
    case 10:
        for (int i = 0; i < cne_graph_max_count(); i++) {
            char *name = cne_graph_id_to_name(i);

            cne_printf("[magenta]Graph [red]%3d[]: [cyan]%s[]\n", i, name);
        }
        return 0;
    case 20:
        cne_node_list_dump(NULL);
        return 0;
    case 21:
        cne_node_dump(NULL, cne_node_from_name(argv[2]));
        return 0;
    case 25:
        cne_graph_list_dump(NULL);
        return 0;
    case 30:
        graph_dot_save("all");
        return 0;
    case 35:
        graph_dot_save(argv[2]);
        return 0;
    case 40:
        break;
    case 41:
        cnt = atoi(argv[2]);
        if (cnt < 0 || cnt > (5 * 60)) /* Limit to 5 minutes */
            cnt = 1;
        break;
    case 50:
        remove_pkt_drop = (remove_pkt_drop == 0) ? 1 : 0;
        cne_printf("%sShowing pkt_drop node\n", remove_pkt_drop ? "Not " : "");
        return 0;
    default:
        return cli_cmd_error("Command invalid", "Graph", argc, argv);
    }

    if (!stats) {
        /* Prepare stats object */
        s_param.graph_patterns    = &pattern;
        s_param.nb_graph_patterns = 1;

        stats = cne_graph_cluster_stats_create(&s_param);
        if (!stats)
            return -1;
    }

    vt_make_space(cne_graph_stats_node_count(stats) + 4);
    while (cnt--) {
        vt_save();
        cne_graph_cluster_stats_get(stats, 0);
        if (cnt) {
            vt_restore();
            sleep(1);
        }
    }

    cne_graph_cluster_stats_destroy(stats);
    stats = NULL;

    return 0;
}

static int
cmd_netlink(int argc, char **argv)
{
    if (argc > 1)
        netlink_debug = atoi(argv[1]);
    cne_printf("[magenta]Netlink Debug[]: [orange]%d[]\n", netlink_debug);
    return 0;
}

// clang-format off
static struct cli_map ip_map[] = {
    {10, "ip link"},
    {11, "ip link %s"},
    {20, "ip route"},
    {30, "ip neigh"},
    {40, "ip stats"},
    {41, "ip stats %d"},
    {-1, NULL}
    };
// clang-format on
static int
cmd_ip(int argc, char **argv)
{
    struct cli_map *m;
    stk_t *stk   = NULL;
    uint32_t idx = 0;

    m = cli_mapping(ip_map, argc, argv);
    if (!m)
        return cli_cmd_error("Info command is invalid", "ip", argc, argv);

    switch (m->index) {
    case 10:
        if (cnet_ifshow(NULL) < 0)
            return -1;
        break;
    case 11:
        if (cnet_ifshow(argv[2]) < 0)
            return -1;
        break;
    case 20:
        if (cnet_rtshow(NULL, argc, argv) < 0)
            return -1;
        break;
    case 30:
        if (cnet_arp_show() < 0)
            return -1;
        return 0;
    case 40:
        if (cnet_ipv4_stats_dump(stk) < 0)
            return -1;
        break;
    case 41:
        idx = atoi(argv[2]);

        if (idx < vec_len(this_cnet->stks))
            stk = vec_at_index(this_cnet->stks, idx);
        else
            CNE_WARN("Unknown stack index showing all\n");

        if (cnet_ipv4_stats_dump(stk) < 0)
            return -1;
        break;
    default:
        return cli_cmd_error("Command invalid", "ip", argc, argv);
    }

    return 0;
}

static int
cmd_ip_cksum(int argc __cne_unused, char **argv __cne_unused)
{
    struct cne_ipv4_hdr ip = {0};
    uint16_t cksum;

    ip.version_ihl     = 0x45;
    ip.type_of_service = 55;
    ip.total_length    = 128;
    ip.packet_id       = 1234UL;
    ip.fragment_offset = 0;
    ip.time_to_live    = 64;
    ip.next_proto_id   = 17;
    ip.hdr_checksum    = 0;
    ip.src_addr        = 0xc0120001;
    ip.dst_addr        = 0xc0120004;

    cksum           = cne_ipv4_cksum(&ip);
    ip.hdr_checksum = cksum;
    cne_printf("[magenta]Checksum[]   : [orange]%04x[] calculated value\n", cksum);
    cne_printf("[magenta]Re-Checksum[]: [orange]%04x[] with validate checksum should be zero\n",
               cne_ipv4_cksum(&ip));
    ip.hdr_checksum = cksum + 1;
    cne_printf("[magenta]Re-Checksum[]: [orange]%04x[] increment checksum\n", cne_ipv4_cksum(&ip));
    ip.hdr_checksum = cksum - 1;
    cne_printf("[magenta]Re-Checksum[]: [orange]%04x[] decrement checksum\n", cne_ipv4_cksum(&ip));
    ip.hdr_checksum = 0xFFFF;
    cne_printf("[magenta]Re-Checksum[]: [orange]%04x[] checksum set to 0xFFFF\n",
               cne_ipv4_cksum(&ip));

    return 0;
}

#define _(_s)                                                    \
    do {                                                         \
        stk_t *stk;                                              \
        cne_printf("[magenta]%-16s[]: ", #_s);                   \
        vec_foreach_ptr (stk, cnet->stks) {                      \
            cne_printf("[cyan]%8ld[] ", stk->tcp_stats->S_##_s); \
        }                                                        \
        cne_printf("\n");                                        \
    } while (/* CONSTCOND */ 0)

// clang-format off
static struct cli_map tcp_map[] = {
    {10, "tcp"},
    {11, "tcp stats"},
    {-1, NULL}
    };
// clang-format on

static int
cmd_tcp(int argc, char **argv)
{
    struct cnet *cnet = this_cnet;
    struct cli_map *m;

    m = cli_mapping(tcp_map, argc, argv);
    if (!m)
        return cli_cmd_error("Info command is invalid", "tcp", argc, argv);

    switch (m->index) {
    case 10:
    case 11:
        _(TCPS_CLOSED);
        _(TCPS_LISTEN);
        _(TCPS_SYN_SENT);
        _(TCPS_SYN_RCVD);
        _(TCPS_ESTABLISHED);
        _(TCPS_CLOSE_WAIT);
        _(TCPS_FIN_WAIT_1);
        _(TCPS_CLOSING);
        _(TCPS_LAST_ACK);
        _(TCPS_FIN_WAIT_2);
        _(TCPS_TIME_WAIT);

        _(no_syn_rcvd);
        _(invalid_ack);
        _(tcp_rst);
        _(ack_predicted);
        _(data_predicted);
        _(rx_total);
        _(rx_short);
        _(rx_badoff);
        _(delayed_ack);
        _(tcp_rexmit);
        _(resets_sent);
        _(tcp_connect);
        break;
    default:
        return cli_cmd_error("Command invalid", "tcp", argc, argv);
    }

    return 0;
}
#undef _

// clang-format off
static struct cli_map tcb_map[] = {
    {10, "tcb"},
    {11, "tcb show"},
    {-1, NULL}
    };
// clang-format on

static int
cmd_tcb(int argc, char **argv)
{
    struct cli_map *m;

    m = cli_mapping(tcb_map, argc, argv);
    if (!m)
        return cli_cmd_error("Info command is invalid", "tcb", argc, argv);

    switch (m->index) {
    case 10:
    case 11:
        cnet_tcb_dump();
        break;
    default:
        return cli_cmd_error("Command invalid", "tcb", argc, argv);
    }

    return 0;
}

// clang-format off
static struct cli_tree cnet_tree[] = {
    c_bin("/cnet"),
    c_cmd("info",       cmd_info,       "CNET information [show|size|mbuf]"),
    c_cmd("chnl",       cmd_chnl,       "Channel information"),
    c_cmd("pcb",        cmd_pcb,        "pcb dump"),
    c_cmd("proto",      cmd_proto,      "Protosw dump"),
    c_cmd("ip",         cmd_ip,         "Show IP interface information [link|route|neigh|stats]"),
    c_cmd("hmap",       cmd_hmap,       "dump out the hashmap data"),
    c_cmd("obj",        cmd_obj,        "objpool show command"),
    c_cmd("graph",      cmd_graph,      "CNET Graph information [list|node|dump|dot|stats]"),
    c_cmd("netlink",    cmd_netlink,    "Enable/Disable Netlink messages"),
    c_cmd("ipcksum",    cmd_ip_cksum,   "Test IP checksum"),
    c_cmd("tcp",        cmd_tcp,        "TCP information"),
    c_cmd("tcb",        cmd_tcb,        "TCB information"),
    c_alias("gstats",   "graph stats",  "Show Graph statistics"),
    c_alias("ifs",      "ip link",      "display the link interface details"),
    c_alias("ifc",      "ip link",      "display the link interface details"),
    c_alias("arp",      "ip neigh",     "display the neighbour interface details"),
    c_alias("route",    "ip route",     "display the route interface details"),
    c_alias("gdot",     "graph dot",    "dump out the graph information in dot format"),
    c_alias("tstats",   "tcp stats",    "dump out the TCP statistics"),
    c_end()
};
// clang-format on

int
cnet_add_cli_cmds(void)
{
    return cli_add_tree(NULL, cnet_tree);
}
