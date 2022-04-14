/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <arpa/inet.h>           // for inet_ntop
#include <signal.h>              // for SIGINT, SIGUSR1, SIGTERM
#include <stdint.h>              // for uint64_t, uint8_t, uint16_t, uint...
#include <stdio.h>               // for snprintf, fflush, stdout, NULL
#include <stdlib.h>              // for realloc
#include <string.h>              // for memset, memcpy, strdup
#include <sys/socket.h>          // for AF_INET
#include <unistd.h>              // for sleep, getpid
#include <net/ethernet.h>        // for ether_addr
#include <netinet/in.h>          // for INET6_ADDRSTRLEN, in_addr, htonl
#include <sched.h>               // for cpu_set_t
#include <stddef.h>              // for offsetof
#include <locale.h>

#include <cne_branch_prediction.h>        // for likely
#include <cne_common.h>                   // for __cne_unused, CNE_MAX_ETHPORTS
#include <cne_log.h>                      // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_INFO
#include <cne_system.h>                   // for cne_lcore_id
#include <cne_vect.h>                     // for xmm_t
#include <net/cne_ip.h>                   // for CNE_IPV4
#include <cne_ether.h>                    // for ether_addr_copy, ETHER_LOCAL_ADMI...
#include <cne_timer.h>
#include <jcfg.h>        // for jcfg_thd_t, jcfg_lport_t, jcfg_lg...
#include <cli.h>
#include <cli_file.h>

#include <cnet.h>
#include <cnet_stk.h>
#include <cnet_chnl.h>
#include <cnet_chnl_opt.h>
#include <cnet_ifshow.h>

#include <cne_graph.h>               // for cne_graph_cluster_stats_param
#include <cne_graph_worker.h>        // for cne_graph_walk, cne_graph
#include <eth_node_api.h>            // for cnet_node_eth_config, cnet_node_pkt...
#include <ip4_node_api.h>            // for cnet_node_ip4_forward_add, cnet_nod...
#include <cnet_netlink.h>
#include <cnet_inet.h>        // for cnet_inet

#include "cnet-graph.h"
#include "cne.h"               // for cne_id, cne_init, cne_on_exit
#include "pktdev_api.h"        // for pktdev_close, pktdev_is_valid_port

static struct cnet_info cnet_info;
struct cnet_info *cinfo = &cnet_info;

#define foreach_thd_lport(_t, _lp) \
    for (int _i = 0; _i < _t->lport_cnt && (_lp = _t->lports[_i]); _i++, _lp = _t->lports[_i])

static struct pkt_eth_node_config pkt_conf[CNE_MAX_ETHPORTS];

static inline int
add_graph_pattern(graph_info_t *gi, const char *pattern)
{
    if ((gi->cnt + 1) > gi->nb_patterns) {
        gi->cnt++;
        gi->patterns = realloc(gi->patterns, ((gi->cnt + 1) * sizeof(char *)));
        if (!gi->patterns)
            CNE_ERR_RET("Failed to realloc patterns\n");
    }
    gi->patterns[gi->nb_patterns++] = strdup(pattern);
    gi->patterns[gi->nb_patterns]   = NULL;
    return 0;
}

static int
initialize_graph(jcfg_thd_t *thd, graph_info_t *gi)
{
    obj_value_t *pattern_array;
    jcfg_lport_t *lport;
    char graph_name[CNE_GRAPH_NAMESIZE + 1];
    char node_name[CNE_GRAPH_NAMESIZE + 1];
    int ret;

    snprintf(graph_name, sizeof(graph_name), "cnet_%d", cne_id());

    cne_printf("[magenta]Graph Name[]: '[orange]%s[]', [magenta]Thread name [orange]%s[]\n",
               graph_name, thd->name);
    ret = jcfg_option_array_get(cinfo->jinfo, thd->name, &pattern_array);
    if (ret < 0)
        CNE_ERR_GOTO(err, "Unable to find %s option name\n", thd->name);

    if (pattern_array->array_sz == 0)
        CNE_ERR_GOTO(err, "Thread %s does not have any graph patterns\n", thd->name);

    cne_printf("  [magenta]Patterns[]: ");
    for (int i = 0; i < pattern_array->array_sz; i++) {
        char *pat = pattern_array->arr[i]->str;

        if ((CNET_ENABLE_TCP == 0) && !strncasecmp("tcp*", pat, 4))
            continue;
        cne_printf("'[orange]%s[]' ", pat);

        if (add_graph_pattern(gi, pat))
            goto err;
    }
    cne_printf("\n");

    foreach_thd_lport (thd, lport) {
        snprintf(node_name, sizeof(node_name), "eth_rx-%u", lport->lpid);
        if (add_graph_pattern(gi, node_name))
            goto err;
    }

    gi->id = cne_graph_create(graph_name, gi->patterns);
    if (gi->id == CNE_GRAPH_ID_INVALID)
        CNE_ERR_GOTO(err, "cne_graph_create(): graph_id '%s' for uid %u\n", graph_name, cne_id());

    gi->graph = cne_graph_lookup(graph_name);
    if (!gi->graph)
        CNE_ERR_GOTO(err, "cne_graph_lookup(): graph '%s' not found\n", graph_name);

    free(gi->patterns);

    return 0;
err:
    free(gi->patterns);
    cne_graph_destroy(gi->id);
    return -1;
}

static int
udp_recv_callback(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    return chnl_send(ch, mbufs, nb_mbufs); /* Return number of mbufs processed */
}

static int
tcp_recv_callback(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs)
{
    CNE_SET_USED(ch);
    CNE_SET_USED(mbufs);
    CNE_SET_USED(nb_mbufs);

    return 0;
}

static int
app_create_channel(int domain, int type, int proto, const char *name, int port, chnl_cb_t cb)
{
    struct in_caddr addr;
    struct chnl *ch = NULL;
    uint32_t opt;

    ch = channel(domain, type, proto, cb);
    if (!ch)
        CNE_ERR_RET("channel call failed\n");

    in_caddr_zero(&addr);

    opt = 1;
    chnl_set_opt(ch, SO_CHANNEL, SO_REUSEADDR, &opt, sizeof(uint32_t));

    opt = (cinfo->flags & FWD_ENABLE_UDP_CKSUM) ? 1 : 0;
    chnl_set_opt(ch, proto, SO_UDP_CHKSUM, &opt, sizeof(uint32_t));

    if (inet_pton(AF_INET, name, (void *)&addr.cin_addr.s_addr) != 1)
        CNE_ERR_RET("Unable to convert IP address to network order\n");

    addr.cin_family = domain;
    addr.cin_len    = (domain == AF_INET) ? sizeof(struct in_addr) : sizeof(struct in6_addr);
    addr.cin_port   = htobe16(port);

    if (chnl_bind(ch, (struct sockaddr *)&addr, sizeof(struct in_caddr)) == -1)
        CNE_ERR_RET("chnl_bind() failed\n");

    if (type == SOCK_STREAM)
        chnl_listen(ch, CNET_TCP_BACKLOG_COUNT);

    return 0;
}

static int
app_parse_chnl(char *chnl_str)
{
    char *info[5];
    char tmp_line[128];
    chnl_cb_t fn;
    int domain, typ, proto, port_id, ret;

    strlcpy(tmp_line, chnl_str, sizeof(tmp_line));
    ret = cne_strtok(tmp_line, ":", info, cne_countof(info));
    if (ret != 4)
        CNE_ERR_RET("Invalid number of values in channel description\n");

    domain = typ = 0;
    if (!strncasecmp(info[0], "udp4", 4)) {
        domain = AF_INET;
        typ    = SOCK_DGRAM;
    } else if (!strncasecmp(info[0], "tcp4", 4)) {
        if (CNET_ENABLE_TCP) {
            domain = AF_INET;
            typ    = SOCK_STREAM;
        } else {
            cne_printf(" [cyan]TCP is disabled[]");
            return 1;
        }
    } else {
        cne_printf(" [cyan]Invalid socket type specified[]");
        return 1;
    }

    proto   = atoi(info[1]);
    port_id = atoi(info[3]);
    fn      = (typ == SOCK_STREAM) ? tcp_recv_callback : udp_recv_callback;

    return app_create_channel(domain, typ, proto, info[2], port_id, fn);
}

/* Main processing loop */
void
thread_func(void *arg)
{
    jcfg_thd_t *thd = arg;
    obj_value_t *chnl_array;
    char chnl_name[CNE_GRAPH_NAMESIZE + 1];
    graph_info_t *gi;
    pthread_t pid = pthread_self();
    int tid, ret;

    if (thd->group->lcore_cnt > 0) {
        if (pthread_setaffinity_np(pid, sizeof(cpu_set_t), &thd->group->lcore_bitmap) < 0)
            CNE_RET("pthread_setaffinity_np('%s') failed\n", thd->name);
    }

    CNE_DEBUG("Graph assigned to lcore %d\n", cne_lcore_id());

    /* Wait for main thread to initialize */
    if (pthread_barrier_wait(&cinfo->barrier) > 0)
        CNE_ERR_GOTO(err, "Failed to wait for barrier\n");

    if (cnet_stk_initialize(cinfo->cnet) < 0)
        CNE_RET("cnet_stk_initialize('%s') failed\n", thd->name);

    if ((tid = cne_id()) < 0)
        CNE_ERR_GOTO(err, "Failed to get cne id\n");

    if (tid >= cne_countof(cinfo->graph_info))
        CNE_ERR_GOTO(err, "Number of threads cannot be >= %d\n", cne_countof(cinfo->graph_info));
    gi = &cinfo->graph_info[tid];

    if (initialize_graph(thd, gi))
        CNE_ERR_GOTO(err, "Initialize_graph() failed\n");
    this_stk->graph = gi->graph;

    /* Construct the options key name <thread-name>-chnl */
    snprintf(chnl_name, sizeof(chnl_name), "%s-chnl", thd->name);

    ret = jcfg_option_array_get(cinfo->jinfo, chnl_name, &chnl_array);
    if (ret < 0) {
        CNE_WARN("Unable to find %s option name\n", thd->name);
        goto skip;
    }

    if (chnl_array->array_sz == 0) {
        CNE_WARN("Thread %s does not have any graph patterns\n", thd->name);
        goto skip;
    }

    cne_printf("  [magenta]Channels[]: [cyan]%s[]\n%-12s", chnl_name, "");
    for (int i = 0; i < chnl_array->array_sz; i++) {
        char *s = chnl_array->arr[i]->str;

        if (!s || (s[0] == '\0'))
            CNE_ERR_GOTO(err, "string is NULL or empty\n");

        cne_printf("'[orange]%s[]'", s);
        ret = app_parse_chnl(s);
        if (ret < 0)
            break;
        cne_printf("\n%-12s", "");
    }
    cne_printf("\r");

skip:
    while (likely(!thd->quit))
        cne_graph_walk(gi->graph);

    return;
err:
    (void)pthread_barrier_wait(&cinfo->barrier);
}

static int
_thread_quit(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_thd_t *thd = obj;
    jcfg_lport_t *lport;

    thd->quit = 1;

    if (thd->lport_cnt) {
        foreach_thd_lport (thd, lport) {
            cne_printf("    [magenta]lport [red]%d[] - '[cyan]%s[]'", lport->lpid, lport->name);
            if (pktdev_close(lport->lpid) < 0)
                CNE_ERR("pktdev_close() returned error\n");
            cne_printf("[magenta] closed[]\n");
        }
    }
    return 0;
}

static void
my_quit(struct cnet_info *ci)
{
    if (ci) {
        jcfg_thread_foreach(ci->jinfo, _thread_quit, ci);
        metrics_destroy();

        cnet_stop();
        cli_destroy();
    }
}

static void
__on_exit(int val, void *arg, int exit_type)
{
    struct cnet_info *ci = arg;

    switch (exit_type) {
    case CNE_CAUGHT_SIGNAL:
        switch (val) {
        case SIGUSR1: /* Used to break into the debugger */
            break;

        case SIGINT: /* Terminate the application */
            cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with signal [green]%d[]\n", val);
            break;

        default:
            cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with signal [red]%d[]\n", val);
            break;
        }
        break;

    case CNE_CALLED_EXIT:
        cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with status [green]%d[]\n", val);
        break;

    case CNE_USER_EXIT:
        cne_printf_pos(99, 1, "\n>>> [cyan]User called exit, with [red]%d[]\n", val);
        break;

    default:
        cne_printf_pos(99, 1, "\n>>> [cyan]Unknow Exit type %d[]\n", exit_type);
        break;
    }
    my_quit(ci);
}

static int
initialize(void)
{
    uint16_t nb_conf = 0;

    CNE_DEBUG("pktmbuf_t size %ld, udata64 offset %ld\n", sizeof(pktmbuf_t),
              offsetof(pktmbuf_t, udata64));

    for (uint16_t lportid = 0; lportid < pktdev_port_count(); lportid++)
        pkt_conf[nb_conf++].port_id = lportid;

    /* Ethdev node config, skip rx queue mapping */
    if (cnet_eth_node_config(pkt_conf, nb_conf))
        CNE_ERR_RET("cnet_eth_node_config: failed\n");

    return 0;
}

static int
cli_tree(void)
{
    /*
     * Root is created already and using system default cmds and dirs, the
     * developer is not required to use the system default cmds/dirs.
     */
    return (cli_create_with_defaults(NULL) || cnet_add_cli_cmds()) ? -1 : 0;
}

int
main(int argc, char **argv)
{
    int signals[] = {SIGINT, SIGTERM, SIGUSR1};

    memset(&cnet_info, 0, sizeof(struct cnet_info));

    setlocale(LC_ALL, "");

    cne_timer_subsystem_init();

    if (cne_init() < 0 || parse_args(argc, argv))
        CNE_ERR_GOTO(leave, "cne_init() failed\n");

    if (cne_on_exit(__on_exit, cinfo, signals, cne_countof(signals)) < 0)
        CNE_ERR_GOTO(leave, "cne_on_exit() failed\n");

    cne_printf("\n*** [yellow]cnet-graph[], [blue]PID[]: [green]%d[] [blue]lcore[]: [green]%d[]\n",
               getpid(), cne_lcore_id());

    /* Create the CNET stack structure, options should have been parsed already */
    cinfo->cnet = cnet_create();
    if (!cinfo->cnet)
        CNE_ERR_RET("Unable to create CNET instance\n");

    usleep(1000);

    if (initialize())
        CNE_ERR_GOTO(err, "Initialize() failed\n");

    if (cli_create(NULL))
        CNE_ERR_GOTO(err, "cli_create() failed\n");

    /* Create the CLI command tree */
    if (cli_setup_with_tree(cli_tree))
        CNE_ERR_GOTO(err, "Unable to create CLI\n");

    /* Wait for all threads to initialize, before starting stats printout */
    if (pthread_barrier_wait(&cinfo->barrier) > 0)
        CNE_ERR_GOTO(err, "Failed to wait for barrier\n");

    if (pthread_barrier_destroy(&cinfo->barrier))
        CNE_ERR_RET("Failed to destroy barrier\n");
    usleep(500000);

    /* Loop gathering commands via CLI until stopped */
    cli_start(NULL);

    cne_printf(">>> [cyan]CNET-Graph Application Exiting[]: [green]Bye![]\n");
    return 0;

err:
    if (pthread_barrier_destroy(&cinfo->barrier))
        CNE_ERR("Failed to destroy barrier\n");
leave:
    cne_printf("\n*** [cyan]cnet-graph Application[], [blue]PID[]: [green]%d[] failed\n", getpid());
    return -1;
}
