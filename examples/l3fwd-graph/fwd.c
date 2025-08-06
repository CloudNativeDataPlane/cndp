/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 * Copyright (c) 2019-2025 Intel Corporation.
 */

#include <arpa/inet.h>                    // for inet_ntop
#include <signal.h>                       // for SIGINT, SIGUSR1, SIGTERM
#include <stdint.h>                       // for uint64_t, uint8_t, uint16_t, uint...
#include <stdio.h>                        // for snprintf, fflush, stdout, NULL
#include <stdlib.h>                       // for realloc
#include <string.h>                       // for memset, memcpy, strdup
#include <sys/socket.h>                   // for AF_INET
#include <unistd.h>                       // for sleep, getpid
#include <cne_branch_prediction.h>        // for likely
#include <cne_common.h>                   // for __cne_unused, CNE_MAX_ETHPORTS
#include <cne_graph_worker.h>             // for cne_graph_walk, cne_graph
#include <cne_log.h>                      // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_INFO
#include <node_eth_api.h>                 // for cne_node_eth_config, cne_node_pkt...
#include <node_ip4_api.h>                 // for cne_node_ip4_rewrite_add, cne_nod...
#include <cne_system.h>                   // for cne_lcore_id
#include <cne_vect.h>                     // for xmm_t
#include <net/cne_ip.h>                   // for CNE_IPV4
#include <net/cne_ether.h>                // for ether_addr_copy, ETHER_LOCAL_ADMI...
#include <jcfg.h>                         // for jcfg_thd_t, jcfg_lport_t, jcfg_lg...
#include <net/ethernet.h>                 // for ether_addr
#include <netinet/in.h>                   // for INET6_ADDRSTRLEN, in_addr, htonl
#include <sched.h>                        // for cpu_set_t
#include <stddef.h>                       // for offsetof

#include "fwd.h"
#include "cne.h"               // for cne_id, cne_init, cne_on_exit
#include "cne_graph.h"         // for cne_graph_cluster_stats_param
#include "pktdev_api.h"        // for pktdev_close, pktdev_is_valid_port

static struct fwd_info fwd_info;
struct fwd_info *fwd = &fwd_info;

#define foreach_thd_lport(_t, _lp) \
    for (int _i = 0; _i < _t->lport_cnt && (_lp = _t->lports[_i]); _i++, _lp = _t->lports[_i])

/* Ethernet addresses of ports */
static uint64_t dest_eth_addr[CNE_MAX_ETHPORTS];
xmm_t val_eth[CNE_MAX_ETHPORTS];

struct ipv4_l3fwd_lpm_route {
    uint32_t ip;
    uint8_t depth;
    uint8_t if_out;
};

#define IPV4_L3FWD_LPM_NUM_ROUTES \
    (sizeof(ipv4_l3fwd_lpm_route_array) / sizeof(ipv4_l3fwd_lpm_route_array[0]))

static struct cne_node_pktdev_config pktdev_conf[CNE_MAX_ETHPORTS];

/* 198.18.0.0/16 are set aside for RFC2544 benchmarking. */
// clang-format off
static struct ipv4_l3fwd_lpm_route ipv4_l3fwd_lpm_route_array[] = {
    {CNE_IPV4(198, 18, 0, 0), 24, 0},
	{CNE_IPV4(198, 18, 1, 0), 24, 1},
    {CNE_IPV4(198, 18, 2, 0), 24, 2},
	{CNE_IPV4(198, 18, 3, 0), 24, 3},
    {CNE_IPV4(198, 18, 4, 0), 24, 4},
	{CNE_IPV4(198, 18, 5, 0), 24, 5},
    {CNE_IPV4(198, 18, 6, 0), 24, 6},
	{CNE_IPV4(198, 18, 7, 0), 24, 7},
};
// clang-format on

void
print_stats(void *arg __cne_unused)
{
    struct cne_graph_cluster_stats_param s_param = {0};
    struct cne_graph_cluster_stats *stats        = NULL;
    const char *pattern                          = "worker_*";

    if (pthread_barrier_wait(&fwd->barrier) > 0)
        CNE_ERR("Failed to wait on barrier\n");

    /* wait for the other nodes to initialize */
    while (!fwd->timer_quit) {
        sleep(1); /* wait for valid stats pointer */

        /* Prepare stats object */
        s_param.graph_patterns    = &pattern;
        s_param.nb_graph_patterns = 1;

        stats = cne_graph_cluster_stats_create(&s_param);
        if (stats)
            break;
    }

    if (!stats)
        return;

    /* Scroll the screen up to allow for stats table and backup to the original row */
    vt_make_space(16 + (fwd->flags & FWD_DEBUG_STATS) ? 12 : 0);

    while (!fwd->timer_quit) {
        vt_save();
        cne_graph_cluster_stats_get(stats, 0);
        vt_restore();
        sleep(1);
    }

    cne_graph_cluster_stats_destroy(stats);
    fflush(stdout);
}

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
    /* Rewrite data of src and dst ether addr */
    const char *patterns[] = {"ip4*", "pktdev_tx-*", "pkt_drop", NULL};
    jcfg_lport_t *lport;
    char name[128];

    for (int i = 0; patterns[i]; i++)
        if (add_graph_pattern(gi, patterns[i]))
            goto err;

    foreach_thd_lport (thd, lport) {
        snprintf(name, sizeof(name), "pktdev_rx-%u", lport->lpid);
        if (add_graph_pattern(gi, name))
            goto err;
    }

    snprintf(name, sizeof(name), "worker_%d", cne_id());
    CNE_INFO("Create Graph '%s'\n", name);

    gi->id = cne_graph_create(name, gi->patterns);
    if (gi->id == CNE_GRAPH_ID_INVALID)
        CNE_ERR_GOTO(err, "cne_graph_create(): graph_id '%s' for uid %u\n", name, cne_id());

    gi->graph = cne_graph_lookup(name);
    if (!gi->graph)
        CNE_ERR_GOTO(err, "cne_graph_lookup(): graph '%s' not found\n", name);

    return 0;
err:
    cne_graph_destroy(gi->id);
    return -1;
}

static int
initialize_routes(void)
{
    /* Rewrite data of src and dst ether addr */
    uint8_t rewrite_data[2 * sizeof(struct ether_addr)];
    uint8_t rewrite_len;

    memset(&rewrite_data, 0, sizeof(rewrite_data));
    rewrite_len = sizeof(rewrite_data);

    /* Add route to ip4 graph infra */
    for (uint16_t i = 0; i < IPV4_L3FWD_LPM_NUM_ROUTES; i++) {
        char route_str[INET6_ADDRSTRLEN * 4];
        char abuf[INET6_ADDRSTRLEN];
        struct in_addr in;
        uint32_t dst_port;

        dst_port = ipv4_l3fwd_lpm_route_array[i].if_out;

        if (!pktdev_is_valid_port(dst_port))
            break;

        in.s_addr = htonl(ipv4_l3fwd_lpm_route_array[i].ip);
        snprintf(route_str, sizeof(route_str), "%s / %d (%d)",
                 inet_ntop(AF_INET, &in, abuf, sizeof(abuf)), ipv4_l3fwd_lpm_route_array[i].depth,
                 ipv4_l3fwd_lpm_route_array[i].if_out);

        /* Use route index 'i' as next hop id */
        if (cne_node_ip4_route_add(ipv4_l3fwd_lpm_route_array[i].ip,
                                   ipv4_l3fwd_lpm_route_array[i].depth, i,
                                   CNE_NODE_IP4_LOOKUP_NEXT_REWRITE) < 0)
            CNE_ERR_RET("Failed to add ip4 route %s to graph\n", route_str);

        memcpy(rewrite_data, val_eth + dst_port, rewrite_len);

        /* Add next hop rewrite data for id 'i' */
        if (cne_node_ip4_rewrite_add(i, rewrite_data, rewrite_len, dst_port) < 0)
            CNE_ERR_RET("Failed to add next hop %u for route %s\n", i, route_str);

        CNE_INFO("Added route %s, next_hop %u\n", route_str, i);
    }
    return 0;
}

/* Main processing loop */
void
thread_func(void *arg)
{
    jcfg_thd_t *thd = arg;
    graph_info_t *gi;
    int tid;

    if (thd->group->lcore_cnt > 0)
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &thd->group->lcore_bitmap);

    CNE_INFO("Assigned to lcore %d\n", cne_lcore_id());

    /* Wait for main thread to initialize */
    if (pthread_barrier_wait(&fwd->barrier) > 0)
        CNE_ERR_GOTO(err, "Failed to wait for barrier\n");

    tid = cne_id();
    if (tid < 0)
        CNE_ERR_GOTO(err, "Failed to get cne id\n");
    if (tid >= cne_countof(fwd->graph_info))
        CNE_ERR_GOTO(err, "Number of threads cannot be >= %d\n", cne_countof(fwd->graph_info));
    gi = &fwd->graph_info[tid];

    if (initialize_graph(thd, gi))
        CNE_ERR_GOTO(err, "Initialize_graph() failed\n");

    if (initialize_routes())
        CNE_ERR_GOTO(err, "Initialize_routes() failed\n");

    CNE_INFO("Entering main loop on tid %d, graph %s\n", cne_id(), gi->graph->name);

    while (likely(!thd->quit))
        cne_graph_walk(gi->graph);

    return;
err:
    (void)pthread_barrier_wait(&fwd->barrier);
}

static int
_thread_quit(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_thd_t *thd = obj;
    jcfg_lport_t *lport;

    thd->quit = 1;

    if (thd->lport_cnt == 0)
        CNE_DEBUG("No lports attached to thread '%s'\n", thd->name);
    else {
        foreach_thd_lport (thd, lport) {
            cne_printf(">>>    [blue]lport [red]%d[] - '[cyan]%s[]'\n", lport->lpid, lport->name);
            if (pktdev_close(lport->lpid) < 0)
                CNE_ERR("pktdev_close() returned error\n");
        }
    }
    return 0;
}

static void
my_quit(struct fwd_info *f)
{
    if (f && !f->timer_quit) {
        f->timer_quit = 1;

        cne_printf(">>> [blue]Closing lport(s)[]\n");
        jcfg_thread_foreach(f->jinfo, _thread_quit, f);
        cne_printf(">>> [blue]Done[]\n");

        metrics_destroy();
        if (pthread_barrier_destroy(&f->barrier))
            CNE_ERR("Failed to destroy pthread barrier\n");
    }
}

static void
__on_exit(int val, void *arg, int exit_type)
{
    struct fwd_info *f = arg;

    switch (exit_type) {
    case CNE_CAUGHT_SIGNAL:
        switch (val) {
        case SIGUSR1: /* Used to break into the debugger */
            break;

        case SIGINT: /* Terminate the application */
            cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with signal [green]%d[]\n", val);
            my_quit(f);
            break;

        default:
            my_quit(f);
            break;
        }
        break;

    case CNE_CALLED_EXIT:
        cne_printf_pos(99, 1, "\n>>> [cyan]Terminating with status [green]%d[]\n", val);
        my_quit(f);
        break;

    case CNE_USER_EXIT:
        cne_printf_pos(99, 1, "\n>>> [cyan]User called exit, with [red]%d[]\n", val);
        my_quit(f);
        break;

    default:
        cne_printf_pos(99, 1, "\n>>> [cyan]Unknown Exit type %d[]\n", exit_type);
        break;
    }
    fflush(stdout);
}

static int
initialize(void)
{
    uint16_t nb_conf = 0;

    CNE_INFO("pktmbuf_t size %ld, udata64 offset %ld\n", sizeof(pktmbuf_t),
             offsetof(pktmbuf_t, udata64));

    /* Pre-init dst MACs for all ports to 02:00:00:00:00:xx */
    for (uint16_t lportid = 0; lportid < pktdev_port_count(); lportid++) {
        struct ether_addr addr;

        dest_eth_addr[lportid]           = ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)lportid << 40);
        *(uint64_t *)(val_eth + lportid) = dest_eth_addr[lportid];

        pktdev_conf[nb_conf++].port_id = lportid;

        if (pktdev_macaddr_get(lportid, &addr))
            CNE_ERR_RET("Failed to get MAC address from lport %d\n", lportid);

        ether_addr_copy(&addr, (struct ether_addr *)(val_eth + lportid) + 1);
    }

    /* Pktdev node config, skip rx queue mapping */
    if (cne_node_eth_config(pktdev_conf, nb_conf))
        CNE_ERR_RET("cne_node_eth_config: failed\n");

    return 0;
}

int
main(int argc, char **argv)
{
    int signals[] = {SIGINT, SIGTERM, SIGUSR1};

    memset(&fwd_info, 0, sizeof(struct fwd_info));

    if (cne_init() < 0)
        CNE_ERR_GOTO(err, "cne_init() failed\n");

    if (cne_on_exit(__on_exit, fwd, signals, cne_countof(signals)) < 0)
        CNE_ERR_GOTO(err, "cne_on_exit() failed\n");

    if (parse_args(argc, argv))
        CNE_ERR_GOTO(err, "parse_args() failed\n");

    cne_printf("\n*** [yellow]l3fwd-graph[], [blue]PID[]: [green]%d[] [blue]lcore[]: [green]%d[]\n",
               getpid(), cne_lcore_id());

    if (initialize())
        CNE_ERR_GOTO(err, "Initialize() failed\n");

    /* Wait for all threads to initialize, before starting stats printout */
    if (pthread_barrier_wait(&fwd->barrier) > 0)
        CNE_ERR_GOTO(err, "Failed to wait for barrier\n");

    while (!fwd->timer_quit)
        sleep(1);

    if (pthread_barrier_destroy(&fwd->barrier))
        CNE_ERR_GOTO(err, "Failed to destroy barrier\n");

    return 0;

err:
    if (fwd->barrier_inited && pthread_barrier_destroy(&fwd->barrier))
        CNE_ERR("Failed to destroy barrier\n");

    cne_printf("\n*** [cyan]l3fwd-graph Application[], [blue]PID[]: [green]%d[] failed\n",
               getpid());
    return -1;
}
