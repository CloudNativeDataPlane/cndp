/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <pthread.h>             // for pthread_barrier_init, pthread_self
#include <sched.h>               // for cpu_set_t
#include <stdio.h>               // for NULL, EOF
#include <stdlib.h>              // for free, calloc
#include <getopt.h>              // for getopt_long, option
#include <bsd/string.h>          // for strlcpy
#include <cne_log.h>             // for CNE_LOG_ERR, CNE_ERR_RET, CNE_ERR, CNE...
#include <cne_lport.h>           // for lport_cfg
#include <cne_mmap.h>            // for mmap_addr, mmap_alloc, mmap_size, mmap_t
#include <pmd_af_xdp.h>          // for PMD_NET_AF_XDP_NAME
#include <jcfg.h>                // for jcfg_obj_t, jcfg_umem_t, jcfg_thd_t
#include <jcfg_process.h>        // for jcfg_process
#include <stdint.h>              // for uint64_t, uint32_t
#include <strings.h>             // for strcasecmp
#include <string.h>              // for strcmp
#include <cli.h>

#include <cnet.h>
#include <cnet_netlink.h>
#include <cnet_netif.h>
#include <cne_strings.h>

#include "cnet-graph.h"        // for fwd_info, fwd, app_options, enable_met...
#include "cne_thread.h"        // for thread_create
#include "pktdev_api.h"        // for pktdev_port_setup
#include "cne_common.h"        // for MEMPOOL_CACHE_MAX_SIZE, __cne_unused
#include "pktmbuf.h"           // for pktmbuf_pool_create, pktmbuf_info_t

#include "cnet_route.h"

static int
process_callback(jcfg_info_t *j, void *_obj, void *arg, int idx)
{
    jcfg_obj_t obj;
    struct cnet_info *ci = arg;
    uint32_t cache_sz;
    char *umem_addr;

    if (!_obj)
        return -1;

    obj.hdr = _obj;

    switch (obj.hdr->cbtype) {
    case JCFG_APPLICATION_TYPE:
        break;

    case JCFG_DEFAULT_TYPE:
        break;

    case JCFG_OPTION_TYPE:
        if (!strcmp(obj.opt->name, NO_METRICS_TAG)) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                ci->opts.no_metrics = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, NO_RESTAPI_TAG)) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                ci->opts.no_restapi = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, ENABLE_CLI_TAG)) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                ci->opts.cli = obj.opt->val.boolean;
        }
        break;

    case JCFG_UMEM_TYPE:
        /* The UMEM object describes the total size of the UMEM space */
        obj.umem->mm = mmap_alloc(obj.umem->bufcnt, obj.umem->bufsz, obj.umem->mtype);
        if (obj.umem->mm == NULL)
            CNE_ERR_RET("**** Failed to allocate mmap memory %ld\n",
                        (uint64_t)obj.umem->bufcnt * (uint64_t)obj.umem->bufsz);

        if (jcfg_default_get_u32(j, "cache", &cache_sz))
            cache_sz = MEMPOOL_CACHE_MAX_SIZE;

        umem_addr = mmap_addr(obj.umem->mm);

        /* Create the pktmbuf pool for each region defined */
        for (int i = 0; i < obj.umem->region_cnt; i++) {
            pktmbuf_info_t *pi;
            region_info_t *ri               = &obj.umem->rinfo[i];
            char name[PKTMBUF_INFO_NAME_SZ] = {0};

            /* Find the starting memory address in UMEM for the pktmbuf_t buffers */
            ri->addr = umem_addr;
            umem_addr += (ri->bufcnt * obj.umem->bufsz);

            /* Initialize a pktmbuf_info_t structure for each region in the UMEM space */
            pi = pktmbuf_pool_create(ri->addr, ri->bufcnt, obj.umem->bufsz, cache_sz, NULL);
            if (!pi) {
                mmap_free(obj.umem->mm);
                CNE_ERR_RET("pktmbuf_pool_init() failed for region %d\n", i);
            }
            snprintf(name, sizeof(name), "%s-%d", obj.umem->name, i);
            pktmbuf_info_name_set(pi, name);
            ri->pool = pi;
        }
        break;

    case JCFG_LPORT_TYPE:
        do {
            jcfg_lport_t *lport = obj.lport;
            struct fwd_port *pd;
            mmap_t *mm;
            jcfg_umem_t *umem;
            struct lport_cfg pcfg = {0};

            umem = lport->umem;
            mm   = umem->mm;

            pd = calloc(1, sizeof(struct fwd_port));
            if (!pd)
                CNE_ERR_RET("Unable to allocate fwd_port structure\n");
            lport->priv_ = pd;

            pcfg.qid          = lport->qid;
            pcfg.bufsz        = umem->bufsz;
            pcfg.rx_nb_desc   = umem->rxdesc;
            pcfg.tx_nb_desc   = umem->txdesc;
            pcfg.umem_addr    = mmap_addr(mm);
            pcfg.umem_size    = mmap_size(mm, NULL, NULL);
            pcfg.pmd_opts     = lport->pmd_opts;
            pcfg.busy_timeout = lport->busy_timeout;
            pcfg.busy_budget  = lport->busy_budget;
            pcfg.flags        = lport->flags;
            pcfg.flags |= (umem->shared_umem == 1) ? LPORT_SHARED_UMEM : 0;

            pcfg.addr = jcfg_lport_region(lport, &pcfg.bufcnt);
            if (!pcfg.addr) {
                free(pd);
                CNE_ERR_RET("lport %s region index %d >= %d or not configured correctly\n",
                            lport->name, lport->region_idx, umem->region_cnt);
            }
            pcfg.pi = umem->rinfo[lport->region_idx].pool;

            /* Setup the mempool configuration */
            strlcpy(pcfg.pmd_name, lport->pmd_name, sizeof(pcfg.pmd_name));
            strlcpy(pcfg.ifname, lport->netdev, sizeof(pcfg.ifname));
            strlcpy(pcfg.name, lport->name, sizeof(pcfg.name));

            pd->lport = pktdev_port_setup(&pcfg);
            if (pd->lport < 0) {
                free(pd);
                CNE_ERR_RET("Unable to setup port %s, pktdev_port_setup() failed\n", lport->name);
            }
            if (cnet_netif_register(lport->lpid, lport->name, lport->netdev) < 0) {
                free(pd);
                CNE_ERR_RET("Failed to register netif for %s\n", lport->name);
            }
        } while ((0));
        break;

    case JCFG_LGROUP_TYPE:
        break;

    case JCFG_THREAD_TYPE:
        if (!strcasecmp("main", obj.thd->thread_type)) { /* Main thread */
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                   &obj.thd->group->lcore_bitmap);
        } else if (!strcasecmp("timer", obj.thd->thread_type)) {
            if (thread_create(obj.thd->name, thread_timer_func, obj.thd) < 0)
                CNE_ERR_RET("Unable to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                            obj.thd->thread_type);
        } else if (!strcasecmp("graph", obj.thd->thread_type)) {
            if (thread_create(obj.thd->name, thread_func, obj.thd) < 0)
                CNE_ERR_RET("Unable to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                            obj.thd->thread_type);
        } else
            CNE_WARN("[yellow]*** [cyan]Unknown thread type[] '[orange]%s[]'\n",
                     obj.thd->thread_type);
        break;

    case JCFG_LPORT_GROUP_TYPE:
        break;

    default:
        return -1;
    }

    return 0;
}

/* Long options start at 256 to distinguish from short options */
#define OPT_NO_COLOR     "no-color"
#define OPT_NO_COLOR_NUM 256

static void
print_usage(char *prog_name)
{
    cne_printf("Usage: %s [-h] [-c json_file] <mode>\n"
               "  <mode>         Mode types drop, tx-only, or [lb | loopback]\n"
               "  -c <json-file> The JSON configuration file\n"
               "  -s <cmd-file>  File containing cli commands for setup\n"
               "  -C             Wait on unix domain socket for JSON or JSON-C file\n"
               "  -d             More debug stats are displayed\n"
               "  -b <burst>     Burst size. If not present default burst size %d max %d.\n"
               "  -D             JCFG debug decoding\n"
               "  -V             JCFG information verbose\n"
               "  -P             JCFG debug parsing\n"
               "  -U             Disable UDP checksum (default enabled)\n"
               "  -L [level]     Enable a logging level\n"
               "  -h             Display the help information\n"
               "  --%-12s Disable color output\n",
               prog_name, BURST_SIZE, MAX_BURST_SIZE, OPT_NO_COLOR);
}

int
parse_args(int argc, char **argv)
{
    // clang-format off
    struct option lgopts[] = {
        {OPT_NO_COLOR, no_argument, NULL, OPT_NO_COLOR_NUM},
        {NULL, 0, 0, 0}
    };
    // clang-format on
    int opt, option_index, flags = 0;
    char json_file[1024] = {0};
    char log_level[16]   = {0};

    cinfo->flags = FWD_ENABLE_UDP_CKSUM;

    cinfo->burst = BURST_SIZE;

    /* Parse the input arguments. */
    for (;;) {
        opt = getopt_long(argc, argv, "hb:c:s:dCDPVUL:", lgopts, &option_index);
        if (opt == EOF)
            break;

        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return -1;

        case 'b':
            cinfo->burst = atoi(optarg);
            if (cinfo->burst <= 0 || cinfo->burst > MAX_BURST_SIZE)
                cinfo->burst = BURST_SIZE;
            break;

        case 'c':
            strlcpy(json_file, optarg, sizeof(json_file));
            flags |= JCFG_PARSE_FILE;
            break;

        case 's':
            cli_add_cmdfile(optarg);
            break;

        case 'U':
            cinfo->flags &= ~FWD_ENABLE_UDP_CKSUM;
            break;

        case 'd':
            cinfo->flags |= FWD_DEBUG_STATS;
            break;

        case 'C':
            flags |= JCFG_PARSE_SOCKET;
            break;

        case 'D':
            flags |= JCFG_DEBUG_DECODING;
            break;

        case 'P':
            flags |= JCFG_DEBUG_PARSING;
            break;

        case 'V':
            flags |= JCFG_INFO_VERBOSE;
            break;

        case 'L':
            strlcpy(log_level, optarg, sizeof(log_level));
            if (cne_log_set_level_str(log_level)) {
                CNE_ERR("Invalid command option\n");
                print_usage(argv[0]);
                return -1;
            }
            break;

        case OPT_NO_COLOR_NUM:
            tty_disable_color();
            break;

        default:
            CNE_ERR("Invalid command option\n");
            print_usage(argv[0]);
            return -1;
        }
    }

    if (optind < argc)
        cinfo->test = get_app_mode(argv[optind]);

    cinfo->jinfo = jcfg_parser(flags, (const char *)json_file);
    if (cinfo->jinfo == NULL)
        CNE_ERR_RET("*** Did not find any configuration to use ***\n");

    /* setup barrier to wait for all threads to finish initialization */
    CNE_DEBUG("Setup barrier for %d threads\n", jcfg_num_threads(cinfo->jinfo));

    if (pthread_barrier_init(&cinfo->barrier, NULL, jcfg_num_threads(cinfo->jinfo)))
        CNE_ERR_RET("Failed to initialize barrier\n");
    cinfo->barrier_inited = true;

    if (jcfg_process(cinfo->jinfo, flags, process_callback, cinfo))
        CNE_ERR_RET("*** Invalid configuration ***\n");

    if (!cinfo->opts.no_metrics && enable_metrics())
        CNE_ERR_RET("Failed to start metrics support\n");

    if (cinfo->test == UNKNOWN_TEST) {
        cinfo->test = DROP_TEST;
        CNE_INFO("*** Mode type was not set in json file or command line, use drop mode ***\n");
    }

    return 0;
}
