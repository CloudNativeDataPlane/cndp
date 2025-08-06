/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corporation.
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <pthread.h>             // for pthread_self, pthread_setaffinity_np
#include <sched.h>               // for cpu_set_t
#include <stdio.h>               // for NULL, printf, EOF
#include <stdlib.h>              // for exit, free, calloc
#include <getopt.h>              // for getopt_long, option
#include <bsd/string.h>          // for strlcpy
#include <cne_log.h>             // for CNE_LOG_ERR, CNE_ERR_RET, CNE_ERR
#include <cne_lport.h>           // for lport_cfg
#include <cne_mmap.h>            // for mmap_addr, mmap_alloc, mmap_size, mmap_t
#include <jcfg.h>                // for jcfg_obj_t, jcfg_thd_t, jcfg_umem_t
#include <jcfg_process.h>        // for jcfg_process
#include <stdint.h>              // for uint16_t, uint64_t, uint32_t
#include <strings.h>             // for strcasecmp
#include <string.h>              // for strcmp

#include "txgen.h"             // for txgen_t, txgen, txgen_launch_one_lcore
#include "cne_thread.h"        // for thread_create
#include "pktdev_api.h"        // for pktdev_port_count, pktdev_get_port_by_...
#include "parse-args.h"
#include "_pcap.h"             // for _pcap_open
#include "capture.h"           // for txgen_packet_capture_init, capture_t
#include "cne_common.h"        // for MEMPOOL_CACHE_MAX_SIZE, __cne_unused
#include "pcap.h"              // for txgen_pcap_parse
#include "pktmbuf.h"           // for pktmbuf_pool_create, pktmbuf_info_t
#include "port-cfg.h"          // for port_info_t
#include "cmds.h"

static int
process_callback(jcfg_info_t *j __cne_unused, void *_obj, void *arg, int idx)
{
    jcfg_obj_t obj;
    txgen_t *t = arg;
    uint32_t cache_sz;
    char *umem_addr;

    if (!_obj || !t)
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
                t->opts.no_metrics = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, NO_RESTAPI_TAG)) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                t->opts.no_restapi = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, ENABLE_CLI_TAG)) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                t->opts.cli = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, "pcap_lports")) {
            if (obj.opt->val.type == ARRAY_OPT_TYPE) {
                obj_value_t *file_arr;
                uint16_t cnt;

                if (jcfg_option_array_get(t->jinfo, "pcap_files", &file_arr) < 0)
                    CNE_ERR_RET("Did not find a PCAP file setting\n");

                if (file_arr->array_sz == 1 && !strcmp(obj.opt->val.arr[0]->str, "all")) {
                    cnt = pktdev_port_count();
                } else if (file_arr->array_sz != obj.opt->val.array_sz)
                    CNE_ERR_RET("mismatch in number of pcap ports and pcap files\n");
                else
                    cnt = obj.opt->val.array_sz;

                for (int i = 0; i < cnt; i++) {
                    uint16_t lpid;
                    port_info_t *pinfo;
                    char *file;

                    if (!strcmp(obj.opt->val.arr[0]->str, "all")) {
                        file = file_arr->arr[0]->str;
                        lpid = i;
                    } else {
                        file = file_arr->arr[i]->str;
                        if (pktdev_get_port_by_name(obj.opt->val.arr[i]->str, &lpid) != 0)
                            CNE_ERR_RET("COULD NOT FIND PORT %s\n", obj.opt->val.arr[i]->str);
                    }

                    pinfo = &txgen.info[lpid];
                    txgen_port_defaults(lpid);
                    pinfo->pcap = _pcap_open(file, lpid);
                    if (pinfo->pcap == NULL)
                        CNE_ERR_RET("Could NOT FIND PCAP\n");

                    if (txgen_pcap_parse(pinfo->pcap, pinfo) != 0)
                        CNE_ERR_RET("Could not parse pcap\n");
                }
            }
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
            region_info_t *ri = &obj.umem->rinfo[i];

            /* Find the starting memory address in UMEM for the pktmbuf_t buffers */
            ri->addr = umem_addr;
            umem_addr += (ri->bufcnt * obj.umem->bufsz);

            /* Initialize a pktmbuf_info_t structure for each region in the UMEM space */
            pi = pktmbuf_pool_create(ri->addr, ri->bufcnt, obj.umem->bufsz, cache_sz, NULL);
            if (!pi) {
                mmap_free(obj.umem->mm);
                CNE_ERR_RET("pktmbuf_pool_init() failed for region %d\n", i);
            }

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
                CNE_ERR_RET("Failed to allocate fwd_port structure\n");
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
                CNE_ERR_RET("Failed to initialize pmd:%s, ifname:%s\n", pcfg.pmd_name, pcfg.ifname);
            }
            for (int i = 0; i < pktdev_port_count(); i++) {
                txgen_packet_capture_init(&txgen.captures[i]);
            }
        } while ((0));
        break;

    case JCFG_LGROUP_TYPE:
        break;

    case JCFG_THREAD_TYPE:
        if (!strcasecmp("cli", obj.thd->thread_type)) { /* Main CLI thread */
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                   &obj.thd->group->lcore_bitmap);
        } else if (!strcasecmp("rxtx", obj.thd->thread_type)) {
            if (thread_create(obj.thd->name, txgen_launch_one_lcore, obj.thd) < 0)
                CNE_ERR_RET("Failed to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                            obj.thd->thread_type);
        } else if (!strcasecmp("tx_only", obj.thd->thread_type)) {
            if (thread_create(obj.thd->name, txgen_launch_one_lcore, obj.thd) < 0)
                CNE_ERR_RET("Failed to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                            obj.thd->thread_type);
        } else if (!strcasecmp("rx_only", obj.thd->thread_type)) {
            if (thread_create(obj.thd->name, txgen_launch_one_lcore, obj.thd) < 0)
                CNE_ERR_RET("Failed to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                            obj.thd->thread_type);
        } else if (!strcasecmp("stats", obj.thd->thread_type)) {
            if (thread_create(obj.thd->name, txgen_stats, obj.thd) < 0)
                CNE_ERR_RET("Failed to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                            obj.thd->thread_type);
        } else
            CNE_ERR_RET("Unknown thread type '%s'\n", obj.thd->thread_type);
        break;
    default:
        return -1;
    }

    return 0;
}

static void
print_usage(char *prog_name)
{
    cne_printf("Usage: %s [-h] [-c json_file]\n"
               "  -c <json-file> The JSON configuration file\n"
               "  -C             Wait on unix domain socket for JSON or JSON-C file\n"
               "  -D             JCFG debug decoding\n"
               "  -V             JCFG information verbose\n"
               "  -P             JCFG debug parsing\n"
               "  -h             Display the help information\n",
               prog_name);
}

int
parse_args(int argc, char **argv)
{
    struct option lgopts[] = {{NULL, 0, 0, 0}};
    int opt, option_index, flags = 0;
    char json_file[1024] = {0};

    /* Parse the input arguments. */
    for (;;) {
        opt = getopt_long(argc, argv, "hc:CDPV", lgopts, &option_index);
        if (opt == EOF)
            break;

        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            exit(0);

        case 'c':
            strlcpy(json_file, optarg, sizeof(json_file));
            flags |= JCFG_PARSE_FILE;
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

        default:
            CNE_ERR("Invalid command option\n");
            print_usage(argv[0]);
            exit(0);
        }
    }

    txgen.jinfo = jcfg_parser(flags, (const char *)json_file);
    if (txgen.jinfo == NULL)
        CNE_ERR_RET("*** Did not find any configuration to use ***\n");

    if (jcfg_process(txgen.jinfo, flags, process_callback, &txgen))
        CNE_ERR_RET("*** Invalid configuration ***\n");

    return 0;
}
