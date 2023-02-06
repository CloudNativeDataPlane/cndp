/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation.
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <pthread.h>             // for pthread_self, pthread_setaffinity_np
#include <sched.h>               // for CPU_COUNT, CPU_ISSET, CPU_SETSIZE, cpu...
#include <stdio.h>               // for NULL, printf, size_t, EOF
#include <stdlib.h>              // for calloc
#include <unistd.h>              // for usleep
#include <getopt.h>              // for getopt_long, option
#include <bsd/string.h>          // for strlcpy
#include <cne_log.h>             // for CNE_LOG_ERR, CNE_ERR_RET, CNE_ERR, CNE...
#include <cne_lport.h>           // for lport_cfg, LPORT_CREATE_MEMPOOL, LPORT...
#include <cne_mmap.h>            // for mmap_addr, mmap_alloc, mmap_name_by_type
#include <pmd_af_xdp.h>          // for PMD_NET_AF_XDP_NAME
#include <jcfg.h>                // for jcfg_obj_t, jcfg_umem_t, jcfg_lport_t
#include <jcfg_process.h>        // for jcfg_process
#include <stdint.h>              // for uint16_t
#include <strings.h>             // for strcasecmp

#include "cne_thread.h"        // for thread_create
#include "dlb_test.h"          // for libdlb
#include "pktdev_api.h"        // for pktdev_port_setup

static int
process_callback(jcfg_info_t *j __cne_unused, void *_obj, void *arg, int idx)
{
    jcfg_obj_t obj;
    struct fwd_info *f = arg;
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
        if (!strcmp(obj.opt->name, "no-metrics")) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                f->opts.no_metrics = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, "no-restapi")) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                f->opts.no_restapi = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, "cli")) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                f->opts.cli = obj.opt->val.boolean;
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

            pcfg.qid        = lport->qid;
            pcfg.bufsz      = umem->bufsz;
            pcfg.rx_nb_desc = umem->rxdesc;
            pcfg.tx_nb_desc = umem->txdesc;
            pcfg.umem_addr  = mmap_addr(mm);
            pcfg.umem_size  = mmap_size(mm, NULL, NULL);

            pcfg.addr = jcfg_lport_region(lport, &pcfg.bufcnt);
            if (!pcfg.addr) {
                free(pd);
                CNE_ERR_RET("lport %s region index %d >= %d or not configured correctly\n",
                            lport->name, lport->region_idx, umem->region_cnt);
            }
            pcfg.pi = umem->rinfo[lport->region_idx].pool;

            /* Setup the mempool configuration */
            strlcpy(pcfg.pmd_name, PMD_NET_AF_XDP_NAME, sizeof(pcfg.pmd_name));
            strlcpy(pcfg.ifname, lport->netdev, sizeof(pcfg.ifname));
            strlcpy(pcfg.name, lport->name, sizeof(pcfg.name));

            pd->lport = pktdev_port_setup(&pcfg);
            if (pd->lport < 0) {
                free(pd);
                CNE_ERR_RET("Unable to setup port %s, pktdev_port_setup() failed\n", lport->name);
            }
        } while ((0));
        break;

    case JCFG_LGROUP_TYPE:
        break;

    case JCFG_THREAD_TYPE:
        if (!strcasecmp("main", obj.thd->thread_type)) { /* Main thread */
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                   &obj.thd->group->lcore_bitmap);
        } else if (!strcasecmp("producer", obj.thd->thread_type)) {
            if (thread_create(obj.thd->name, (void *)producer, obj.thd) < 0)
                CNE_ERR_RET("Unable to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                            obj.thd->thread_type);
        } else if (!strcasecmp("consumer", obj.thd->thread_type)) {
            if (thread_create(obj.thd->name, (void *)consumer, obj.thd) < 0)
                CNE_ERR_RET("Unable to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                            obj.thd->thread_type);
        } else if (!strcasecmp("worker", obj.thd->thread_type)) {
            if (num_workers > obj.thd->group->lcore_cnt)
                CNE_ERR_RET("Not enough cores (group - %d) for worker threads (workers - %d)\n",
                            obj.thd->group->lcore_cnt, num_workers);

            cpu_set_t worker_bitmap = obj.thd->group->lcore_bitmap;
            /* Initialize the worker arguments */
            for (int i = 0, bit = 0; i < num_workers; i++, bit++) {
                while (CPU_ISSET(bit, &worker_bitmap) == 0)
                    bit++;
                work_args[i].lcore = bit;
                if (thread_create(obj.thd->name, (void *)worker, (void *)&work_args[i]) < 0)
                    CNE_ERR_RET("Unable to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                                obj.thd->thread_type);
            }
        } else
            CNE_ERR_RET("*** Unknown thread type '%s'\n", obj.thd->thread_type);
        break;

    case JCFG_LPORT_GROUP_TYPE:
        break;

    default:
        return -1;
    }

    return 0;
}

// clang-format off
static struct option long_options[] = {
    {"-c", required_argument, NULL, 'c'},
    {"dev-id", required_argument, 0, 'd'},
    {"num-workers", required_argument, 0, 'w'},
    {NULL, 0, 0, 0}
};
// clang-format on

static void
print_usage(char *prog_name)
{
    cne_printf(
        "  Usage: %s [-h] [-c json_file] [options]\n"
        "  Options:\n"
        "  -c <json-file>,        The JSON configuration file\n"
        "  -d, --dev-id=N         Device ID (default: 0)\n"
        "  -w, --num-workers=N    Number of 'worker' threads that forward events (default: 0)\n"
        "  -h                     Display the help information\n",
        prog_name);
}

int
parse_args(int argc, char **argv)
{
    int opt, option_index, flags = 0;
    char json_file[1024] = {0};

    /* Parse the input arguments. */
    for (;;) {
        opt = getopt_long(argc, argv, "c:d:w:h", long_options, &option_index);
        if (opt == -1)
            break;

        switch (opt) {
        case 'c':
            strlcpy(json_file, optarg, sizeof(json_file));
            flags |= JCFG_PARSE_FILE;
            break;
        case 'h':
            print_usage(argv[0]);
            return -1;
        case 'd':
            dev_id = atoi(optarg);
            break;
        case 'w':
            num_workers = atoi(optarg);
            break;
        default:
            CNE_ERR("Invalid command option\n");
            print_usage(argv[0]);
            return -1;
        }
    }
    fwd->jinfo = jcfg_parser(flags, (const char *)json_file);
    if (fwd->jinfo == NULL)
        CNE_ERR_RET("*** Did not find any configuration to use ***\n");

    fwd->flags = flags;

    if (dlb_init() == -1)
        CNE_ERR_RET("*** DLB Device configuration fail ***\n");

    if (jcfg_process(fwd->jinfo, flags, process_callback, fwd))
        CNE_ERR_RET("*** Invalid configuration ***\n");

    return 0;
}
