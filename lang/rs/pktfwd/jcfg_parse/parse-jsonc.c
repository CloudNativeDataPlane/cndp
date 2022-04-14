/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <pthread.h>             // for pthread_self, pthread_setaffinity_np
#include <sched.h>               // for cpu_set_t
#include <stdio.h>               // for NULL, printf, EOF
#include <stdlib.h>              // for free, calloc
#include <getopt.h>              // for getopt_long, option
#include <bsd/string.h>          // for strlcpy
#include <stdint.h>              // for uint64_t, uint32_t
#include <strings.h>             // for strcasecmp
#include <string.h>              // for strcmp
#include <cne_log.h>             // for CNE_LOG_ERR, CNE_ERR_RET, CNE_ERR
#include <cne_lport.h>           // for lport_cfg
#include <cne_mmap.h>            // for mmap_addr, mmap_alloc, mmap_size, mmap_t
#include <pmd_af_xdp.h>          // for PMD_NET_AF_XDP_NAME
#include <jcfg.h>                // for jcfg_obj_t, jcfg_umem_t, jcfg_opt_t
#include <jcfg_process.h>        // for jcfg_process
#include <cne_thread.h>          // for thread_create
#include <pktdev_api.h>          // for pktdev_port_setup
#include <cne_common.h>          // for MEMPOOL_CACHE_MAX_SIZE, __cne_unused
#include <pktmbuf.h>             // for pktmbuf_pool_create, pktmbuf_info_t
#include <txbuff.h>              // for txbuff_t, txbuff_add, txbuff_free, txbuff_...
#include "fwd.h"                 // for fwd_info, fwd, app_options, get_app_mode

#define foreach_thd_lport(_t, _lp) \
    for (int _i = 0; _i < _t->lport_cnt && (_lp = _t->lports[_i]); _i++, _lp = _t->lports[_i])

struct thread_func_arg_t {
    struct fwd_info *fwd;
    jcfg_thd_t *thd;
};

static void
destroy_per_thread_txbuff(jcfg_thd_t *thd, struct fwd_info *fwd)
{
    if (thd->priv_) {
        txbuff_t **txbuffs = (txbuff_t **)thd->priv_;
        int i;

        for (i = 0; i < jcfg_num_lports(fwd->jinfo); i++) {
            if (txbuffs[i])
                txbuff_free(txbuffs[i]);
            txbuffs[i] = NULL;
        }

        free(thd->priv_);
        thd->priv_ = NULL;
    }
}

static int
_create_txbuff(jcfg_info_t *jinfo __cne_unused, void *obj, void *arg, int idx)
{
    jcfg_lport_t *lport = obj;
    txbuff_t **txbuffs  = arg;
    struct fwd_port *pd;

    pd           = lport->priv_;
    txbuffs[idx] = txbuff_pktdev_create(MAX_BURST, NULL, NULL, pd->lport);
    if (!txbuffs[idx])
        CNE_ERR_RET("Failed to create txbuff for lport %d\n", idx);

    return 0;
}

static int
create_per_thread_txbuff(jcfg_thd_t *thd, struct fwd_info *fwd)
{
    jcfg_lport_t *lport;

    if (thd->priv_) {
        CNE_ERR("Expected thread's private data to be unused but it is %p\n", thd->priv_);
        return -1;
    }

    thd->priv_ = calloc(jcfg_num_lports(fwd->jinfo), sizeof(txbuff_t *));
    if (!thd->priv_) {
        CNE_ERR("Failed to allocate txbuff(s) for %d lport(s)\n", jcfg_num_lports(fwd->jinfo));
        return -1;
    }

    /* Allocate a Tx buffer for all lports, not just the receiving ones */
    if (jcfg_lport_foreach(fwd->jinfo, _create_txbuff, thd->priv_)) {
        destroy_per_thread_txbuff(thd, fwd);
        return -1;
    }

    /* Set reference for this thread's receiving lports, not all lports */
    foreach_thd_lport (thd, lport)
        ((struct fwd_port *)lport->priv_)->thd = thd;

    return 0;
}

static void
thread_func(void *arg)
{
    struct thread_func_arg_t *func_arg = arg;
    struct fwd_info *fwd               = func_arg->fwd;
    jcfg_thd_t *thd                    = func_arg->thd;
    jcfg_lport_t *lport;

    if (thd->group->lcore_cnt > 0)
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &thd->group->lcore_bitmap);
    thd->tid = gettid();

    /* Wait for main thread to initialize */
    if (pthread_barrier_wait(&fwd->barrier) > 0)
        CNE_ERR_GOTO(leave, "Failed to wait on barrier\n");

    if (fwd->test == FWD_TEST)
        if (create_per_thread_txbuff(thd, fwd))
            cne_exit("Failed to create txbuff(s) for \"%s\" thread\n", thd->name);

    cne_printf("  [blue]Thread ID [red]%d [blue]on lcore [green]%d[]\n", thd->tid, cne_lcore_id());
    for (;;) {
        foreach_thd_lport (thd, lport) {
            if (thd->quit) /* Make sure we check quit often to break out ASAP */
                goto leave;

            if (fwd->test_arr[fwd->test].cb_func(lport))
                goto leave;
        }
    }

leave:
    if (fwd->test == FWD_TEST)
        destroy_per_thread_txbuff(thd, fwd);
    // Free thread_func_arg_t.
    free(func_arg);
}

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
        if (!strcmp(obj.opt->name, NO_METRICS_TAG)) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                f->opts.no_metrics = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, NO_RESTAPI_TAG)) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                f->opts.no_restapi = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, ENABLE_CLI_TAG)) {
            if (obj.opt->val.type == BOOLEAN_OPT_TYPE)
                f->opts.cli = obj.opt->val.boolean;
        } else if (!strcmp(obj.opt->name, MODE_TAG)) {
            if (obj.opt->val.type == STRING_OPT_TYPE) {
                f->opts.mode = obj.opt->val.str;
                f->test      = get_app_mode(f->opts.mode);
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
            region_info_t *ri               = &obj.umem->rinfo[i];
            char name[PKTMBUF_INFO_NAME_SZ] = {0};

            /* Find the starting memory address in UMEM for the pktmbuf_t buffers */
            ri->addr = umem_addr;
            umem_addr += (ri->bufcnt * obj.umem->bufsz);

            /* Initialize a pktmbuf_info_t structure for each region in the UMEM space */
            pi = pktmbuf_pool_create(ri->addr, ri->bufcnt, obj.umem->bufsz, cache_sz, NULL);
            if (!pi)
                CNE_ERR_RET("pktmbuf_pool_init() failed for region %d\n", i);
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
            pcfg.pmd_opts     = lport->pmd_opts;
            pcfg.umem_addr    = mmap_addr(mm);
            pcfg.umem_size    = mmap_size(mm, NULL, NULL);
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
        } while ((0));
        break;

    case JCFG_LGROUP_TYPE:
        break;

    case JCFG_THREAD_TYPE:
        if (!strcasecmp("main", obj.thd->thread_type)) { /* Main thread */
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
                                   &obj.thd->group->lcore_bitmap);
        } else if (!strcasecmp("fwd", obj.thd->thread_type)) {
            if (f->test != UNKNOWN_TEST) {
                struct thread_func_arg_t *func_arg;
                // Allocate memory for func_arg. This will be freed in thread_func.
                func_arg = calloc(1, sizeof(*func_arg));
                if (!func_arg)
                    CNE_ERR_RET("Allocation of struct thread_func_arg_t failed\n");
                func_arg->fwd = f;
                func_arg->thd = obj.thd;
                if (thread_create(obj.thd->name, thread_func, func_arg) < 0) {
                    free(func_arg);
                    CNE_ERR_RET("Unable to create thread %d (%s) or type %s\n", idx, obj.thd->name,
                                obj.thd->thread_type);
                }
            } else
                CNE_ERR_RET("NO MODE was configured\n");
        } else
            CNE_ERR_RET("*** Unknown thread type '%s'\n", obj.thd->thread_type);
        break;
    default:
        return -1;
    }
    return 0;
}

static void
print_usage(char *prog_name)
{
    printf("Usage: %s [-h] [-c json_file] <mode>\n"
           "  <mode>         Mode types drop, tx-only, [lb | loopback], or fwd\n"
           "  -c <json-file> The JSON configuration file\n"
           "  -C             Wait on unix domain socket for JSON or JSON-C file\n"
           "  -d             More debug stats are displayed\n"
           "  -D             JCFG debug decoding\n"
           "  -V             JCFG information verbose\n"
           "  -P             JCFG debug parsing\n"
           "  -h             Display the help information\n",
           prog_name);
}

int
parse_args(int argc, char *const argv[], struct fwd_info *fwd)
{
    struct option lgopts[] = {{NULL, 0, 0, 0}};
    int opt, option_index, flags = 0;
    char json_file[1024] = {0};
    /* Parse the input arguments. */
    for (;;) {
        opt = getopt_long(argc, argv, "hc:dCDPV", lgopts, &option_index);
        if (opt == EOF)
            break;

        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return -1;

        case 'c':
            strlcpy(json_file, optarg, sizeof(json_file));
            flags |= JCFG_PARSE_FILE;
            break;

        case 'd':
            fwd->flags |= FWD_DEBUG_STATS;
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
            return -1;
        }
    }

    fwd->jinfo = jcfg_parser(flags, (const char *)json_file);
    if (fwd->jinfo == NULL)
        CNE_ERR_RET("*** Did not find any configuration to use ***\n");

    /* create a thread barrier to wait on all threads init */
    if (pthread_barrier_init(&fwd->barrier, NULL, jcfg_num_threads(fwd->jinfo)))
        CNE_ERR_RET("*** Failed to initialize pthread barrier ***\n");

    if (jcfg_process(fwd->jinfo, flags, process_callback, fwd))
        CNE_ERR_RET("*** Invalid configuration ***\n");

    if (!fwd->opts.no_metrics && enable_metrics(fwd))
        CNE_ERR_RET("Failed to start metrics support\n");

    if (optind < argc)
        fwd->test = get_app_mode(argv[optind]);

    if (fwd->test == UNKNOWN_TEST)
        CNE_ERR_RET("mode type was not set in json file or command line\n");

    return 0;
}

void
free_lport(jcfg_lport_t *lport)
{
    if (lport->umem) {
        mmap_free(lport->umem->mm);
        lport->umem->mm = NULL; /* Make sure we do not free this again */
        if (lport->umem->rinfo) {
            pktmbuf_destroy(lport->umem->rinfo->pool);
            lport->umem->rinfo->pool = NULL;
        }
    }
}
