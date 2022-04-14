/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation
 */

#ifndef _DLB_TEST_H_
#define _DLB_TEST_H_

/* @file
 *
 * DLB example
 */

#include <stdint.h>        // for uint64_t, uint32_t, uint8_t
#include <sys/types.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <strings.h>        // for strcasecmp
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <jcfg.h>        // for jcfg_t
#include <jcfg_process.h>
#include <cne_log.h>        // for CNE_ERR_RET, CNE_LOG_ERR
#include <dlb.h>            // for DLB

#include "pktmbuf.h"        // for pktmbuf_t

#define CQ_DEPTH 8

#define NUM_EVENTS_PER_LOOP 4
#define RETRY_LIMIT         10000000
#define MAX_THREADS         16
#define MAX_BURST           256
#define DST_LPORT           5

struct fwd_port {
    jcfg_thd_t *thd;                /**< reference to processing thread */
    int lport;                      /**< PKTDEV lport id */
    pktmbuf_t *rx_mbufs[MAX_BURST]; /**< RX mbufs array */
    uint64_t ipackets;              /**< previous rx packets */
    uint64_t opackets;              /**< previous tx packets */
    uint64_t ibytes;                /**< previous rx bytes */
    uint64_t obytes;                /**< previous tx bytes */
};

struct app_options {
    bool no_metrics; /**< Enable metrics*/
    bool no_restapi; /**< Enable REST API*/
    bool cli;        /**< Enable Cli*/
};

struct fwd_info {
    jcfg_info_t *jinfo;      /**< JSON-C configuration */
    uint32_t flags;          /**< Application set of flags */
    volatile int timer_quit; /**< flags to start and stop the application */
    struct app_options opts; /**< Application options*/
};

extern struct fwd_info *fwd; /**< global application informatio pointer */

typedef struct {
    uint64_t enq;
    uint64_t deq;
} dlb_evt_stats;

typedef struct {
    dlb_port_hdl_t port;
    int queue_id;
    int port_id;
    int lcore;
    dlb_evt_stats prev_evt_stats, curr_evt_stats;
} dlb_thread_args_t;

extern dlb_thread_args_t prod_args, cons_args, *work_args;

enum wait_mode_t {
    POLL,
    INTERRUPT,
};

extern dlb_hdl_t dlb; /* DLB Device handle */
extern dlb_dev_cap_t cap;
extern int dev_id;
extern uint64_t num_events;
extern int num_workers;
extern dlb_domain_hdl_t domain;
extern int domain_id;
extern unsigned sns_per_queue;

int parse_args(int argc, char **argv);
void print_dlb_stats(void);
void print_port_stats_all(void);
int producer(void *arg);
int consumer(void *arg);
int worker(void *arg);

static int
print_resources(dlb_hdl_t dlb)
{
    dlb_resources_t rsrcs;

    if (dlb_get_num_resources(dlb, &rsrcs))
        return -1;

    cne_printf("DLB's available resources:\n");
    cne_printf("\tDomains:           %d\n", rsrcs.num_sched_domains);
    cne_printf("\tLDB queues:        %d\n", rsrcs.num_ldb_queues);
    cne_printf("\tLDB ports:         %d\n", rsrcs.num_ldb_ports);
    cne_printf("\tDIR ports:         %d\n", rsrcs.num_dir_ports);
    cne_printf("\tES entries:        %d\n", rsrcs.num_ldb_event_state_entries);
    cne_printf("\tContig ES entries: %d\n", rsrcs.max_contiguous_ldb_event_state_entries);
    if (!cap.combined_credits) {
        cne_printf("\tLDB credits:       %d\n", rsrcs.num_ldb_credits);
        cne_printf("\tContig LDB cred:   %d\n", rsrcs.max_contiguous_ldb_credits);
        cne_printf("\tDIR credits:       %d\n", rsrcs.num_dir_credits);
        cne_printf("\tContig DIR cred:   %d\n", rsrcs.max_contiguous_dir_credits);
        cne_printf("\tLDB credit pls:    %d\n", rsrcs.num_ldb_credit_pools);
        cne_printf("\tDIR credit pls:    %d\n", rsrcs.num_dir_credit_pools);
    } else {
        cne_printf("\tCredits:           %d\n", rsrcs.num_credits);
        cne_printf("\tCredit pools:      %d\n", rsrcs.num_credit_pools);
    }
    cne_printf("\n");

    return 0;
}

static int
create_sched_domain(dlb_hdl_t dlb)
{
    dlb_create_sched_domain_t args;
    dlb_resources_t rsrcs;

    if (dlb_get_num_resources(dlb, &rsrcs))
        return -1;

    args.num_ldb_queues              = (num_workers == 0) ? 0 : 1;
    args.num_ldb_ports               = num_workers;
    args.num_dir_ports               = 2;
    args.num_ldb_event_state_entries = 2 * args.num_ldb_ports * CQ_DEPTH;
    if (!cap.combined_credits) {
        args.num_ldb_credits      = rsrcs.max_contiguous_ldb_credits;
        args.num_dir_credits      = rsrcs.max_contiguous_dir_credits;
        args.num_ldb_credit_pools = 1;
        args.num_dir_credit_pools = 1;
    } else {
        args.num_credits      = rsrcs.num_credits;
        args.num_credit_pools = 1;
    }

    return dlb_create_sched_domain(dlb, &args);
}

static int
create_dir_queue(dlb_domain_hdl_t domain, int port_id)
{
    return dlb_create_dir_queue(domain, port_id);
}

static int
create_ldb_queue(dlb_domain_hdl_t domain)
{
    dlb_create_ldb_queue_t args = {0};

    args.num_sequence_numbers = sns_per_queue;

    return dlb_create_ldb_queue(domain, &args);
}

static int
create_dir_port(dlb_domain_hdl_t domain, int ldb_pool, int dir_pool, int queue_id)
{
    dlb_create_port_t args;

    if (!cap.combined_credits) {
        args.ldb_credit_pool_id = ldb_pool;
        args.dir_credit_pool_id = dir_pool;
        args.num_ldb_credits    = 8;
        args.num_dir_credits    = 8;
    } else {
        args.credit_pool_id = ldb_pool;
        args.num_credits    = 8;
    }

    args.ldb_credit_pool_id = ldb_pool;
    args.dir_credit_pool_id = dir_pool;
    args.cq_depth           = CQ_DEPTH;

    return dlb_create_dir_port(domain, &args, queue_id);
}

static int
create_ldb_port(dlb_domain_hdl_t domain, int ldb_pool, int dir_pool)
{
    dlb_create_port_t args;

    if (!cap.combined_credits) {
        args.ldb_credit_pool_id = ldb_pool;
        args.dir_credit_pool_id = dir_pool;
        args.num_ldb_credits    = 32;
        args.num_dir_credits    = 32;
    } else {
        args.credit_pool_id = ldb_pool;
        args.num_credits    = 32;
    }
    args.cq_depth                    = CQ_DEPTH;
    args.num_ldb_event_state_entries = CQ_DEPTH * 2;
    // #ifdef DLB2
    //     args.cos_id = DLB_PORT_COS_ID_ANY;
    // #endif

    return dlb_create_ldb_port(domain, &args);
}

/**
 * Routine to configure and setup the DLB device
 *
 * @return
 *   Status of the setup
 */
static inline int
dlb_init(void)
{
    int ldb_pool_id = 0, dir_pool_id = 0;
    int prod_port_id, cons_port_id, worker_queue_id;
    int i;

    cne_printf("\nDevice ID - %d, Num Events: %ld, Num Workers: %d\n", dev_id, num_events,
               num_workers);

    work_args = (dlb_thread_args_t *)malloc(sizeof(dlb_thread_args_t) * num_workers);
    if (!work_args)
        CNE_ERR_RET("Failed to allocate memory for workers");

    if (dlb_open(dev_id, &dlb) == -1)
        CNE_ERR_RET("Failed to open dlb device");

    if (dlb_get_dev_capabilities(dlb, &cap))
        CNE_ERR_RET("Failed to get dlb capabilities");

    if (print_resources(dlb))
        CNE_ERR_RET("Failed to get print resources");

    if (dlb_get_ldb_sequence_number_allocation(dlb, 0, &sns_per_queue))
        CNE_ERR_RET("Failed to ldb sequence number allocation");

    domain_id = create_sched_domain(dlb);
    if (domain_id == -1)
        CNE_ERR_RET("Failed to create dlb sched domain");

    domain = dlb_attach_sched_domain(dlb, domain_id);
    if (domain == NULL)
        CNE_ERR_RET("Failed to get attach sched domain");

    if (!cap.combined_credits) {
        ldb_pool_id = dlb_create_ldb_credit_pool(domain, 2048);
        if (ldb_pool_id == -1)
            CNE_ERR_RET("Failed to create ldb credit pool");

        dir_pool_id = dlb_create_dir_credit_pool(domain, 1024);
        if (dir_pool_id == -1)
            CNE_ERR_RET("Failed to create dir credit pool");
    } else {
        ldb_pool_id = dlb_create_credit_pool(domain, 1024);
        if (ldb_pool_id == -1)
            CNE_ERR_RET("Failed to create credit pool");
    }

    prod_args.queue_id = create_dir_queue(domain, -1);
    if (prod_args.queue_id == -1)
        CNE_ERR_RET("Failed to create dir queue");

    cne_printf("DIR Queue Id %d created\n", prod_args.queue_id);
    cons_port_id = create_dir_port(domain, ldb_pool_id, dir_pool_id, prod_args.queue_id);
    if (cons_port_id == -1)
        CNE_ERR_RET("Failed to create dir port");

    cne_printf("DIR Port Id %d created\n", cons_port_id);

    cons_args.port = dlb_attach_dir_port(domain, cons_port_id);
    if (cons_args.port == NULL)
        CNE_ERR_RET("Failed to attach dir port");

    cons_args.port_id  = cons_port_id;
    cons_args.queue_id = prod_args.queue_id;

    /* Set the lcores for producer and consumer threads */
    prod_args.lcore = 1;
    cons_args.lcore = 2;

    if (num_workers > 0) {
        worker_queue_id    = prod_args.queue_id;
        prod_args.queue_id = create_ldb_queue(domain);
        if (prod_args.queue_id == -1)
            CNE_ERR_RET("Failed to create ldb queue");
        cne_printf("LDB Queue Id %d created\n", prod_args.queue_id);
    }

    for (i = 0; i < num_workers; i++) {
        int port_id;
        work_args[i].queue_id = worker_queue_id;

        port_id = create_ldb_port(domain, ldb_pool_id, dir_pool_id);
        if (port_id == -1)
            CNE_ERR_RET("Failed to create ldb port");

        cne_printf("LDB Port Id %d created\n", port_id);

        work_args[i].port = dlb_attach_ldb_port(domain, port_id);
        if (work_args[i].port == NULL)
            CNE_ERR_RET("Failed to attach ldb port");

        if (dlb_link_queue(work_args[i].port, prod_args.queue_id, 0) == -1)
            CNE_ERR_RET("Failed to link queue");

        work_args[i].port_id = port_id;
        cne_printf("Worker %d linked to queue id %d\n", i, prod_args.queue_id);

        /* Set the lcore for worker threads starting from 3 */
        work_args[i].lcore = 3 + i;
    }

    int queue_id = create_dir_queue(domain, -1);
    if (prod_args.queue_id == -1)
        CNE_ERR_RET("Failed to create dir queue");

    cne_printf("DIR Queue Id %d created\n", queue_id);

    prod_port_id = create_dir_port(domain, ldb_pool_id, dir_pool_id, queue_id);
    if (prod_port_id == -1)
        CNE_ERR_RET("Failed to create dir port");

    cne_printf("DIR Port Id %d created\n", prod_port_id);

    prod_args.port = dlb_attach_dir_port(domain, prod_port_id);
    if (prod_args.port == NULL)
        CNE_ERR_RET("Failed to attach dir port");

    prod_args.port_id = prod_port_id;
    if (dlb_launch_domain_alert_thread(domain, NULL, NULL))
        CNE_ERR_RET("Failed to launch domain alert thread");

    if (dlb_start_sched_domain(domain))
        CNE_ERR_RET("Failed to start sched domain");

    return 0;
}

/**
 * Routine to remove and close the DLB device
 *
 */
static inline int
dlb_remove(void)
{
    int i;
    for (i = 0; i < num_workers; i++) {
        if (dlb_detach_port(work_args[i].port) == -1)
            CNE_ERR_RET("Failed to detach port");
    }

    if (dlb_detach_port(cons_args.port) == -1)
        CNE_ERR_RET("Failed to detach port");

    if (dlb_detach_port(prod_args.port) == -1)
        CNE_ERR_RET("Failed to detach port");

    if (dlb_detach_sched_domain(domain) == -1)
        CNE_ERR_RET("Failed to detach sched domain");

    if (dlb_reset_sched_domain(dlb, domain_id) == -1)
        CNE_ERR_RET("Failed to reset sched domain");

    if (dlb_close(dlb) == -1)
        CNE_ERR_RET("Failed to close dlb");

    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _DLB_TEST_H_ */
