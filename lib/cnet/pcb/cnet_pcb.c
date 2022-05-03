/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <cnet.h>        // for cnet_add_instance
#include <cnet_reg.h>
#include <cnet_stk.h>        // for stk_entry, per_thread_stk, this_stk
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>         // for chnl_protocol_str, chnl, AF_INET
#include <netinet/in.h>        // for INADDR_ANY, ntohs

#include "cnet_pcb.h"
#include "cne_inet.h"        // for CIN_PORT, CIN_CADDR, CIN_F...

/*
 * Lookup a PCB in the given list to locate the matching PCB or near matching
 * PCB. The flag value denotes if the match is EXACT or a best match. With the
 * local (laddr) and foreign address (faddr) locate the matching or best
 * matching PCB data.
 *
 * Find a matching local, foreign and port address in the PCB list given. A
 * local copy of the local and foreign address is created for the compare when
 * not doing a exact match, but looking for the best match.
 *
 *   PCB laddr |   laddr   |  Type
 *  -----------+-----------+--------
 *    non-Zero |  non-Zero |  Exact
 *    non-Zero |     Zero  |  Best
 *        Zero | non-Zero  |  Best
 *        Zero |     Zero  |  Invalid
 *
 *   PCB faddr |   faddr   |  Type
 *  -----------+-----------+--------
 *    non-Zero |  non-Zero |  Exact
 *    non-Zero |     Zero  |  Best
 *        Zero | non-Zero  |  Best
 *        Zero |     Zero  |  Invalid
 *
 * The following code is mostly taken from 'TCP/IP Illustrated Volume 2' p726.
 */
static inline struct pcb_entry *
pcb_v4_lookup(struct pcb_entry **vec, struct pcb_key *key, int32_t flag)
{
    struct pcb_entry *match = NULL;
    struct pcb_entry *pcb;
    int wildcard, matchwild = 3;
    uint32_t laddr, faddr;
    uint16_t lport, fport;

    lport = CIN_PORT(&key->laddr);
    fport = CIN_PORT(&key->faddr);
    laddr = CIN_CADDR(&key->laddr);
    faddr = CIN_CADDR(&key->faddr);

    vec_foreach_ptr (pcb, vec) {
        if (CIN_PORT(&pcb->key.laddr) != lport)
            continue;

        wildcard = 0;

        if (CIN_CADDR(&pcb->key.laddr) != INADDR_ANY) {
            if (laddr == INADDR_ANY)
                wildcard++;
            else if (CIN_CADDR(&pcb->key.laddr) != laddr)
                continue;
        } else {
            if (laddr != INADDR_ANY)
                wildcard++;
        }

        if (CIN_CADDR(&pcb->key.faddr) != INADDR_ANY) {
            if (faddr == INADDR_ANY)
                wildcard++;
            else if (CIN_CADDR(&pcb->key.faddr) != faddr || CIN_PORT(&pcb->key.faddr) != fport)
                continue;
        } else {
            if (faddr != INADDR_ANY)
                wildcard++;
        }

        if (wildcard && (flag & EXACT_MATCH))
            continue;

        if (wildcard < matchwild) {
            match     = pcb;
            matchwild = wildcard;
            if (matchwild == 0)
                break; /* Exact match */
        }
    }
    return match;
}

static inline struct pcb_entry *
pcb_v6_lookup(struct pcb_entry **vec, struct pcb_key *key, int32_t flag)
{
    CNE_SET_USED(vec);
    CNE_SET_USED(key);
    CNE_SET_USED(flag);

    return NULL;
}

struct pcb_entry *
cnet_pcb_lookup(struct pcb_hd *hd, struct pcb_key *key, int32_t flag)
{
    if (flag & IPV6_TYPE)
        return pcb_v6_lookup(hd->vec, key, flag);
    else
        return pcb_v4_lookup(hd->vec, key, flag);
}

static void
pcb_obj_cb(mempool_t *mp __cne_unused, void *obj_cb_arg __cne_unused, void *obj,
           unsigned n __cne_unused)
{
    struct pcb_entry *pcb = (struct pcb_entry *)obj;

    memset(pcb, 0, sizeof(struct pcb_entry));

    pcb->closed = 1;
}

static int
pcb_destroy(void *_stk)
{
    stk_t *stk = _stk;
    cnet_assert(stk != NULL);

    mempool_destroy(stk->pcb_objs);
    stk->pcb_objs = NULL;

    return 0;
}

static int
pcb_create(void *_stk)
{
    stk_t *stk             = _stk;
    struct mempool_cfg cfg = {0};

    cfg.objcnt       = CNET_NUM_CHANNELS;
    cfg.objsz        = sizeof(struct pcb_entry);
    cfg.obj_init     = pcb_obj_cb;
    cfg.obj_init_arg = NULL;

    stk->pcb_objs = mempool_create(&cfg);
    if (stk->pcb_objs == NULL)
        return -1;

    return 0;
}

CNE_INIT_PRIO(cnet_pcb_constructor, STACK)
{
    cnet_add_instance("PCB", CNET_PCB_PRIO, pcb_create, pcb_destroy);
}

static void
pcb_show(struct pcb_entry *pcb)
{
    char fbuf[128], lbuf[128], *ret = NULL;
    char ip1[IP4_ADDR_STRLEN] = {0};
    char ip2[IP4_ADDR_STRLEN] = {0};

    if (pcb->closed)
        return;

    cne_printf("       [green]%-6s [orange] %04x [red]%6s[]", pcb->closed ? "Closed" : "Open",
               pcb->opt_flag, chnl_protocol_str(pcb->ip_proto));

    ret = inet_ntop4(ip1, sizeof(ip1), &pcb->key.faddr.cin_addr, NULL);
    if (snprintf(fbuf, sizeof(fbuf), "%s:%d", ret ? ret : "Invalid IP",
                 ntohs(CIN_PORT(&pcb->key.faddr))) < 0)
        CNE_RET("Truncated buffer data\n");

    cne_printf(" [orange]%20s[]", fbuf);

    ret = inet_ntop4(ip2, sizeof(ip2), &pcb->key.laddr.cin_addr, NULL);
    if (snprintf(lbuf, sizeof(lbuf), "%s:%d", ret ? ret : "Invalid IP",
                 ntohs(CIN_PORT(&pcb->key.laddr))) < 0)
        CNE_RET("Truncated buffer data\n");

    cne_printf(" [cyan]%20s[] %4d\n", lbuf, pcb->ttl);
}

static void
pcb_iterate(mempool_t *mp __cne_unused, void *obj_cb_arg __cne_unused, void *obj,
            unsigned n __cne_unused)
{
    pcb_show((struct pcb_entry *)obj);
}

static void
pcb_dump(stk_t *stk)
{
    if (!stk)
        stk = this_stk;

    cne_printf("[yellow]PCB[]: [skyblue]%s\n", stk->name);
    cne_printf("       [magenta]%-6s %5s %6s %20s %20s %4s[]\n", "State", "Flags", "Proto",
               "Foreign", "Local", "TTL");

    mempool_obj_iter(stk->pcb_objs, pcb_iterate, NULL);
}

void
cnet_pcb_dump(stk_t *stk)
{
    pcb_dump(stk);
}

void
cnet_pcb_show(struct pcb_entry *pcb)
{
    if (!pcb)
        return;
    cne_printf("       [magenta]%-6s %5s %6s %20s %20s %4s[]\n", "State", "Flags", "Proto",
               "Foreign", "Local", "TTL");
    pcb_show(pcb);
}
