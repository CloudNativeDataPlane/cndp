/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <mempool.h>        // for mempool_obj_iter, mempool_destroy, mempool_cfg
#include <cnet.h>           // for cnet_add_instance
#include <cne_vec.h>        // for vec_add, vec_alloc_ptr, vec_at_index
#include <cnet_reg.h>
#include <cnet_stk.h>        // for stk_entry, per_thread_stk, this_stk
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>        // for chnl_domain_str, chnl_protocol_str, chnl_type...
#include <string.h>           // for strlen

#include "cnet_protosw.h"
#include "cne_log.h"        // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_WARNING

/**
 * This module manages the list of "protocol switch" structures, each of which
 * corresponds to a channel type, e.g. {AF_INET, SOCK_DGRAM, IPPROTO_UDP}.
 */
static struct protosw_entry *ipproto_table[CNET_MAX_IPPROTO];

static struct protosw_entry *
cnet_protosw_match(uint16_t domain, uint16_t type, uint16_t proto)
{
    struct protosw_entry *p;

    vec_foreach_ptr (p, this_stk->protosw_vec) {
        if (p->name[0] == '\0')
            continue;

        if ((p->domain == domain) && (p->type == type) && (p->proto == proto))
            return p;
    }

    return NULL;
}

struct protosw_entry *
cnet_protosw_find(uint16_t domain, uint16_t type, uint16_t proto)
{
    struct protosw_entry *p;

    vec_foreach_ptr (p, this_stk->protosw_vec) {
        if (p->name[0] == '\0')
            continue;

        if (p->domain == domain) {
            if (((type == SOCK_ANY) || (p->type == type)) && (p->proto == proto))
                return p;

            if ((p->type == type) && ((proto == SOCK_ANY) || (p->proto == proto)))
                return p;
        }
    }

    return NULL;
}

struct protosw_entry *
cnet_protosw_add(const char *name, uint16_t domain, uint16_t type, uint16_t proto)
{
    struct protosw_entry *psw;

    if (!name || (name[0] == '\0'))
        return NULL;

    /* Locate the entry if it exists, else look for a matching entry */
    psw = cnet_protosw_match(domain, type, proto);

    if (psw)
        return psw;

    psw = calloc(1, sizeof(struct protosw_entry));
    if (!psw)
        return NULL;

    snprintf(psw->name, sizeof(psw->name), "%s", name);

    psw->domain = domain;
    psw->type   = type;
    psw->proto  = proto;

    /* Setup proto ID to index in the protosw table */
    vec_add(this_stk->protosw_vec, psw);

    return psw;
}

int
cnet_ipproto_set(uint8_t ipproto, struct protosw_entry *psw)
{
    if (ipproto_table[ipproto])
        return -1;

    ipproto_table[ipproto] = psw;
    return 0;
}

struct protosw_entry *
cnet_ipproto_get(uint8_t ipproto)
{
    return ipproto_table[ipproto];
}

struct protosw_entry *
cnet_protosw_find_by_proto(uint8_t proto)
{
    struct protosw_entry *psw;

    vec_foreach_ptr (psw, this_stk->protosw_vec) {
        if (psw->proto == proto)
            return psw;
    }

    return NULL;
}

void
cnet_protosw_dump(stk_t *stk)
{
    struct protosw_entry *p;
    int i = 0;

    if (!stk)
        stk = this_stk;

    cne_printf("\n");
    cne_printf("[yellow]Protosw [skyblue]%s[]:\n", stk->name);
    cne_printf("[magenta]idx %-12s %-8s %-8s %-12s  %-14s[]\n", "Name", "Domain", "Type", "Proto",
               "CHNL-Funcs");

    vec_foreach_ptr (p, stk->protosw_vec) {
        if (strlen(p->name) > 0)
            cne_printf(
                "[cyan]%3d [orange]%-12s [goldenrod]%-8s [green]%-8s [cyan]%-8s[]([red]%2d[])  "
                "[skyblue]%14p[]\n",
                i, p->name, chnl_domain_str(p->domain), chnl_type_str(p->type),
                chnl_protocol_str(p->proto), p->proto, p->funcs);
        i++;
    }
}

static int
protosw_destroy(void *_stk)
{
    stk_t *stk = _stk;
    struct protosw_entry *v;

    cnet_assert(stk != NULL);

    vec_foreach_ptr (v, stk->protosw_vec)
        free(v);

    vec_free(stk->protosw_vec);
    stk->protosw_vec = NULL;

    return 0;
}

CNE_INIT_PRIO(cnet_protosw_constructor, STACK)
{
    cnet_add_instance("ProtoSW", CNET_PROTOSW_PRIO, NULL, protosw_destroy);
}
