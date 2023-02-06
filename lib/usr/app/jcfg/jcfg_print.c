/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation.
 */

#include <cne_common.h>        // for __cne_unused
#include <cne_log.h>
#include <sched.h>        // for CPU_COUNT, CPU_ISSET, CPU_SETSIZE

#include "jcfg_print.h"
#include "jcfg_private.h"
#include "cne_mmap.h"        // for mmap_name_by_type

void
__print_object(jcfg_hdr_t *hdr, obj_value_t *val)
{
    cne_printf("   '[cyan]%-12s[]' ", hdr->name);
    switch (val->type) {
    case BOOLEAN_OPT_TYPE:
        cne_printf("[green]Boolean[]: [magenta]%s[]", val->boolean ? "true" : "false");
        break;
    case STRING_OPT_TYPE:
        cne_printf("[green]String[]:  '[magenta]%s[]'", val->str);
        break;
    case INTEGER_OPT_TYPE:
        cne_printf("[green]Integer[]: [magenta]%ld[]", val->value);
        break;
    case ARRAY_OPT_TYPE:
        cne_printf("[green]Array[] [magenta]%u[]: [white][ ", val->array_sz);
        break;
    case OBJECT_OPT_TYPE:
        cne_printf("[green]Object[] [magenta]%u[]: [white]{ ", val->array_sz);
        break;
    default:
        cne_printf("[red]Unknown type %d[]:", val->type);
        break;
    }

    if (val->array_sz > 0) {
        for (int i = 0; i < val->array_sz; i++) {
            switch (val->arr[i]->type) {
            case BOOLEAN_OPT_TYPE:
                cne_printf("[magenta]%s[] ", val->arr[i]->boolean ? "true" : "false");
                break;
            case STRING_OPT_TYPE:
                cne_printf("[white]'[magenta]%s[white]'[] ", val->arr[i]->str);
                break;
            case INTEGER_OPT_TYPE:
                cne_printf("[magenta]%ld[] ", val->arr[i]->value);
                break;
            default:
                break;
            }
        }
    }
    if (val->type == ARRAY_OPT_TYPE)
        cne_printf("[white]]");
    else if (val->type == OBJECT_OPT_TYPE)
        cne_printf("[white]}");
    cne_printf("\n");
}

void
__print_umem(jcfg_hdr_t *hdr, obj_value_t *val __cne_unused)
{
    jcfg_umem_t *u = (jcfg_umem_t *)hdr;

    cne_printf("   '[cyan]%-12s[]' [green]bufcnt[]: [magenta]%u[] [green]bufsz[]: [magenta]%u[]",
               u->name, u->bufcnt, u->bufsz);
    cne_printf(" [green]type[]: [magenta]%s[] [green]rxdesc[]: [magenta]%u[] [green]txdesc[]: "
               "[magenta]%u[]\n",
               mmap_name_by_type(u->mtype), u->rxdesc, u->txdesc);
    cne_printf("                  [green]regions[]: [magenta]%u[] [ ", u->region_cnt);
    for (int i = 0; i < u->region_cnt; i++)
        cne_printf("[magenta]%u[] ", u->rinfo[i].bufcnt);
    cne_printf("] ([yellow]%s[])\n", u->desc);
}

void
__print_lport(jcfg_hdr_t *hdr, obj_value_t *val __cne_unused)
{
    jcfg_lport_t *lport = (jcfg_lport_t *)hdr;

    cne_printf("   '[cyan]%-12s[]' [green]netdev[]: [magenta]%s[] [green]pmd[]: "
               "[magenta]%s[] [green]lport[]: [magenta]%d[] [green]qid[]: [magenta]%d[] "
               "[green]region[]: [magenta]%d[] "
               "[green]umem[]: [magenta]%s[] ([yellow]%s[])\n",
               lport->name, lport->netdev, lport->pmd_name, lport->lpid, lport->qid,
               lport->region_idx, lport->umem_name, lport->desc);
}

void
__print_lgroup(jcfg_hdr_t *hdr, obj_value_t *val __cne_unused)
{
    jcfg_lgroup_t *lgroup = (jcfg_lgroup_t *)hdr;

    cne_printf("   '[cyan]%-12s[]' [green]lcores[]: [magenta]%2d[]:[ ", lgroup->name,
               CPU_COUNT(&lgroup->lcore_bitmap));
    for (int i = 0; i < CPU_SETSIZE; i++)
        if (CPU_ISSET(i, &lgroup->lcore_bitmap))
            cne_printf("[magenta]%d[] ", i);
    cne_printf("]\n");
}

void
__print_thread(jcfg_hdr_t *hdr, obj_value_t *val __cne_unused)
{
    jcfg_thd_t *thd = (jcfg_thd_t *)hdr;

    cne_printf("   '[cyan]%-12s[]' [green]group[]: [magenta]%-10s[] [green]type[]: "
               "'[yellow]%-10s[]' [green]lports[]: [ ",
               thd->name, thd->group_name, thd->thread_type ? thd->thread_type : "");

    for (int i = 0; i < thd->lport_cnt; i++)
        cne_printf("'[magenta]%s[]' ", thd->lport_names[i]);

    cne_printf("] ([yellow]%s[])\n", thd->desc);
}

void
__print_lport_group(jcfg_hdr_t *hdr, obj_value_t *val __cne_unused)
{
    jcfg_lport_group_t *lpg = (jcfg_lport_group_t *)hdr;
    int i;

    cne_printf("   '[cyan]%-12s[]' [green]netdevs[]: [ ", lpg->name);

    for (i = 0; i < lpg->num_netdev_names; i++)
        cne_printf("'[magenta]%s[]' ", lpg->netdev_names[i]);

    if (lpg->qlist) {
        struct queue_list *qlist = (struct queue_list *)lpg->qlist;
        struct queue_list_entry *e;

        cne_printf("] [green]queues[]: [ ");

        TAILQ_FOREACH (e, &qlist->head, next)
            cne_printf("[magenta]%u[] ", e->v);
    }

    cne_printf("] [green]threads[]: [ ");

    for (i = 0; i < lpg->num_thread_names; i++)
        cne_printf("'[magenta]%s[]' ", lpg->thread_names[i]);

    if (lpg->desc)
        cne_printf("] ([yellow]%s[])\n", lpg->desc);
    else
        cne_printf("]\n");
}
