/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <cnet_icmp6.h>
#include <cnet_stk.h>          // for stk_entry, per_thread_stk, proto_...
#include <netinet/in.h>        // for IPPROTO_ICMPV6
#include <stdlib.h>            // for NULL, calloc, free

#include "cne_log.h"             // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_W...
#include "cne_vec.h"             // for vec_len, vec_free_mbuf_at_index
#include "cnet_protosw.h"        // for cnet_protosw_add()
#include "cnet_reg.h"            // for cnet_add_instance

static int
icmp6_create(void *_stk)
{
    stk_t *stk = _stk;
    struct protosw_entry *psw;

    stk->icmp6 = calloc(1, sizeof(struct icmp6_entry));
    if (stk->icmp6 == NULL) {
        CNE_ERR("Allocation of ICMP6 structure failed\n");
        return -1;
    }

    psw = cnet_protosw_add("ICMP6", AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (psw == NULL)
        psw = cnet_protosw_add("ICMP6", AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    CNE_ASSERT(psw != NULL);

    stk->icmp6->cksum_on            = 1;
    stk->icmp6->rcv_size            = MAX_ICMP6_RCV_SIZE;
    stk->icmp6->snd_size            = MAX_ICMP6_SND_SIZE;
    stk->icmp6->icmp6_hd.local_port = _IPPORT_RESERVED;

    return 0;
}

static int
icmp6_destroy(void *_stk)
{
    stk_t *stk = _stk;

    if (stk->icmp6) {
        struct pcb_entry *p;

        vec_foreach_ptr (p, stk->icmp6->icmp6_hd.vec)
            free(p);
        vec_free(stk->icmp6->icmp6_hd.vec);
        stk->icmp6->icmp6_hd.vec = NULL;
        free(stk->icmp6);
        stk->icmp6 = NULL;
    }
    return 0;
}

CNE_INIT_PRIO(cnet_icmp6_constructor, STACK)
{
    cnet_add_instance("icmp6", CNET_ICMP6_PRIO, icmp6_create, icmp6_destroy);
}
