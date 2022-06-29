/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#include <cnet.h>                  // for cnet_add_instance
#include <cnet_stk.h>              // for stk_entry, per_thread_stk, proto_...
#include <cne_inet.h>              // for inet_ntop4, in_caddr_copy, in_cad...
#include <cnet_pcb.h>              // for pcb_entry, pcb_key, pcb_hd, cnet_...
#include <cnet_ip_common.h>        // for ip_info
#include <cnet_netif.h>            // for net_addr, cnet_ipv4_compare, netif
#include "../chnl/chnl_priv.h"
#include <cnet_chnl.h>         // for AF_INET, SOCK_DGRAM, CH_IP_DONTFRAG
#include <cnet_route.h>        // for rt_funcs, rt_lookup_t
#include <cnet_udp.h>
#include <endian.h>             // for be16toh, htobe16
#include <netinet/in.h>         // for IPPROTO_UDP
#include <stdlib.h>             // for NULL, calloc, free
#include <cnet_route4.h>        // for

#include "cne_branch_prediction.h"        // for unlikely, likely
#include <net/cne_ether.h>                // for cne_ether_hdr
#include "net/cne_ip.h"                   // for cne_ipv4_hdr, cne_ipv4_udptcp_cksum
#include "cne_log.h"                      // for CNE_LOG, CNE_LOG_DEBUG, CNE_LOG_W...
#include "net/cne_udp.h"                  // for cne_udp_hdr
#include "cne_vec.h"                      // for vec_len, vec_free_mbuf_at_index
#include "cnet_reg.h"
#include "cnet_ipv4.h"           // for _OFF_DF
#include "cnet_protosw.h"        // for
#include "pktmbuf.h"             // for pktmbuf_data_len, pktmbuf_t, pktm...
#include "cnet_fib_info.h"

static int
udp_create(void *_stk)
{
    stk_t *stk = _stk;
    struct protosw_entry *psw;

    stk->udp = calloc(1, sizeof(struct udp_entry));
    if (stk->udp == NULL) {
        CNE_ERR("Allocation of UDP structure failed\n");
        return -1;
    }

    psw = cnet_protosw_add("UDP", AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CNE_ASSERT(psw != NULL);

    cnet_ipproto_set(IPPROTO_UDP, psw);

    stk->udp->cksum_on          = 1;
    stk->udp->rcv_size          = MAX_UDP_RCV_SIZE;
    stk->udp->snd_size          = MAX_UDP_SND_SIZE;
    stk->udp->udp_hd.local_port = _IPPORT_RESERVED;

    return 0;
}

static int
udp_destroy(void *_stk)
{
    stk_t *stk = _stk;

    if (stk->udp) {
        struct pcb_entry *p;

        vec_foreach_ptr (p, stk->udp->udp_hd.vec)
            free(p);
        vec_free(stk->udp->udp_hd.vec);
        stk->udp->udp_hd.vec = NULL;
        free(stk->udp);
        stk->udp = NULL;
    }
    return 0;
}

CNE_INIT_PRIO(cnet_udp_constructor, STACK)
{
    cnet_add_instance("udp", CNET_UDP_PRIO, udp_create, udp_destroy);
}
