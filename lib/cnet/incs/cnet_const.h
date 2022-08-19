/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_CONST_H
#define __CNET_CONST_H

/**
 * @file
 * CNET Constant values.
 */

#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>

#include <cne_prefetch.h>

#include <cne_log.h>

#include <errno.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Stack tick rate in milliseconds */
#define MS_PER_TICK 10

/* Determine if a bit is set or cleared as a boolean expression */
#define is_set(x, y) (((x) & (y)) != 0)
#define is_clr(x, y) (((x) & (y)) == 0)

#define PROTO_DEFAULT_MBUF_COUNT 1024  /**< Default UDP/TCP mbuf count */
#define _IPPORT_RESERVED         49152 /**< Starting Ephemeral Port value */

/**
 * short definition to set a function does not return
 */
#define __cnet_no_return __attribute__((__no_return__))

/**
 * short definition to define any attribute value(s)
 */
#define __cnet_attribute(...) __attribute__((__VA_ARGS__))

#ifdef CNET_ASSERT_ENABLED
#define cnet_assert(x) assert(x)
#else
#define cnet_assert(x) \
    do {               \
    } while (/*CONSTCOND*/ 0)
#endif

enum {
    CNET_MAX_INITS   = 64,
    PROTOSW_MAX_SIZE = 64,
};

enum {
    CNET_PRIORITY_0  = 0x0000,
    CNET_PRIORITY_1  = 0x0100,
    CNET_PRIORITY_2  = 0x0200,
    CNET_PRIORITY_3  = 0x0300,
    CNET_PRIORITY_4  = 0x0400,
    CNET_PRIORITY_5  = 0x0500,
    CNET_PRIORITY_6  = 0x0600,
    CNET_PRIORITY_7  = 0x0700,
    CNET_PRIORITY_8  = 0x0800,
    CNET_PRIORITY_9  = 0x0900,
    CNET_PRIORITY_10 = 0x0a00
};

enum {
    CNET_NETLINK_PRIO = (CNET_PRIORITY_1 + 0), /**< Per stack instance priorities */
    CNET_STK_PRIO     = (CNET_PRIORITY_1 + 1),
    CNET_PROTOSW_PRIO = (CNET_PRIORITY_1 + 2),

    CNET_IPV4_PRIO = (CNET_PRIORITY_2 + 0),
    CNET_IPV6_PRIO = (CNET_PRIORITY_2 + 1),
    CNET_ND_PRIO   = (CNET_PRIORITY_2 + 2),

    CNET_ICMP_PRIO  = (CNET_PRIORITY_3 + 0),
    CNET_ICMP6_PRIO = (CNET_PRIORITY_3 + 1),
    CNET_RARP_PRIO  = (CNET_PRIORITY_3 + 2),

    CNET_PCB_PRIO = (CNET_PRIORITY_4 + 0),
    CNET_UDP_PRIO = (CNET_PRIORITY_4 + 1),
    CNET_TCP_PRIO = (CNET_PRIORITY_4 + 2),
    CNET_RAW_PRIO = (CNET_PRIORITY_4 + 3),

    CNET_CHNL_PRIO       = (CNET_PRIORITY_5 + 0),
    CNET_RAW_CHNL_PRIO   = (CNET_PRIORITY_5 + 1),
    CNET_UDP_CHNL_PRIO   = (CNET_PRIORITY_5 + 2),
    CNET_TCP_CHNL_PRIO   = (CNET_PRIORITY_5 + 3),
    CNET_ICMP_CHNL_PRIO  = (CNET_PRIORITY_5 + 4),
    CNET_ICMP6_CHNL_PRIO = (CNET_PRIORITY_5 + 5),

    CNET_UTILS_PRIO = (CNET_PRIORITY_9 + 0),
    CNET_CFG_PRIO   = (CNET_PRIORITY_10),
};

enum {
    STK_VEC_COUNT       = 32,
    TCP_VEC_PCB_COUNT   = 32,
    UDP_VEC_PCB_COUNT   = 32,
    RAW_VEC_PCB_COUNT   = 32,
    ICMP_VEC_PCB_COUNT  = 32,
    ICMP6_VEC_PCB_COUNT = 32,
    CHNL_OPT_VEC_COUNT  = 8,
};

/* Generic matching flags for pcb, route, and arp lookups */
typedef enum { EXACT_MATCH = 1, BEST_MATCH = 2, IPV6_TYPE = 0x80 } match_t;

typedef enum { CNET_INIT = 1, CNET_STOP, CNET_ALL } init_types_e;

struct netif;
struct chnl;
struct tcb_entry;
struct pcb_entry;
struct cnet;
struct stk_s;
struct pktmbuf_s;

/**< List of protocol input funcs */
typedef int (*proto_input_t)(struct netif *netif, struct pktmbuf_s **vec);

typedef int (*cfunc_t)(void *arg);
typedef int (*vfunc_t)(void);

typedef union iofunc_s {
    void (*generic)(void);

    int (*netif)(struct netif *netif);
    int (*ifunc)(struct netif *netif, struct pktmbuf_s **vec);
    void (*vfunc)(struct netif *netif, struct pktmbuf_s **vec);
    int (*ioctl)(struct netif *netif, int cmd, void *data);

    int (*chfunc)(struct chnl *ch, struct pktmbuf_s **vec);
    int (*tcbfunc)(struct tcb_entry *tcb);
} iofunc_t;

enum {
    _SELREAD,  /**< Select read flag */
    _SELWRITE, /**< Select write flag */
    _SELEXCEPT /**< Select exception flag */
};

enum {
    ARP_IO, /* Keep in this order, cnet_netif.c:netif_input */
    RARP_IO,
    IPV4_IO,
    IPV6_IO,

    RAW_IO,
    UDP_IO,
    TCP_IO,
    ICMP_IO,
    ICMPV6_IO,
    ND_IO,
    LO_IO,
    NETIF_IO,

    PROTO_IO_MAX
};

static inline int
__errno_get(void)
{
    return errno;
}

/**
 * This routine sets the system 'errno' value.
 *
 * RETURNS: OK, or ERROR if errno is set to a non-zero value.
 *
 * ERRNO: N/A
 */
static inline int
__errno_set(int errorValue)
{
    return errno = errorValue, (errorValue ? -1 : 0);
}

/**
 * This routine sets the system 'errno' value.
 *
 * RETURNS: NULL
 *
 * ERRNO: N/A
 */
static inline void *
__errno_set_null(int errorValue)
{
    return errno = errorValue, NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* __CNET_CONST_H */
