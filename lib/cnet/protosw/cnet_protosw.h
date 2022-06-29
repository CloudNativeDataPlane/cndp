/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_PROTOSW_H
#define __CNET_PROTOSW_H

/**
 * @file
 * CNET Ptotocol switch routines.
 */

#include <stdint.h>           // for uint16_t, uint8_t
#include <stdio.h>            // for size_t
#include <sys/types.h>        // for ssize_t

#include "cnet_const.h"        // for proto_input_t
#ifdef __cplusplus
extern "C" {
#endif

#define CNET_MAX_IPPROTO 256
#define PROTOSW_WILDCARD 0xFFFF

struct in_caddr;
struct chnl;
struct cne_vec;
struct stk_s;

/*
 * protoFuncs_t - structure to hold all of the protocol function pointers.
 *
 * Each function pointer must have a valid value, which means may have to set
 * the function pointer to the nullProtocol routine, if not supported.
 *
 * The following functions are called as indicated below.
 */
typedef int (*close_func_t)(struct chnl *ch);
typedef int (*send_func_t)(struct chnl *ch, pktmbuf_t **mbufs, uint16_t nb_mbufs);
typedef int (*recv_func_t)(struct chnl *ch, pktmbuf_t **mbufs, int nb_mbufs);
typedef int (*bind_func_t)(struct chnl *ch, struct in_caddr *pAddr, int len);
typedef int (*connect_func_t)(struct chnl *ch, struct in_caddr *to, int slen);
typedef int (*shutdown_func_t)(struct chnl *ch, int how);
typedef int (*accept_func_t)(struct chnl *ch, struct in_caddr *addr, int *addrlen);
typedef int (*listen_func_t)(struct chnl *ch, int backlog);

struct proto_funcs {
    close_func_t close_func;       /**< close routine */
    recv_func_t recv_func;         /**< receive routine */
    send_func_t send_func;         /**< send routine */
    bind_func_t bind_func;         /**< bind routine */
    connect_func_t connect_func;   /**< connect routine */
    shutdown_func_t shutdown_func; /**< shutdown routine*/
    accept_func_t accept_func;     /**< accept routine */
    listen_func_t listen_func;     /**< listen routine */
};

/*
 * protosw_t - Protocol switch structure to hold all of the different types
 */
struct protosw_entry {
    char name[14];             /**< Name field for display only */
    uint16_t domain;           /**< Domain type AF_XXXX */
    uint16_t type;             /**< Type of protocol */
    uint16_t proto;            /**< Protocol type */
    pktmbuf_t **vec;           /**< CNET vec pointer */
    struct proto_funcs *funcs; /**< Protocol functions */
};

/**
 * @brief Add protocol information to the list of protocol switch list.
 *
 * @param name
 *   The number of protocol name to add.
 * @param domain
 *   The domain of the protocol to add.
 * @param type
 *   The type of protocol to add.
 * @param proto
 *   The proto type value to add.
 * @return
 *   NULL on error or a pointer to a protocol switch entry.
 */
CNDP_API struct protosw_entry *cnet_protosw_add(const char *name, uint16_t domain, uint16_t type,
                                                uint16_t proto);

/**
 * @brief Find a protocol entry in the protocol switch list.
 *
 * @param domain
 *   The domain to search for in the list.
 * @param type
 *   The type of protocol.
 * @param proto
 *   The proto type value.
 * @return
 *   NULL on error or a pointer to a protocol switch entry.
 */
CNDP_API struct protosw_entry *cnet_protosw_find(uint16_t domain, uint16_t type, uint16_t proto);

/**
 * @brief Dump out the list of protocol switch values.
 *
 * @param stk
 *   The stack instance to be dumped.
 * @return
 *   N/A
 */
CNDP_API void cnet_protosw_dump(struct stk_s *stk);

/**
 * @brief Set the IP proto value in the given protosw_entry pointer.
 *
 * @param ipproto
 *   The IP proto type value to be set in the structure.
 * @param psw
 *   The protosw_entry structure pointer.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cnet_ipproto_set(uint8_t ipproto, struct protosw_entry *psw);

/**
 * @brief Get the protosw_entry to locate using the IP proto type.
 *
 * @param ipproto
 *   The IP proto type value to be set in the structure.
 * @return
 *   NULL on error or a pointer to a protocol switch entry.
 */
CNDP_API struct protosw_entry *cnet_ipproto_get(uint8_t ipproto);

/**
 * @brief Find a protocol switch entry using the IP proto type.
 *
 * @param proto
 *   The IP proto type value to be set in the structure.
 * @return
 *   NULL on error or a pointer to a protocol switch entry.
 */
CNDP_API struct protosw_entry *cnet_protosw_find_by_proto(uint8_t proto);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_PROTOSW_H */
