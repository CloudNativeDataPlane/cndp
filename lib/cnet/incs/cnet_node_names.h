/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2023 Intel Corporation
 */

#ifndef __CNET_NODE_NAMES_H
#define __CNET_NODE_NAMES_H

/**
 * @file
 * CNET Node names
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Names of all the graph nodes in the CNET stack to eliminate unnecessary
 * constant strings that need to be managed by the developer in all of the
 * node files.
 */
#define ARP_REQUEST_NODE_NAME   "arp_request"
#define ND6_REQUEST_NODE_NAME   "nd6_request"
#define CHNL_CALLBACK_NODE_NAME "chnl_callback"
#define CHNL_RECV_NODE_NAME     "chnl_recv"
#define CHNL_SEND_NODE_NAME     "chnl_send"
#define ETH_RX_NODE_NAME        "eth_rx"
#define ETH_TX_NODE_NAME        "eth_tx"
#define GTPU_INPUT_NODE_NAME    "gtpu_input"
#define IP4_FORWARD_NODE_NAME   "ip4_forward"
#define IP4_INPUT_NODE_NAME     "ip4_input"
#define IP4_OUTPUT_NODE_NAME    "ip4_output"
#define IP4_PROTO_NODE_NAME     "ip4_proto"
#define IP6_FORWARD_NODE_NAME   "ip6_forward"
#define IP6_INPUT_NODE_NAME     "ip6_input"
#define IP6_OUTPUT_NODE_NAME    "ip6_output"
#define IP6_PROTO_NODE_NAME     "ip6_proto"
#define KERNEL_RECV_NODE_NAME   "kernel_recv"
#define NULL_NODE_NAME          "null"
#define PKT_DROP_NODE_NAME      "pkt_drop"
#define PTYPE_NODE_NAME         "ptype"
#define PUNT_KERNEL_NODE_NAME   "punt_kernel"
#define TCP_INPUT_NODE_NAME     "tcp_input"
#define TCP_OUTPUT_NODE_NAME    "tcp_output"
#define UDP_INPUT_NODE_NAME     "udp_input"
#define UDP_OUTPUT_NODE_NAME    "udp_output"
#define ICMP6_INPUT_NODE_NAME   "icmp6_input"
#define ICMP6_OUTPUT_NODE_NAME  "icmp6_output"

#ifdef __cplusplus
}
#endif

#endif /* __CNET_NODE_NAMES_H */
