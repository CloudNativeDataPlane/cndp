/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.
 * Copyright (c) 2019-2025 Intel Corporation.
 * All rights reserved.
 */

#ifndef _CNE_TCP_H_
#define _CNE_TCP_H_

/**
 * @file
 *
 * TCP-related defines
 */

#include <stdint.h>

#include <cne_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * TCP Header
 */
struct cne_tcp_hdr {
    cne_be16_t src_port; /**< TCP source lport. */
    cne_be16_t dst_port; /**< TCP destination lport. */
    cne_be32_t sent_seq; /**< TX data sequence number. */
    cne_be32_t recv_ack; /**< RX data acknowledgment sequence number. */
    uint8_t data_off;    /**< Data offset. */
    uint8_t tcp_flags;   /**< TCP flags */
    cne_be16_t rx_win;   /**< RX flow control window. */
    cne_be16_t cksum;    /**< TCP checksum. */
    cne_be16_t tcp_urp;  /**< TCP urgent pointer, if any. */
} __attribute__((__packed__));

/**
 * TCP Flags
 */
#define TCP_CWR_FLAG 0x80 /**< Congestion Window Reduced */
#define TCP_ECE_FLAG 0x40 /**< ECN-Echo */
#define TCP_URG_FLAG 0x20 /**< Urgent Pointer field significant */
#define TCP_ACK_FLAG 0x10 /**< Acknowledgment field significant */
#define TCP_PSH_FLAG 0x08 /**< Push Function */
#define TCP_RST_FLAG 0x04 /**< Reset the connection */
#define TCP_SYN_FLAG 0x02 /**< Synchronize sequence numbers */
#define TCP_FIN_FLAG 0x01 /**< No more data from sender */

#ifdef __cplusplus
}
#endif

#endif /* CNE_TCP_H_ */
