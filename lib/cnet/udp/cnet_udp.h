/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_UDP_H
#define __CNET_UDP_H

/**
 * @file
 * CNET UDP routines and constants.
 */

#include <stdint.h>        // for uint32_t

#include "cnet_const.h"        // for bool_t
#include "cnet_pcb.h"          // for pcb_hd

#ifdef __cplusplus
extern "C" {
#endif

/* UDP parameters for Send and Receive buffer sizes. */
#define MAX_UDP_RCV_SIZE (1024 * 1024)
#define MAX_UDP_SND_SIZE MAX_UDP_RCV_SIZE

struct udp_entry {
    struct pcb_hd udp_hd; /**< Head of the pcb list for UDP */
    bool cksum_on;        /**< Turn UDP checksum on/off */
    uint32_t rcv_size;    /**< UDP Receive Size */
    uint32_t snd_size;    /**< UDP Send Size */
};

#ifdef __cplusplus
}
#endif

#endif /* __CNET_UDP_H */
