/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#ifndef __IP6_FLOWLABEL_H
#define __IP6_FLOWLABEL_H

#include <netinet/in.h>        // for in6_addr
#include <stdint.h>            // for uint16_t, int32_t, uint32_t, uintptr_t
#include <stdbool.h>           // for bool
#include <cnet_pcb.h>
#include "net/cne_ip.h"        // for cne_ipv6_hdr

#ifdef __cplusplus
extern "C" {
#endif

void do_srhash_init(uint32_t seed);
// void srhash_init0(void);

bool ip6_autoflowlabel(struct pcb_entry *pcb);

uint32_t ip6_make_flowlabel(uint32_t flowlabel, bool autolabel);

/**
 * Get system control values.
 *
 * @param path
 *   The path string to the control value.
 * @return
 *   -1 on error or value on success
 */

CNDP_API int get_sysctl_value(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* __IP6_FLOWLABEL_H */
