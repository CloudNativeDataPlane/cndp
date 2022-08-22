/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_CMDS_H_
#define _TXGEN_CMDS_H_

#include <inttypes.h>
#include <cne_version.h>
#include <net/cne_net.h>
#include <cne_strings.h>
#include <portlist.h>
#include <stdint.h>        // for uint32_t, uint16_t, uint8_t

#include "txgen.h"
#include "ether.h"           // for eth_stats_t
#include "port-cfg.h"        // for port_info_t, port_sizes_t
#include "stats.h"           // for pkt_stats_t

struct ether_addr;

#ifdef __cplusplus
extern "C" {
#endif

/* Internal APIs */
char *txgen_flags_string(port_info_t *info);
char *txgen_transmit_count_rate(int lport, char *buff, int len);
void txgen_update(void);
char *txgen_link_state(int lport, char *buff, int len);
char *txgen_transmit_count(int lport, char *buff, int len);
char *txgen_transmit_rate(int lport, char *buff, int len);
int txgen_pkt_stats(int lport, pkt_stats_t *pstats);
int txgen_port_stats(int lport, const char *name, eth_stats_t *pstats);
int txgen_port_sizes(int lport, port_sizes_t *psizes);

/* Global commands */
void txgen_start_transmitting(port_info_t *info);
void txgen_stop_transmitting(port_info_t *info);
void txgen_screen(int state);
void txgen_force_update(void);
void txgen_update_display(void);
void txgen_clear_display(void);

int txgen_save(char *path);
void txgen_cls(void);
void txgen_clear_stats(port_info_t *info);
void txgen_reset(port_info_t *info);
void txgen_port_restart(port_info_t *info);
void txgen_quit(void);
void txgen_set_port_number(uint16_t port_number);
void txgen_port_defaults(uint32_t pid);

/* Single */
void single_set_ipaddr(port_info_t *info, char type, struct in_addr *ip, int prefixlen);
void single_set_proto(port_info_t *info, char *type);
void single_set_mac(port_info_t *info, const char *which, struct ether_addr *mac);
void single_set_dst_mac(port_info_t *info, struct ether_addr *mac);
void single_set_src_mac(port_info_t *info, struct ether_addr *mac);
void single_set_pkt_type(port_info_t *info, const char *type);
void single_set_tx_count(port_info_t *info, uint32_t cnt);
void single_set_tx_burst(port_info_t *info, uint32_t burst);
void single_set_pkt_size(port_info_t *info, uint16_t size);
void single_set_tx_rate(port_info_t *info, const char *rate);
void single_set_ttl_value(port_info_t *info, uint8_t ttl);
void single_set_port_value(port_info_t *info, char type, uint32_t portValue);

/* Pattern */
void pattern_set_type(port_info_t *info, char *str);
void pattern_set_user_pattern(port_info_t *info, char *str);

/* Enable or toggle types */
void enable_pcap(port_info_t *info, uint32_t state);
void enable_capture(port_info_t *info, uint32_t state);

/* PCAP */
void pcap_filter(port_info_t *info, char *str);

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_CMDS_H_ */
