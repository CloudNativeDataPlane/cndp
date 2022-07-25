/*
 * cndp.h - CNDP header
 *
 * Copyright (c) 2021-2022 Intel Corporation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __included_cndp_h__
#define __included_cndp_h__

#if USE_LIBXDP
#include <xdp/xsk.h>
#else
 #include <bpf/xsk.h>
#endif
#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/ethernet/ethernet.h>
#include <cne_lport.h>
#include <pktdev.h>
#include <cne_common.h>
#include <pktdev_driver.h>
#include <cndp/xskdev.h>
#include "cndp_elog.h"

#define USE_2110_ETHERNET_REGISTER_INTERFACE 0
#define USE_2101_RX_QUEUES 0
#define CNDP_MAX_PORTS 30
#define CNDP_MAX_DEVS 6

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
} cndp_trace_t;

/* CNDP port info */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  lport_cfg_t cfg;
  xskdev_info_t *xi;
  // lport_stats_t stats; MT_TODO
  clib_spinlock_t lock;
  u32 qid;
} cndp_lport_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 nb_qs;
  u32 offset;
  u8 pool;

  u32 hw_if_index;
  u32 sw_if_index;
  cndp_lport_t *lports; // previously port_data

  char *ifname;
  struct ether_addr mac;
  u32 instance;

  char *umem_addr;

  /* Buffer template */
  vlib_buffer_t buffer_template;
} cndp_device_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  cndp_device_t *devices[CNDP_MAX_DEVS];
  u32 total_devs;
  u8 log_level;
  vlib_main_t *vlib_main;
} cndp_main_t;

/* cndp.c */
extern cndp_main_t cndp_main;

/* device.c */
extern vnet_device_class_t cndp_device_class;

/* node.c */
extern vlib_node_registration_t cndp_input_node;

/* format.c */
format_function_t format_cndp_device_name;

clib_error_t *cndp_create_dev (vlib_main_t *vm, u8 *ifname, u32 nb_qs,
                               u32 offset);

void cndp_delete_dev (vlib_main_t *vm, u32 sw_if_index);

#endif /* __included_cndp_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
