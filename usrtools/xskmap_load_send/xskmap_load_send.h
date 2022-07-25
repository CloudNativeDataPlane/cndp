/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Red Hat, Inc.
 * Copyright (c) 2022 Intel Corporation.
 */

#include <stdio.h>
#include <getopt.h>
#include <bsd/string.h>
#include <bpf/bpf.h>
#if USE_LIBXDP
#include <xdp/xsk.h>
#else
#include <bpf/xsk.h>
#endif
#include <cne.h>
#include <uds.h>
#include <cne_stdio.h>
#include <cne_log.h>

#define OPT_NO_COLOR     "no-color"
#define OPT_NO_COLOR_NUM 256

struct map_info {
    char map_path[1024];
    uds_info_t *uds_info;
    volatile int timer_quit;
};

struct map_info info;
