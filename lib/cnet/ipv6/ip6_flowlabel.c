/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Sartura Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "ip6_flowlabel.h"

void
do_srhash_init(uint32_t seed)
{
    time_t now;

    if (seed > 0)
        srand(seed);
    else {
        now = time(NULL);
        srand(now);
    }
}

/*
 * rotate_32 - Rotate a 32-bit value
 */
static inline uint32_t
rotate_32(uint32_t val, unsigned int shiftSize)
{
    if (shiftSize == 0)
        return val;

    return (val >> shiftSize) | (val << (64 - shiftSize));
}

static inline uint32_t
get_new_srhash(unsigned int rshftSz)
{
    uint32_t rhash;

    rhash = (rand() % IP6_MAX_FLOW_LABEL_RANGE) + 1;

    rhash = rotate_32(rhash, rshftSz);
    return rhash;
}

static inline int
ip6_default_np_autolabel(void)
{
    int auto_flowlabels_val;

    auto_flowlabels_val = get_sysctl_value(IP6_AUTO_FLOWLABELS_PATH);
    switch (auto_flowlabels_val) {
    case IP6_AUTO_FLOW_LABEL_OFF:
    case IP6_AUTO_FLOW_LABEL_OPTIN:
    default:
        return 0;
    case IP6_AUTO_FLOW_LABEL_OPTOUT:
    case IP6_AUTO_FLOW_LABEL_FORCED:
        return 1;
    }
}

bool
ip6_autoflowlabel(struct pcb_entry *pcb)
{
    /*
     * If no ipv6 socket option set then read directly from sysctl
     * */

    if (pcb->ip6_fl_entry == NULL || !pcb->ip6_fl_entry->autoflowlabel_set)
        return ip6_default_np_autolabel();
    else
        return pcb->ip6_fl_entry->autoflowlabel;
}

int
get_sysctl_value(const char *path)
{
    FILE *fp;
    int val = -1;

    if (access(path, R_OK) != 0)
        return val;

    fp = fopen(path, "r");
    fscanf(fp, "%d", &val);

    fclose(fp);

    return val;
}

uint32_t
ip6_make_flowlabel(uint32_t flowlabel, bool autolabel)
{
    uint32_t hash;
    int auto_flowlabels_val, flowlabel_state_ranges_val;
    unsigned int rshift_sz = 16;

    flowlabel &= IPV6_FLOWLABEL_MASK;
    auto_flowlabels_val = get_sysctl_value(IP6_AUTO_FLOWLABELS_PATH);

    if (flowlabel || auto_flowlabels_val == IP6_AUTO_FLOW_LABEL_OFF ||
        (!autolabel && auto_flowlabels_val != IP6_AUTO_FLOW_LABEL_FORCED))
        return flowlabel;

    hash = get_new_srhash(rshift_sz);

    flowlabel = (__be32)hash & IPV6_FLOWLABEL_MASK;

    flowlabel_state_ranges_val = get_sysctl_value(IP6_FLOWLABEL_STATE_RANGES_PATH);
    if (flowlabel_state_ranges_val > 0)
        flowlabel |= IPV6_FLOWLABEL_STATELESS_FLAG;

    return flowlabel;
}
