# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017-2022 Intel Corporation

proc_1_target = files('proc_1.c')

deps += [
    acl,
    bpf_dep,
    events,
    idlemgr,
    mempool,
    metrics,
    mmap,
    pktdev,
    pktmbuf,
    ring,
    tun,
    txbuff,
    uds,
    udsc,
    xskdev,
]
executable('proc_1',
    proc_1_target,
    c_args: cflags,
    install: true,
    dependencies: deps)
