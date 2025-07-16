# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2025 Intel Corporation

sources = files('main.c', 'parse-args.c', 'stats.c', 'reference.c')

deps += [
    events,
    fib,
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

executable('rtc-m2',
	sources,
	c_args: cflags,
	install: true,
    link_whole: cndp_pmds,
	dependencies: deps)
