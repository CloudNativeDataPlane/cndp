# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

sources = files('main.c', 'parse-args.c', 'stats.c', 'acl-func.c')

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

executable('cndpfwd',
	sources,
	c_args: cflags,
	install: true,
    link_whole: cndp_pmds,
	dependencies: deps)
