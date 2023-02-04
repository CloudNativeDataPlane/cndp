# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2023 Intel Corporation

sources = files('fwd.c', 'parse-args.c', 'stats.c')

deps += [
    events,
    graph,
    mempool,
    metrics,
    mmap,
    nodes,
    pktdev,
    pktmbuf,
    tun,
    uds,
    ]

executable('l3fwd-graph',
    sources,
    c_args: cflags,
    install: true,
    link_whole: cndp_pmds,
    dependencies: deps)
