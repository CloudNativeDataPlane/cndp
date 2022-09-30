# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

sources = files('cnet-graph.c', 'parse-args.c', 'stats.c')

deps += [
    events,
    fib,
    graph,
    hmap,
    kvargs,
    mempool,
    metrics,
    mmap,
    pktdev,
    pktmbuf,
    stack,
    timer,
    tun,
    uds,
    utils,
]

executable('cnet-graph',
    sources,
    c_args: cflags,
    install: true,
    link_whole: cndp_pmds,
    dependencies: deps)
