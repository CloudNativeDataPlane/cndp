# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

sources = files('cnet-graph.c', 'parse-args.c', 'stats.c')

deps += [pktdev, graph, mempool, pktmbuf, hmap, timer,
    mmap, uds, metrics, pmd_af_xdp, fib, stack, utils]

executable('cnet-graph',
    sources,
    c_args: cflags,
    install: true,
    dependencies: deps)
