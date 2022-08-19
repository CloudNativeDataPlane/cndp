# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

sources = files('fwd.c', 'parse-args.c', 'stats.c')

deps += [pktdev, graph, mempool, pktmbuf,
    mmap, uds, metrics, pmd_af_xdp, pmd_af_packet, nodes]

executable('l3fwd-graph',
    sources,
    c_args: cflags,
    install: true,
    dependencies: deps)
