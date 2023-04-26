# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2023 Intel Corporation

sources = files('main.c', 'parse-args.c', 'phil.c')

deps += [cli, cne, cthread, metrics, pktmbuf, mempool,
    timer, mmap, jcfg, thread, bpf_dep, uds]

executable('phil',
    sources,
    c_args: cflags,
    install: true,
    dependencies: deps)
