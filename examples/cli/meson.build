# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2023 Intel Corporation

sources = files('main.c')

deps += [pktdev, pktmbuf, mmap, mempool, txbuff, csock]

executable('cli',
    sources,
    c_args: cflags,
    install: true,
    dependencies: deps)
