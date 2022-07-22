# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('pmd_tap.c')
headers = files('pmd_tap.h')

deps += [cne, mempool, mmap, pktdev, pktmbuf, tun]

libpmd_tap = library('pmd_tap', sources, install: true, dependencies: deps)
pmd_tap = declare_dependency(link_with: libpmd_tap, include_directories: include_directories('.'))

cndp_pmds += libpmd_tap
