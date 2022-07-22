# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('pmd_ring.c')
headers = files('pmd_ring.h')

deps += [pktdev, ring, pktmbuf, mmap, mempool, cne, kvargs]

libpmd_ring = library('pmd_ring', sources, install: true, dependencies: deps)
pmd_ring = declare_dependency(link_with: libpmd_ring, include_directories: include_directories('.'))

cndp_pmds += libpmd_ring
