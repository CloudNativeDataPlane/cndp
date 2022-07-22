# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('pmd_null.c')
headers = files('pmd_null.h')

deps += [cne, mempool, mmap, pktdev, pktmbuf]

libpmd_null = library('pmd_null', sources, install: true, dependencies: deps)
pmd_null = declare_dependency(link_with: libpmd_null, include_directories: include_directories('.'))

cndp_pmds += libpmd_null
