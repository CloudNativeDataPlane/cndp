# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('pmd_af_xdp.c')
headers = files('pmd_af_xdp.h')

deps += [mmap, cne, kvargs, pktdev, mempool, pktmbuf, ring, uds, xskdev, bpf_dep]

libpmd_af_xdp = library('pmd_af_xdp', sources, install: true, dependencies: deps)
pmd_af_xdp = declare_dependency(link_with: libpmd_af_xdp, include_directories: include_directories('.'))

cndp_pmds += libpmd_af_xdp
