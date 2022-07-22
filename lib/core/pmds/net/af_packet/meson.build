# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('pmd_af_packet.c')
headers = files('pmd_af_packet.h')

deps += [cne, mempool, mmap, pktdev, pktmbuf]

libpmd_af_packet = library('pmd_af_packet', sources, install: true, dependencies: deps)
pmd_af_packet = declare_dependency(link_with: libpmd_af_packet, include_directories: include_directories('.'))

cndp_pmds += libpmd_af_packet
