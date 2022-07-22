# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('pktmbuf.c', 'pktmbuf_ops.c', 'pktmbuf_ptype.c')
headers = files('pktmbuf.h', 'pktmbuf_ops.h', 'pktmbuf_ptype.h', 'pktmbuf_offload.h')

deps += [cne, mmap, mempool]

libpktmbuf = library(libname, sources, install: true, dependencies: deps)
pktmbuf = declare_dependency(link_with: libpktmbuf, include_directories: include_directories('.'))

cndp_libs += pktmbuf
