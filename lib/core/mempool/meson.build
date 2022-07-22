# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('mempool.c', 'mempool_ring.c')
headers = files('mempool.h')

deps += [cne, osal, ring, mmap]

libmempool = library(libname, sources, install: true, dependencies: deps)
mempool = declare_dependency(link_with: libmempool, include_directories: include_directories('.'))

cndp_libs += mempool
