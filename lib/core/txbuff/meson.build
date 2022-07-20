# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('txbuff.c')
headers = files('txbuff.h')

deps += [cne, mmap, mempool, pktmbuf, pktdev, uds, xskdev]

libtxbuff = library(libname, sources, install: true, dependencies: deps)
txbuff = declare_dependency(link_with: libtxbuff, include_directories: include_directories('.'))

cndp_libs += txbuff
