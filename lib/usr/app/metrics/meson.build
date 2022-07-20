# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('metrics.c')
headers = files('metrics.h')

deps += [include, cne, mmap, uds, pktmbuf, mempool]

libmetrics = library(libname, sources, install: true, dependencies: deps)
metrics = declare_dependency(link_with: libmetrics, include_directories: include_directories('.'))

cndp_libs += metrics
