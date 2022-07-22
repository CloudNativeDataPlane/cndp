# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files(
    'cne_ring.c'
    )
headers = files(
    'cne_ring.h',
    'cne_ring_api.h',
    )

deps += [mmap, cne]

libring = library(libname, sources, install: true, dependencies: deps)
ring = declare_dependency(link_with: libring, include_directories: include_directories('.'))

cndp_libs += ring
