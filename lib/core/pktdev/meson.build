# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files(
    'pktdev.c',
    'pktdev_api.c',
    )
headers = files(
    'pktdev.h',
    'pktdev_core.h',
    'pktdev_api.h',
    'pktdev_driver.h',
    )

deps += [cne, mempool, mmap, pktmbuf, uds, xskdev]

libpktdev = library(libname, sources, install: true, dependencies: deps)
pktdev = declare_dependency(link_with: libpktdev, include_directories: include_directories('.'))

cndp_libs += pktdev
