# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
# Copyright (c) 2019-2022 Intel Corporation

sources = files('cne_rib.c', 'cne_rib6.c')
headers = files('cne_rib.h', 'cne_rib6.h')

deps += [cne, mempool, mmap]

librib = library(libname, sources, install: true, dependencies: deps)
rib = declare_dependency(link_with: librib, include_directories: include_directories('.'))

cndp_libs += rib
