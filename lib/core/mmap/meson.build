# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('cne_mmap.c')
headers = files('cne_mmap.h')

deps += []

libmmap = library(libname, sources, install: true, dependencies: deps)
mmap = declare_dependency(link_with: libmmap, include_directories: include_directories('.'))

cndp_libs += mmap
