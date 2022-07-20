# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018-2022 Intel Corporation

sources = files('hmap.c')
headers = files('hmap.h')

deps += [cne]

libhmap = library(libname, sources, install: true, dependencies: deps)
hmap = declare_dependency(link_with: libhmap, include_directories: include_directories('.'))

cndp_libs += hmap

