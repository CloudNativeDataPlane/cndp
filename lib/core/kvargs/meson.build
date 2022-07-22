# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('kvargs.c')
headers = files('kvargs.h')

deps += []

libkvargs = library(libname, sources, install: true, dependencies: deps)
kvargs = declare_dependency(link_with: libkvargs, include_directories: include_directories('.'))

cndp_libs += kvargs
