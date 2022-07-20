# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('csock.c')
headers = files('csock.h')

deps += []

libcsock = library(libname, sources, install: true, dependencies: deps)
csock = declare_dependency(link_with: libcsock, include_directories: include_directories('.'))

cndp_libs += csock
