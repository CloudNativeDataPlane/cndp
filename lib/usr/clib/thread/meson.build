# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('cne_thread.c')
headers = files('cne_thread.h')

deps += [cne, mmap]

libthread = library(libname, sources, install: true, dependencies: deps)
thread = declare_dependency(link_with: libthread, include_directories: include_directories('.'))

cndp_libs += thread
