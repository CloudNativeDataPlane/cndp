# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017-2022 Intel Corporation

sources = files('cne_timer.c')
headers = files('cne_timer.h')

deps += [cne, mmap]

libtimer = library(libname, sources, install: true, dependencies: deps)
timer = declare_dependency(link_with: libtimer, include_directories: include_directories('.'))

cndp_libs += timer
