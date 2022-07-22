# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files(
    'cne.c',
    'tailqs.c',
    'uid.c',
    )
headers = files(
    'cne.h',
    'uid.h',
    )

deps += [mmap]

libcne = library(libname, sources, install: true, dependencies: deps)
cne = declare_dependency(link_with: libcne, include_directories: include_directories('.'))

cndp_libs += cne
