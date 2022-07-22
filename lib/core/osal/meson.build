# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files(
    'cne_cpuflags.c',
    'cne_stdio.c',
    'cne_system.c',
    'cne_tty.c',
    'netdev_funcs.c',
    'vt100_out.c',
    )
headers = files(
    'cne_stdio.h',
    'cne_system.h',
    'cne_tty.h',
    'netdev_funcs.h',
    'vt100_out.h',
    )

deps += []

libosal = library(libname, sources, install: true, dependencies: deps)
osal = declare_dependency(link_with: libosal, include_directories: include_directories('.'))

cndp_libs += osal
