# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2023 Intel Corporation

sources = files('tun_alloc.c')
headers = files('tun_alloc.h')

deps += [include]

libtun = library('tun', sources, install: true, dependencies: deps)
tun = declare_dependency(link_with: libtun, include_directories: include_directories('.'))

enabled_libs += 'tun'
cndp_libs += libtun
