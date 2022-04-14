# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('uds.c')
headers = files('uds.h')

libuds = both_libraries(libname, sources, install: true, dependencies: deps)
uds = declare_dependency(link_with: libuds, include_directories: include_directories('.'))

cndp_libs += uds

