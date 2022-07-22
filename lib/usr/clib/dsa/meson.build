# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2022 Intel Corporation

sources = files('cne_dsa.c', 'sw_dsa.c')
headers = files('cne_dsa.h')

deps += []

libdsa = library(libname, sources, install: true, dependencies: deps)
dsa = declare_dependency(link_with: libdsa, include_directories: include_directories('.'))

cndp_libs += dsa
