# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2025 Intel Corporation

sources = files('idlemgr.c')
headers = files('idlemgr.h')

deps += []

libidlemgr = library(libname, sources, install: true, dependencies: deps)
idlemgr = declare_dependency(link_with: libidlemgr, include_directories: include_directories('.'))

cndp_libs += idlemgr
