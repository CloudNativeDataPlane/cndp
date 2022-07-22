# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017-2022 Intel Corporation

sources = files('ibroker.c', 'uintr_handler.c')
headers = files('ibroker.h')

libibroker = library(libname, sources, install: true, dependencies: deps)
ibroker = declare_dependency(link_with: libibroker, include_directories: include_directories('.'))

cndp_libs += ibroker

