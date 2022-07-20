# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('cne_log.c')
headers = files('cne_log.h')

deps += [osal]

liblog = library(libname, sources, install: true, dependencies: deps)
log = declare_dependency(link_with: liblog, include_directories: include_directories('.'))

cndp_libs += log
