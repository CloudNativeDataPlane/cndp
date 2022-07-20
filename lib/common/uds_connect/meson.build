# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018-2022 Intel Corporation


sources = files('uds_connect.c')
headers = files('uds_connect.h')

deps += [uds]

libudsc = library(libname, sources, install: true, dependencies: deps)
udsc = declare_dependency(link_with: libudsc, include_directories: include_directories('.'))

cndp_libs += udsc
