# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation
# meson file, for building this example as part of a main CNDP build.
#
# To build this example as a standalone application with an already-installed
# CNDP instance, use 'make'

# SPDX-License-Identifier: BSD-3-Clause


sources = files('cne_meter.c')
headers = files('cne_meter.h')

deps += [cne, timer]

libmeter = library(libname, sources, install: true, dependencies: deps)
meter = declare_dependency(link_with: libmeter, include_directories: include_directories('.'))

cndp_libs += meter
