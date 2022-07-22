# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('cne_event.c')
headers = files('cne_event.h')

deps += []

libevents = library(libname, sources, install: true, dependencies: deps)
events = declare_dependency(link_with: libevents, include_directories: include_directories('.'))

cndp_libs += events
