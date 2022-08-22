# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022 Intel Corporation

sources = files('msgchan.c')
headers = files('msgchan.h')

deps += [mmap, cne, ring]

libmsgchan = library(libname, sources, install: true, dependencies: deps)
msgchan = declare_dependency(link_with: libmsgchan, include_directories: include_directories('.'))

cndp_libs += msgchan
