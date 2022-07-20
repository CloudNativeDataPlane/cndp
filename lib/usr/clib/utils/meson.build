# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files(
    'crc32.c',
#    'crc32_sse42.c',   # later
    'hexdump.c',
	)
headers = files(
    'crc32.h',
    'hexdump.h',
    )

deps += []

libmisc = library(libname, sources, install: true, dependencies: deps)
utils = declare_dependency(link_with: libmisc, include_directories: include_directories('.'))

cndp_libs += utils
