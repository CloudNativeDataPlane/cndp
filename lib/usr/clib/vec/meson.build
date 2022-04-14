# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018-2022 Intel Corporation


sources = files('cne_vec.c')
headers = files('cne_vec.h')

deps += [cne, mempool, mmap, pktmbuf]

libvec = both_libraries(libname, sources, install: true, dependencies: deps)
vec = declare_dependency(link_with: libvec, include_directories: include_directories('.'))

cndp_libs += vec
