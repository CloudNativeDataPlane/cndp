# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files(
    'cne_arp.c',
    'cne_ether.c',
    'cne_net.c',
	)
headers = files(
    'cne_arp.h',
    'cne_ether.h',
    'cne_net.h',
    )

deps += [cne, mmap, pktmbuf, mempool]

libnet = both_libraries(libname, sources, install: true, dependencies: deps)
net = declare_dependency(link_with: libnet, include_directories: include_directories('.'))

cndp_libs += net
