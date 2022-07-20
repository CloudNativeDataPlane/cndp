# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 Marvell International Ltd.

name = 'nodes'

sources = files('null.c', 'pktdev_rx.c', 'pktdev_tx.c', 'ip4_lookup.c',
		'ip4_rewrite.c', 'pkt_drop.c', 'pktdev_ctrl.c', 'pkt_cls.c')
headers = files('node_ip4_api.h', 'node_eth_api.h')

deps += [cne, fib, graph, pktdev, mempool, pktmbuf, mmap]

libnodes = library(libname, sources, install: true, dependencies: deps)
nodes = declare_dependency(link_with: libnodes, include_directories: include_directories('.'))

cndp_libs += libnodes
