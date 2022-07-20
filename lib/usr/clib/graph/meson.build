# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 Marvell International Ltd.

sources = files('node.c', 'graph.c', 'graph_ops.c', 'graph_debug.c', 'graph_stats.c', 'graph_populate.c')
headers = files('cne_graph.h', 'cne_graph_worker.h')

deps += [cne]

libgraph = library(libname, sources, install: true, dependencies: deps)
graph = declare_dependency(link_with: libgraph, include_directories: include_directories('.'))

cndp_libs += graph
