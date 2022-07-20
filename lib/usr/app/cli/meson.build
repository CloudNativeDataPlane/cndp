# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files(
	'cli_auto_complete.c',
	'cli.c',
	'cli_cmap.c',
	'cli_cmds.c',
	'cli_env.c',
	'cli_file.c',
	'cli_gapbuf.c',
	'cli_help.c',
	'cli_history.c',
	'cli_input.c',
	'cli_map.c',
	'cli_search.c',
	'cli_vt100.c')
headers = files(
	'cli_auto_complete.h',
	'cli_cmap.h',
	'cli_cmds.h',
	'cli_common.h',
	'cli_env.h',
	'cli_file.h',
	'cli_gapbuf.h',
	'cli.h',
	'cli_help.h',
	'cli_history.h',
	'cli_input.h',
	'cli_map.h',
	'cli_search.h')

deps += [cne, uds, xskdev, pktmbuf, mempool, mmap]

libcli = library(libname, sources, install: true, dependencies: deps)
cli = declare_dependency(link_with: libcli, include_directories: include_directories('.'))

cndp_libs += cli
