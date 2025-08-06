# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2025 Intel Corporation

dirs = [
    'acl',
    'dsa',
    'thread',
    'utils',
    'timer',
    'graph',
    'hmap',
    'rib',
    'fib',
    'meter',
    'nodes',
    'cthread',
    'msgchan',
]

foreach d:dirs
    deps = [build_cfg, include, osal, log]

    libname = 'cne_' + d
    enabled_libs += libname
	subdir(d)

	install_headers(headers, subdir: meson.project_name().to_lower())
endforeach
