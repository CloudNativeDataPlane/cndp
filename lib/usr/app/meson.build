# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2025 Intel Corporation

dirs = [
    'cli',
    'jcfg',
    'metrics'
]

foreach d:dirs
    deps = [build_cfg, osal, include, log]

    libname = 'cne_' + d
    enabled_libs += libname
	subdir(d)

	install_headers(headers, subdir: meson.project_name().to_lower())
endforeach
