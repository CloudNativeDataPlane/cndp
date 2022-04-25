# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

dirs = [
    'af_packet',
    'af_xdp',
    'memif',
    'null',
    'ring',
    'tap',
    ]

foreach d:dirs
    deps = [build_cfg, include, osal, log]

    enabled_libs += 'pmd_' + d
	subdir(d)

	install_headers(headers, subdir: meson.project_name().to_lower())
endforeach
