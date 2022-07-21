# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

dirs = [
    'cnectl',
    'txgen',
    'jsonc2json',
	'xskmap_load_send',
]

foreach d:dirs
    deps = [build_cfg, include, osal, cne, log]

    sources = []
    headers = []

    subdir(d)

    install_headers(headers, subdir: meson.project_name().to_lower())
endforeach
