# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2025 Intel Corporation

dirs = [
    'uds',
    'uds_connect'
]

foreach d:dirs

    deps = [build_cfg, include]

    sources = []
    headers = []

    libname = 'cne_' + d
    enabled_libs += libname
    subdir(d)

    install_headers(headers, subdir: meson.project_name().to_lower())
endforeach
