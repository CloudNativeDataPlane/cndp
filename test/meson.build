# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

dirs = ['common', 'fuzz', 'testcne']

foreach d:dirs
    sources = []
    headers = []

    subdir(d)

    install_headers(headers, subdir: meson.project_name().to_lower())
endforeach
