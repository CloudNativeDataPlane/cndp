# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files('tst_info.c', 'test.c')

deps += [include, osal, utils, log, cne, cli, build_cfg]

libtst_common = library('tst_common', sources, install: true, dependencies: deps)
tst_common = declare_dependency(link_with: libtst_common, include_directories: include_directories('.'))
