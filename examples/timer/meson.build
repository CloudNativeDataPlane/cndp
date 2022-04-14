# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

sources = files('main.c')

deps += [timer]

executable('timer',
    sources,
    c_args: cflags,
    install: true,
    dependencies: deps)
