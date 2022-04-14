# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

sources = files('main.c', 'parse-args.c', 'handler.c')

deps += [cne, log, ibroker]

broker = executable('ibroker',
    sources,
    c_args: cflags,
    install: true,
    dependencies: deps)

