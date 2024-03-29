# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2023 Intel Corporation

if meson.get_compiler('cpp').get_id() != 'clang'
    message('Fuzz tests require clang. Fuzz tests will not be built.')
    subdir_done()
endif

cppflags = ['-gline-tables-only', '-fsanitize=address,fuzzer', '-fsanitize-address-use-after-scope']

fuzzerz = [
    'cli_input',
    'uds_create',
    'cne_log',
    'mempool_create',
    'mmap_alloc',
]

deps = [
    bpf_dep,
    build_cfg,
    cli,
    cne,
    include,
    log,
    mempool,
    mmap,
    osal,
    uds,
]

foreach f : fuzzerz
    # e.g. fuzz_cli_input built from cli_input.cc
    executable('fuzz_' + f,
        files(f + '.cc'),
        cpp_args: cppflags,
        install: false,
        dependencies: deps,
        link_args: ['-fsanitize=address,fuzzer'],
    )
endforeach
