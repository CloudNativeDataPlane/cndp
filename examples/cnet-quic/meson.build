# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

sources = files('cnet-quic.c', 'parse-args.c', 'stats.c', 'quic-cli.c')

deps += [pktdev, graph, mempool, pktmbuf, hmap, timer,
    mmap, uds, metrics, pmd_af_xdp, fib, stack, utils]

quicly_path = get_option('quicly_path')
picotls_path = get_option('picotls_path')

quicly_dep = cc.find_library('quicly', dirs: quicly_path, required: false)
if quicly_dep.found()
    quic_dep = [
        quicly_dep,
        cc.find_library('picotls-core', dirs: picotls_path, required: true),
        cc.find_library('picotls-openssl', dirs: picotls_path, required: true),
        cc.find_library('picotls-fusion', dirs: picotls_path, required: true),
        cc.find_library('ssl', required: true),
        cc.find_library('crypto', required: true),
    ]

    warning_flags = [
        '-Wno-cast-qual',
        '-Wno-unused-parameter',
        '-Wno-sign-compare',
        '-Wno-discarded-qualifiers',
        '-Wno-missing-prototypes',
        '-Wno-missing-declarations',
        '-Wno-ignored-qualifiers',
        '-Wno-cast-qualifiers',
        '-Wno-null-pointer-subtraction',
        '-Wno-format-nonliteral',
        '-Wno-incompatible-pointer-types-discards-qualifiers',
        ]
    quic_cflags = []
    foreach arg: warning_flags
        if cc.has_argument(arg)
            quic_cflags += arg
        endif
        if cpp.has_argument(arg)
            quic_cflags += arg
        endif
    endforeach
    quic_cflags += ['-I'+quicly_path+'/include', '-I'+picotls_path+'/include']
    quic_cflags += ['-DPICOTLS_USE_DTRACE=0', '-DQUICLY_HAVE_FUSION=1']

    executable('cnet-quic',
        sources,
        c_args: [cflags, quic_cflags],
        install: true,
        dependencies: [deps, quic_dep])
else
    message('**** Quicly not found at '+quicly_path+'\n   Update meson_options.txt file.\n   The quic-echo example cannot be built.')
endif
