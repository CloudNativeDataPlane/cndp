# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
# Copyright (c) 2019-2022 Intel Corporation

sources = files('cne_fib.c', 'cne_fib6.c', 'dir24_8.c', 'trie.c')
headers = files('cne_fib.h', 'cne_fib6.h')

deps += [cne, mempool, mmap, rib]

static_cne = []
objs = []
avx512_cflags = []

if avx512_on == true
    avx512_cflags += ['-DCC_DIR24_8_AVX512_SUPPORT']
    # TRIE AVX512 implementation uses avx512bw intrinsics along with
    # avx512f and avx512dq
    if cc.get_define('__AVX512BW__', args: machine_args) != ''
        avx512_cflags += ['-DCC_TRIE_AVX512_SUPPORT']
    endif

    message('**** Add dir24_8_avx512.c')
    sources += files('dir24_8_avx512.c')

    # TRIE AVX512 implementation uses avx512bw intrinsics along with
    # avx512f and avx512dq
    if cc.get_define('__AVX512BW__', args: machine_args) != ''
        sources += files('trie_avx512.c')
        message('**** Add trie_avx512.c')
    endif
elif cc.has_multi_arguments('-mavx512f', '-mavx512dq')
    message('*** have multiple avx512f and avx512dq')

    avx512_cflags += ['-DCC_DIR24_8_AVX512_SUPPORT']
    # TRIE AVX512 implementation uses avx512bw intrinsics along with
    # avx512f and avx512dq
    if cc.has_argument('-mavx512bw')
        avx512_cflags += ['-DCC_TRIE_AVX512_SUPPORT']
    endif

    dir24_8_avx512_tmp = static_library('dir24_8_avx512_tmp',
            'dir24_8_avx512.c',
            dependencies: deps,
            c_args: avx512_cflags + ['-mavx512f', '-mavx512dq'])
    objs += dir24_8_avx512_tmp.extract_objects('dir24_8_avx512.c')
    # TRIE AVX512 implementation uses avx512bw intrinsics along with
    # avx512f and avx512dq
    if cc.has_argument('-mavx512bw')
        trie_avx512_tmp = static_library('trie_avx512_tmp',
                'trie_avx512.c',
                dependencies: deps,
                c_args: avx512_cflags + ['-mavx512f', \
                        '-mavx512dq', '-mavx512bw'])
        objs += trie_avx512_tmp.extract_objects('trie_avx512.c')
    endif
endif

libfib = library(libname, sources, objects: objs, install: true, dependencies: deps)
fib = declare_dependency(link_with: libfib, include_directories: include_directories('.'))

cndp_libs += fib
