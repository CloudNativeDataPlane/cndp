# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2023 Intel Corporation

# process all libraries equally, as far as possible
# "core" libs first, then others alphebetically as far as possible
# NOTE: for speed of meson runs, the dependencies in the subdirectories
# sometimes skip deps that would be implied by others, e.g. if mempool is
# given as a dep, no need to mention ring. This is especially true for the
# core libs which are widely reused, so their deps are kept to a minimum.

special_dirs = [
    'osal',
    'log',
]

dirs = [
    'events',
    'kvargs',
    'mmap',
    'cne',
    'ring',
    'hash',
    'mempool',
    'pktmbuf',
    'xskdev',
    'pktdev',
    'txbuff',
    'pmds',
    'idlemgr',
]

# handle the special case for OSAL and log directory.
foreach d:special_dirs
    deps = [build_cfg, include]

    sources = []
    headers = []

    libname = 'cne_' + d
    enabled_libs += libname

    subdir(d)

    install_headers(headers, subdir: meson.project_name().to_lower())
endforeach

foreach d:dirs
    deps = [include, osal, log, build_cfg]

    sources = []
    headers = []

    if d != 'pmds'
        libname = 'cne_' + d
        enabled_libs += libname
    endif
    subdir(d)

    install_headers(headers, subdir: meson.project_name().to_lower())
endforeach
