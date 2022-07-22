# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

sources = files(
    'jcfg_application.c',
    'jcfg_decode.c',
    'jcfg_default.c',
    'jcfg_dump.c',
    'jcfg_thread.c',
    'jcfg_lgroup.c',
    'jcfg_lport.c',
    'jcfg_lport_group.c',
    'jcfg_option.c',
    'jcfg_print.c',
    'jcfg_umem.c',
    'jcfg_process.c',
    'jcfg.c',
    )
headers = files('jcfg.h', 'jcfg_process.h')

deps += [cne, mmap, thread, pktdev, mempool, pktmbuf, uds]

libjcfg = library(libname, sources, install: true, dependencies: deps)
jcfg = declare_dependency(link_with: libjcfg, include_directories: include_directories('.'))

cndp_libs += jcfg
