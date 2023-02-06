# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2023 Intel Corporation

dirs = [
    'afxdp',
    'cli',
    'cndpfwd',
    'cnet-graph',
    'cnet-quic',
    'dlb_test',
    'helloworld',
    'l3fwd-graph',
    'timer',
    'phil',
]

if cne_conf.get('HAS_UINTR_SUPPORT')
    dirs += ['ibroker']
endif

def_deps = [build_cfg, osal, include, log, cne, cli, thread, jcfg, kvargs, hash]

foreach d:dirs
    cflags = []
    deps =  def_deps  # reset the deps to the original values

    sources = []
    headers = []

    subdir(d)

    install_headers(headers, subdir: meson.project_name().to_lower())
endforeach
