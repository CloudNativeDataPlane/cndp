# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018-2023 Intel Corporation
# Copyright (c) Red Hat Inc.

def_deps = [
    build_cfg,
    osal,
    cne,
    include,
    log,

    hmap,
    mempool,
    mmap,
    pktdev,
    pktmbuf,
    fib,
    ring,
    cli,
    hash,
    pmd_ring,
    timer,
    thread,
    utils,
    graph,
    jcfg,
    tun,
    uds,
    pmd_tap,
    xskdev,
    ]

dirs = [ # list is not sorted and must be in this order.
    'incs',			# common libraries needing to be built first.
    'reg',
    'cnet',
    'stk',
    'pcb',
    'protosw',
    'drv',
    'netif',

    'route',        # Independent libs
    'netlink',
    'chnl',
    'arp',
    'nd6',

    'eth',          # CNET graph node and libs
    'ptype',
    'ipv4',
    'ipv6',
    'punt',
    'gtpu',
    'tcp',
    'udp',
    'icmp6',
    'nodes',

    'sbin',         # Misc tools and command libs
    'cmds',
]

sources = []
headers = []
includes = []

foreach d:dirs
    subdir(d)

    includes += include_directories(d)
endforeach

install_headers(headers, subdir: meson.project_name().to_lower() + '/cnet')

libname = 'cne_stack'
enabled_libs += libname

libcne_stack = library(libname, sources, install: true, dependencies: def_deps,
    include_directories: includes)
stack = declare_dependency(link_with: libcne_stack, include_directories: includes)

cndp_libs += stack
