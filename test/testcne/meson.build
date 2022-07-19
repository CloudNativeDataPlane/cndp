# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation
# meson file, for building this example as part of a main CNDP build.
#
# To build this example as a standalone application with an already-installed
# CNDP instance, use 'make'

cflags = []
json_test_dir = get_option('json_test_dir')
if json_test_dir != ''
    cflags += '-DJSON_TEST_DIR="' + json_test_dir + '"'
endif

subdir('files/json') # Copy files for jcfg test

# Keep lists sorted
sources = files(
    'acl_test.c',
    'cne_register_test.c',
    'cli_cmds.c',
    'cthread_test.c',
    'dsa_test.c',
    'fib_perf_test.c',
    'fib_test.c',
    'fib6_perf_test.c',
    'fib6_test.c',
    'graph_perf_test.c',
    'graph_test.c',
    'hash_perf_test.c',
    'hash_test.c',
    'hmap_test.c',
    'jcfg_test.c',
    'kvargs_test.c',
    'log_test.c',
    'loop_test.c',
    'mbuf_test.c',
    'mempool_test.c',
    'metrics_test.c',
    'meter_test.c',
    'mmap_test.c',
    'msgchan_test.c',
    'parse_args.c',
    'pkt_test.c',
    'pktcpy_test.c',
    'pktdev_test.c',
    'rib_test.c',
    'rib6_test.c',
    'ring_api.c',
    'ring_profile.c',
    'ring_test.c',
    'tailqs_test.c',
    'test_timer_perf.c',
    'test_timer.c',
    'testcne.c',
    'thread_test.c',
    'timer_test.c',
    'uid_test.c',
    'vec_test.c',
    'xskdev_test.c',
)

if cne_conf.get('HAS_UINTR_SUPPORT')
    message('**** adding ibroker_test.c')
    sources += files('ibroker_test.c')
endif

deps = [
    acl,
    bpf_dep,
    build_cfg,
    cli,
    cne,
    cthread,
    dsa,
    fib,
    uds,
    graph,
    hash,
    hmap,
    include,
    jcfg,
    kvargs,
    log,
    mempool,
    metrics,
    mmap,
    meter,
    msgchan,
    osal,
    pktdev,
    pktmbuf,
    pmd_af_xdp,
    pmd_null,
    pmd_ring,
    rib,
    ring,
    thread,
    timer,
    tst_common,
    utils,
    xskdev,
]

if cne_conf.get('HAS_UINTR_SUPPORT')
    deps += ibroker
endif

testcne = executable('test-cne',
    sources,
    c_args: cflags,
    install: true,
    dependencies: deps
    )

test_names = [
    'acl',
    'cne',
    'dsa',
    'fib',
    'fib_perf',
    'fib6',
    'fib6_perf',
    'graph',
    'graph_perf',
    'hash',
    'hmap',
    'jcfg',
    'kvargs',
    'log',
    'mbuf',
    'mempool',
    'meter',
    'metrics',
    'mmap',
    'pkt',
    'ring',
    'sizeof',
    'tailqs',
    'thread',
    'uid',
    'vec',
]

test_names_with_iface = [
    'pktdev',
    'xskdev',
]

test_names_long_runtime = [
    'cthread',
    'hash_perf',
    'pktcpy',
    'rib',
    'rib6',
    'ring_api',
    'ring_profile',
    'timer',
]

# Run each test as a separate meson 'test' so they run in parallel and have their own timeout
# Tests in this first group are short and do not need to run as root or have a real network
foreach n:test_names
    test(n, testcne, suite: ['default', 'short'], timeout: 60, args: ['--no-color', n])
endforeach

# Require real network interface, cannot be run in parallel, and must be root.
# The interface must be passed as a "--test-args='-- -i <iface>'" parameter
foreach n:test_names_with_iface
   test(n, testcne, suite: ['root-iface-short'], is_parallel: false, timeout: 60,
        args: ['--no-color', n])
endforeach

# These tests take a long time to run, up to 30 minutes
foreach n:test_names_long_runtime
   test(n, testcne, suite: ['long'], timeout: 60*30, args: ['--no-color', n])
endforeach
