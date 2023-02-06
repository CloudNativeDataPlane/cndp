# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2023 Intel Corporation

sources = files(
	'cksum.c',
	'cli-functions.c',
	'cmds.c',
	'capture.c',
	'display.c',
	'ether.c',
	'ipv4.c',
	'latency.c',
	'main.c',
	'parse-args.c',
	'_pcap.c',
	'pcap.c',
	'portlist.c',
	'stats.c',
	'tcp.c',
	'txgen.c',
	'udp.c',
	'cne_net_crc.c',
)

deps += [
    cli,
    events,
    hash,
    jcfg,
    kvargs,
    mempool,
    metrics,
    mmap,
    pktdev,
    pktmbuf,
    ring,
    thread,
    timer,
    tun,
    uds,
    utils,
    ]

executable('txgen',
    sources,
    c_args: cflags,
    install: true,
    link_whole: cndp_pmds,
    dependencies: deps)
