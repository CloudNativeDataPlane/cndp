# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2023 Intel Corporation

sources = []
headers = files(
    'cne_atomic.h',
    'cne_branch_prediction.h',
    'cne_byteorder.h',
    'cne_common.h',
    'cne_cpuflags.h',
    'cne_cpuid.h',
    'cne_cycles.h',
    'cne_gettid.h',
    'cne_inet.h',
    'cne_inet4.h',
    'cne_isa.h',
    'cne_lport.h',
    'cne_mutex_helper.h',
    'cne_pause.h',
    'cne_per_thread.h',
    'cne_pktcpy.h',
    'cne_prefetch.h',
    'cne_rtm.h',
    'cne_rwlock.h',
    'cne_spinlock.h',
    'cne_strings.h',
    'cne_tailq.h',
    'cne_test.h',
    'cne_vec.h',
    'cne_vect_generic.h',
    'cne_vect.h',
    'cne_version.h',
    'cne_xmmt_ops.h',
    )
net_hdrs = files(
    'net/cne_arp.h',
    'net/cne_ether.h',
    'net/cne_gre.h',
    'net/cne_gtp.h',
    'net/cne_icmp.h',
    'net/cne_ip.h',
    'net/cne_mpls.h',
    'net/cne_sctp.h',
    'net/cne_tcp.h',
    'net/cne_udp.h',
    )

include = declare_dependency(include_directories: include_directories('.'))

install_headers(headers, subdir: meson.project_name().to_lower())
install_headers(net_hdrs, subdir: meson.project_name().to_lower() + '/net')
