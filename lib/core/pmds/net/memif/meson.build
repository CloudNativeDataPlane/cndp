# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018-2019 Cisco Systems, Inc.  All rights reserved.


sources = files('pmd_memif_socket.c', 'memif_socket.c')
headers = files('pmd_memif_socket.h', 'memif_socket.h', 'memif.h')

deps += [mmap, cne, kvargs, events, pktdev, mempool, pktmbuf, ring, hash]

libpmd_memif = library('pmd_memif', sources, install:true, dependencies: deps)
pmd_memif = declare_dependency(link_with: libpmd_memif, include_directories: include_directories('.'))

cndp_pmds += libpmd_memif
