# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

if dlb_dep.found()

    sources = files('dlb_test.c', 'parse-args.c', 'stats.c')

    deps += [pktdev, pktmbuf, mempool, txbuff, ring, mmap,
        uds, metrics, pmd_af_xdp, bpf_dep, dlb_dep]


    executable('dlb_test',
        sources,
        c_args: cflags,
        install: true,
        dependencies: deps)

else
    message('DLB test build missing library')
endif

