# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2023 Intel Corporation

if dlb_dep.found()

    sources = files('dlb_test.c', 'parse-args.c', 'stats.c')

    deps += [pktdev, pktmbuf, mempool, txbuff, ring, mmap,
        uds, metrics, bpf_dep, dlb_dep]


    executable('dlb_test',
        sources,
        c_args: cflags,
        install: true,
        link_whole: cndp_pmds,
        dependencies: deps)

else
    message('DLB test build missing library')
endif

