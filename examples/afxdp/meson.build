# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

linux_source_dir = get_option('linux_source_dir')

fs = import('fs') # Meson 0.53.0 required for this package
if fs.is_dir(linux_source_dir)
    build_afxdp_user = true
else
    build_afxdp_user = false
endif

if build_afxdp_user
    message('**** Building xdpsock_user.c from the linux source as afxdp_user')
    message('**** Building xsk_fwd.c from the linux source as afxdp_fwd')
    message('**** Found Linux source @ ' + linux_source_dir)

    sources = files('afxdp_user.c')

    deps += [bpf_dep]

    executable('afxdp_user',
        sources,
        c_args: [
            '-I'+linux_source_dir+'/usr/include',
            '-I'+linux_source_dir+'/arch/x86/include',
            '-I'+linux_source_dir+'/tools/include',
            '-I'+linux_source_dir+'/samples/bpf',
            cflags
        ],
        install: true,
        dependencies: deps)

    sources = files('afxdp_fwd.c')

    executable('afxdp_fwd',
        sources,
        c_args: [
            '-I'+linux_source_dir+'/usr/include',
            '-I'+linux_source_dir+'/arch/x86/include',
            '-I'+linux_source_dir+'/tools/include',
            '-I'+linux_source_dir+'/samples/bpf',
            cflags
        ],
        install: true,
        dependencies: deps)
else
    message('**** Missing Linux source code, not building afxdp_user or afxdp_fwd example:'+linux_source_dir)
endif
