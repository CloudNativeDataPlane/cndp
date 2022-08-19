# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022 Red Hat, Inc.

if cne_verbose
	message('Build xskmap_load_send')
endif

deps += [bpf_dep, uds]

sources = files('xskmap_load_send.c')

xskmap_load_send = executable('xskmap_load_and_send', sources, dependencies: deps, install: true)
