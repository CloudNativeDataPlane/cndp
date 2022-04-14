# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

if cne_verbose
	message('Build jsonc2json')
endif

sources = files('jsonc2json.c')

jsonc2json = executable('jsonc2json', sources, dependencies: json_c, install: true)
