# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017-2025 Intel Corporation

sources = files('ibroker.c')
uintr_sources = files('uintr_handler.c')
headers = files('ibroker.h')

uintr_c_args = []
if cc.has_argument('-mtls-dialect=gnu2')
	uintr_c_args += ['-mtls-dialect=gnu2']
endif

ibroker_uintr_obj = static_library('ibroker_uintr_obj', uintr_sources,
	c_args: uintr_c_args,
	install: false,
	dependencies: deps)

libibroker = library(libname, sources,
	install: true,
	dependencies: deps,
	link_whole: ibroker_uintr_obj)
ibroker = declare_dependency(link_with: libibroker, include_directories: include_directories('.'))

cndp_libs += ibroker
